// Package config loads ~/.config/reclaim/config.toml.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Config is reclaim's configuration. Zero values are replaced by defaults.
type Config struct {
	Interval time.Duration // refresh interval, default 2s
	Grace    time.Duration // SIGTERM → SIGKILL grace period, default 5s

	Protect Protect

	// Culprit detection (see package pressure).
	CulpritWindow    time.Duration
	CulpritThreshold float64
	PSIWeight        float64
	GrowthWeight     float64

	// Growth annotation.
	GrowthWindow   time.Duration // Δ column window, default 10m
	GrowthMinSpan  time.Duration // default 10m
	GrowthMinDelta uint64        // default 256 MiB

	Path string // where the config was loaded from, if anywhere
}

// Protect lists user-configured protected groups.
type Protect struct {
	Names   []string // comm, or unit-derived group name
	Exes    []string // resolved executable path
	Cgroups []string // glob on cgroup path
	// DisableDefaults lists default protections to turn off, by the name
	// shown in the UI (e.g. "sshd"). PID 1, kernel threads and reclaim
	// itself cannot be disabled.
	DisableDefaults []string
}

// Default returns the built-in configuration.
func Default() Config {
	return Config{
		Interval:         2 * time.Second,
		Grace:            5 * time.Second,
		CulpritWindow:    60 * time.Second,
		CulpritThreshold: 10,
		PSIWeight:        0.4,
		GrowthWeight:     0.6,
		GrowthWindow:     10 * time.Minute,
		GrowthMinSpan:    10 * time.Minute,
		GrowthMinDelta:   256 << 20,
	}
}

// DefaultPath returns $XDG_CONFIG_HOME/reclaim/config.toml.
func DefaultPath() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "reclaim", "config.toml")
}

// StateDir returns $XDG_STATE_HOME/reclaim.
func StateDir() string {
	dir := os.Getenv("XDG_STATE_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(dir, "reclaim")
}

// Load reads the config at path. A missing file yields the defaults.
func Load(path string) (Config, error) {
	c := Default()
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := c.parse(string(data)); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	c.Path = path
	return c, nil
}

func (c *Config) parse(src string) error {
	kv, err := parseTOML(src)
	if err != nil {
		return err
	}
	for k, v := range kv {
		var err error
		switch k {
		case "interval":
			err = setDuration(&c.Interval, v)
		case "grace":
			err = setDuration(&c.Grace, v)
		case "protect.names":
			err = setStrings(&c.Protect.Names, v)
		case "protect.exes":
			err = setStrings(&c.Protect.Exes, v)
		case "protect.cgroups":
			err = setStrings(&c.Protect.Cgroups, v)
		case "protect.disable_defaults":
			err = setStrings(&c.Protect.DisableDefaults, v)
		case "culprit.window":
			err = setDuration(&c.CulpritWindow, v)
		case "culprit.threshold":
			err = setFloat(&c.CulpritThreshold, v)
		case "culprit.psi_weight":
			err = setFloat(&c.PSIWeight, v)
		case "culprit.growth_weight":
			err = setFloat(&c.GrowthWeight, v)
		case "growth.window":
			err = setDuration(&c.GrowthWindow, v)
		case "growth.min_span":
			err = setDuration(&c.GrowthMinSpan, v)
		case "growth.min_delta_mb":
			var f float64
			if err = setFloat(&f, v); err == nil {
				c.GrowthMinDelta = uint64(f) << 20
			}
		default:
			err = errors.New("unknown key")
		}
		if err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
	}
	if c.Interval < 500*time.Millisecond {
		return errors.New("interval: must be at least 500ms")
	}
	return nil
}

func setDuration(dst *time.Duration, v any) error {
	s, ok := v.(string)
	if !ok {
		return errors.New(`want a duration string such as "5s"`)
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	if d < 0 {
		return errors.New("must not be negative")
	}
	*dst = d
	return nil
}

func setStrings(dst *[]string, v any) error {
	s, ok := v.([]string)
	if !ok {
		return errors.New("want an array of strings")
	}
	*dst = s
	return nil
}

func setFloat(dst *float64, v any) error {
	f, ok := v.(float64)
	if !ok {
		return errors.New("want a number")
	}
	*dst = f
	return nil
}
