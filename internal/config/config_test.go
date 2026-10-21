package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	src := `# reclaim
grace = "10s"   # longer for editors

[protect]
names   = ["firefox", 'keepassxc']
exes    = [
  "/usr/bin/keepassxc",  # password manager
  "/opt/a#b",
]
cgroups = ["*/app-*-keepassxc-*.scope"]
disable_defaults = ["sshd"]

[culprit]
threshold = 20
psi_weight = 0.5

[growth]
min_delta_mb = 512
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Grace != 10*time.Second || c.Interval != 2*time.Second {
		t.Fatalf("durations %v %v", c.Grace, c.Interval)
	}
	want := Protect{
		Names:           []string{"firefox", "keepassxc"},
		Exes:            []string{"/usr/bin/keepassxc", "/opt/a#b"},
		Cgroups:         []string{"*/app-*-keepassxc-*.scope"},
		DisableDefaults: []string{"sshd"},
	}
	if !reflect.DeepEqual(c.Protect, want) {
		t.Fatalf("protect %+v", c.Protect)
	}
	if c.CulpritThreshold != 20 || c.PSIWeight != 0.5 || c.GrowthWeight != 0.6 || c.GrowthMinDelta != 512<<20 {
		t.Fatalf("%+v", c)
	}
	if c.Path != path {
		t.Fatal(c.Path)
	}
}

func TestLoadMissing(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "nope.toml"))
	if err != nil || c.Grace != 5*time.Second {
		t.Fatal(c, err)
	}
}

func TestErrors(t *testing.T) {
	cases := map[string]string{
		`bogus = 1`:                 "unknown key",
		`grace = 5`:                 "duration",
		`grace = "-1s"`:             "negative",
		`interval = "10ms"`:         "at least",
		"[protect]\nnames = [1, 2]": "strings",
		"[protect]\nnames = \"x\"":  "array",
		`grace "5s"`:                "key = value",
		"[[tables]]":                "unsupported",
	}
	for src, want := range cases {
		var c Config
		err := c.parse(src)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want error containing %q", src, err, want)
		}
	}
}
