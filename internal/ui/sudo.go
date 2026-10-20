package ui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/clobrano/reclaim/internal/action"
)

// runSudo runs the helper through sudo with the terminal attached, so sudo
// can prompt for a password, and decodes the helper's JSON result.
func runSudo(args []string) action.Result {
	cmd := exec.Command(args[0], args[1:]...)
	var out bytes.Buffer
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, &out, os.Stderr
	err := cmd.Run()
	var res action.Result
	if jerr := json.Unmarshal(out.Bytes(), &res); jerr != nil {
		if err == nil {
			err = jerr
		}
		res.Error = fmt.Sprintf("sudo helper: %v", err)
	}
	return res
}
