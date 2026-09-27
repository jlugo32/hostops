// Command hostops is an allowlisted, audited executor for self-managed Linux
// web hosts. See README.md and CLAUDE.md.
package main

import (
	"os"

	"github.com/jlugo32/hostops/internal/cli"
	"github.com/jlugo32/hostops/internal/output"
)

var version = "dev"

func main() {
	cli.Version = version
	app := &cli.App{Stdout: os.Stdout, Stderr: os.Stderr, StdoutTTY: output.IsTTY(os.Stdout), StderrTTY: output.IsTTY(os.Stderr)}
	os.Exit(app.Run(os.Args[1:]))
}
