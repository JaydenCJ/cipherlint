// Command cipherlint lints nginx, Caddy, Apache and HAProxy TLS
// configurations against dated best-practice profiles — offline, with a
// citation for every finding.
package main

import (
	"os"

	"github.com/JaydenCJ/cipherlint/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
