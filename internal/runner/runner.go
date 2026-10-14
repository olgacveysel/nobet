// Package runner defines how collectors run shell commands on a host. The
// implementations, local and over SSH, live in package transport, so code
// that only needs the interface never links the SSH client.
package runner

// Runner executes a shell command and returns its output.
type Runner interface {
	Run(cmd string) (Result, error)
}

// Result is the outcome of one command. A non-zero exit code is not an
// error; errors are reserved for transport problems and timeouts.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}
