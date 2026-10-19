package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/TamilSelvam22112003/Nls-NexOS-Core-v0.1.1/internal/ca"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return fmt.Errorf("command required")
	}
	command := args[0]
	switch command {
	case "help", "-h", "--help":
		printUsage()
		return nil
	case "init":
		fs := flag.NewFlagSet(command, flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		dir := fs.String("dir", "/var/lib/nls-ca", "CA state directory")
		if err := fs.Parse(args[1:]); err != nil { return err }
		if fs.NArg() != 0 { return fmt.Errorf("unexpected positional arguments") }
		pass, err := passphrase()
		if err != nil { return err }
		if err = (ca.Store{Dir:*dir}).Init(pass); err != nil { return err }
		fmt.Println("initialized; enrollment is not ready")
		fmt.Println("Next: set-enrollment-credentials, set-policy, set-access-controls, then status")
		return nil
	case "set-enrollment-credentials":
		return commandEnrollment(args[1:])
	case "set-policy":
		return commandPolicy(args[1:])
	case "set-access-controls":
		return commandAccess(args[1:])
	case "status":
		fs := flag.NewFlagSet(command, flag.ContinueOnError)
		fs.SetOutput(os.Stderr)
		dir := fs.String("dir", "/var/lib/nls-ca", "CA state directory")
		if err := fs.Parse(args[1:]); err != nil { return err }
		if fs.NArg() != 0 { return fmt.Errorf("unexpected positional arguments") }
		pass, err := passphrase()
		if err != nil { return err }
		status, statusErr := (ca.Store{Dir:*dir}).Status(pass)
		fmt.Println(status)
		return statusErr
	default:
		printUsage()
		return fmt.Errorf("unknown command %q", command)
	}
}

func commandEnrollment(args []string) error {
	fs := flag.NewFlagSet("set-enrollment-credentials", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dir := fs.String("dir", "/var/lib/nls-ca", "CA state directory")
	name := fs.String("name", "", "router name scoped to the enrollment credential")
	ttlText := fs.String("ttl", "10m", "credential lifetime (maximum 10m)")
	if err := fs.Parse(args); err != nil { return err }
	if fs.NArg() != 0 { return fmt.Errorf("unexpected positional arguments") }
	pass, err := passphrase()
	if err != nil { return err }
	ttl, err := time.ParseDuration(*ttlText)
	if err != nil { return fmt.Errorf("invalid TTL: %w", err) }
	token, err := (ca.Store{Dir:*dir}).SetEnrollmentCredential(pass, *name, ttl)
	if err != nil { return err }
	fmt.Println("Enrollment token (shown once; store securely):")
	fmt.Println(token)
	fmt.Println("Credential saved as a SHA-256 hash; expires at", time.Now().UTC().Add(ttl).Format(time.RFC3339))
	return nil
}

func commandPolicy(args []string) error {
	fs := flag.NewFlagSet("set-policy", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dir := fs.String("dir", "/var/lib/nls-ca", "CA state directory")
	protect := fs.String("protect-prefix", "", "comma-separated PROTECT CIDR prefixes")
	bypass := fs.String("bypass-prefix", "", "comma-separated BYPASS CIDR prefixes")
	if err := fs.Parse(args); err != nil { return err }
	if fs.NArg() != 0 { return fmt.Errorf("unexpected positional arguments") }
	pass, err := passphrase()
	if err != nil { return err }
	if err = (ca.Store{Dir:*dir}).SetPolicy(pass, splitList(*protect), splitList(*bypass)); err != nil { return err }
	fmt.Println("policy saved; run status to verify readiness")
	return nil
}

func commandAccess(args []string) error {
	fs := flag.NewFlagSet("set-access-controls", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dir := fs.String("dir", "/var/lib/nls-ca", "CA state directory")
	allow := fs.Bool("allow-enrollment", true, "allow enrollment after all state checks pass")
	maxRouters := fs.Int("max-active-routers", 1000, "maximum active router registry entries")
	if err := fs.Parse(args); err != nil { return err }
	if fs.NArg() != 0 { return fmt.Errorf("unexpected positional arguments") }
	pass, err := passphrase()
	if err != nil { return err }
	if err = (ca.Store{Dir:*dir}).SetAccessControls(pass, *allow, *maxRouters); err != nil { return err }
	fmt.Println("access controls saved; run status to verify readiness")
	return nil
}

func passphrase() (string, error) {
	p := os.Getenv("NLS_CA_PASSPHRASE")
	if strings.TrimSpace(p) == "" {
		return "", fmt.Errorf("set NLS_CA_PASSPHRASE in the environment; passphrases are never accepted as command-line arguments")
	}
	return p, nil
}

func splitList(value string) []string {
	if strings.TrimSpace(value) == "" { return nil }
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) != "" { out = append(out, strings.TrimSpace(p)) }
	}
	return out
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `NLS Router-CA admin CLI
Usage:
  nls-core init [--dir DIR]
  nls-core set-enrollment-credentials --name NAME [--ttl 10m] [--dir DIR]
  nls-core set-policy --protect-prefix CIDR[,CIDR...] [--bypass-prefix CIDR[,CIDR...]] [--dir DIR]
  nls-core set-access-controls [--allow-enrollment=true|false] [--max-active-routers N] [--dir DIR]
  nls-core status [--dir DIR]

All commands except help require NLS_CA_PASSPHRASE in the environment.
`)
}
