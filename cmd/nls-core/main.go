package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/TamilSelvam22112003/Nls-NexOS-Core-v0.1.1/internal/ca"
	"github.com/TamilSelvam22112003/Nls-NexOS-Core-v0.1.1/internal/enrollment"
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
	case "serve-enrollment":
		return serve(args[1:], true)
	case "serve-control":
		return serve(args[1:], false)
	case "revoke-router":
		return commandRevoke(args[1:])
	case "export-ca-cert":
		return commandExportCACert(args[1:])
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
	publicKeySHA256 := fs.String("public-key-sha256", "", "SHA-256 of the intended router Ed25519 public key")
	endpointIPv6 := fs.String("endpoint-ipv6", "", "router advertised IPv6 endpoint")
	endpointPort := fs.Uint("endpoint-udp-port", 0, "router advertised UDP port")
	ttlText := fs.String("ttl", "10m", "credential lifetime (maximum 10m)")
	if err := fs.Parse(args); err != nil { return err }
	if fs.NArg() != 0 { return fmt.Errorf("unexpected positional arguments") }
	pass, err := passphrase()
	if err != nil { return err }
	ttl, err := time.ParseDuration(*ttlText)
	if err != nil { return fmt.Errorf("invalid TTL: %w", err) }
	if *publicKeySHA256 == "" || *endpointIPv6 == "" || *endpointPort < 1 || *endpointPort > 65535 { return fmt.Errorf("--public-key-sha256, --endpoint-ipv6, and --endpoint-udp-port are required") }
	token, err := (ca.Store{Dir:*dir}).SetScopedEnrollmentCredential(pass, *name, *publicKeySHA256, *endpointIPv6, uint16(*endpointPort), ttl)
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


func serve(args []string, isEnrollment bool) error {
	name := "serve-control"
	defaultListen := ":8444"
	if isEnrollment { name="serve-enrollment"; defaultListen=":8443" }
	fs:=flag.NewFlagSet(name,flag.ContinueOnError);fs.SetOutput(os.Stderr)
	dir:=fs.String("dir","/var/lib/nls-ca","CA state directory")
	listen:=fs.String("listen",defaultListen,"TLS listen address")
	tlsName:=fs.String("tls-name","localhost","TLS certificate DNS name")
	if err:=fs.Parse(args);err!=nil{return err}
	if fs.NArg()!=0{return fmt.Errorf("unexpected positional arguments")}
	pass,err:=passphrase();if err!=nil{return err}
	ctx,stop:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM);defer stop()
	svc:=enrollment.Service{Store:ca.Store{Dir:*dir},Passphrase:pass,TLSName:*tlsName}
	fmt.Fprintf(os.Stderr,"%s listening on %s (TLS 1.3)\n",name,*listen)
	if isEnrollment{return svc.ServeEnrollment(ctx,*listen)}
	return svc.ServeControl(ctx,*listen)
}

func commandRevoke(args []string) error {
	fs:=flag.NewFlagSet("revoke-router",flag.ContinueOnError);fs.SetOutput(os.Stderr)
	dir:=fs.String("dir","/var/lib/nls-ca","CA state directory")
	routerID:=fs.String("router-id","","32 hexadecimal characters")
	reason:=fs.String("reason","","revocation reason")
	if err:=fs.Parse(args);err!=nil{return err}
	if fs.NArg()!=0{return fmt.Errorf("unexpected positional arguments")}
	pass,err:=passphrase();if err!=nil{return err}
	if len(*routerID)!=32{return fmt.Errorf("--router-id must be 32 hexadecimal characters")}
	if _,err=hex.DecodeString(*routerID);err!=nil{return fmt.Errorf("--router-id must be hexadecimal")}
	if err=(ca.Store{Dir:*dir}).RevokeRouter(pass,*routerID,*reason);err!=nil{return err}
	fmt.Println("router revoked; control sessions will be rejected on their next authorization check")
	return nil
}

func commandExportCACert(args []string) error {
	fs:=flag.NewFlagSet("export-ca-cert",flag.ContinueOnError);fs.SetOutput(os.Stderr)
	dir:=fs.String("dir","/var/lib/nls-ca","CA state directory")
	tlsName:=fs.String("tls-name","localhost","TLS certificate DNS name")
	out:=fs.String("out","ca-cert.pem","output CA certificate PEM")
	if err:=fs.Parse(args);err!=nil{return err}
	if fs.NArg()!=0{return fmt.Errorf("unexpected positional arguments")}
	pass,err:=passphrase();if err!=nil{return err}
	_,_,err=(ca.Store{Dir:*dir}).TLSCertificate(pass,*tlsName);if err!=nil{return err}
	pemBytes,err:=(ca.Store{Dir:*dir}).RootCertificatePEM(pass,*tlsName);if err!=nil{return err}
	if err=os.WriteFile(*out,pemBytes,0644);err!=nil{return err}
	fmt.Println("CA certificate exported:",*out)
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
  nls-core set-enrollment-credentials --name NAME --public-key-sha256 HEX --endpoint-ipv6 IPV6 --endpoint-udp-port PORT [--ttl 10m] [--dir DIR]
  nls-core set-policy --protect-prefix CIDR[,CIDR...] [--bypass-prefix CIDR[,CIDR...]] [--dir DIR]
  nls-core set-access-controls [--allow-enrollment=true|false] [--max-active-routers N] [--dir DIR]
  nls-core status [--dir DIR]
  nls-core serve-enrollment [--listen :8443] [--tls-name ca.example] [--dir DIR]
  nls-core serve-control [--listen :8444] [--tls-name ca.example] [--dir DIR]
  nls-core revoke-router --router-id HEX32 --reason TEXT [--dir DIR]
  nls-core export-ca-cert --tls-name ca.example --out ca-cert.pem [--dir DIR]

All commands except help require NLS_CA_PASSPHRASE in the environment.
`)
}
