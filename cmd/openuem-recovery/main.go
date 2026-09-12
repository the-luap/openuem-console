package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/open-uem/openuem-console/internal/recovery"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out, diagnostics io.Writer) error {
	f := flag.NewFlagSet("openuem-recovery", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.Usage = func() {}
	action := f.String("action", "verify", "Action: keygen, create, verify or restore")
	output := f.String("output", "", "New database backup or private identity file (absolute path)")
	keysOutput := f.String("recovery-output", "", "New separately encrypted recovery bundle (absolute path)")
	spec := f.String("specification", "", "Protected JSON file naming environment variables and recovery files")
	dataRecipient := f.String("recipient", "", "Public age recipient for database backups")
	keysRecipient := f.String("recovery-recipient", "", "Different public age recipient for the recovery bundle")
	dataInput := f.String("input", "", "Encrypted database backup to verify or restore")
	keysInput := f.String("recovery-input", "", "Matching encrypted recovery bundle")
	dataIdentity := f.String("identity", "", "Protected age identity file for the database backup")
	keysIdentity := f.String("recovery-identity", "", "Protected age identity file for the recovery bundle")
	work := f.String("work-directory", "", "Existing private staging directory on encrypted storage")
	extract := f.String("recovery-directory", "", "New protected directory for restored configuration and keys")
	confirm := f.String("confirm-database", "", "Exact empty destination database name, required for restore")
	confirmID := f.String("confirm-backup-id", "", "Exact verified backup ID, required for restore")
	dump := f.String("pg-dump", "", "Absolute pg_dump path; defaults to the executable on PATH")
	restore := f.String("pg-restore", "", "Absolute pg_restore path; defaults to the executable on PATH")
	deadline := f.Duration("timeout", 30*time.Minute, "Maximum operation duration (1 second to 24 hours)")
	f.VisitAll(func(item *flag.Flag) { item.Value = &singleValue{Value: item.Value} })
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(diagnostics, "Usage: openuem-recovery --action keygen|create|verify|restore [flags]")
			f.SetOutput(diagnostics)
			f.PrintDefaults()
			return nil
		}
		return recovery.ErrConfig
	}
	allowed := map[string]string{
		"keygen":  "action timeout output",
		"create":  "action timeout output recovery-output specification recipient recovery-recipient pg-dump",
		"verify":  "action timeout input recovery-input identity recovery-identity work-directory",
		"restore": "action timeout input recovery-input identity recovery-identity work-directory recovery-directory confirm-database confirm-backup-id pg-restore",
	}
	invalid := false
	f.Visit(func(item *flag.Flag) {
		if !strings.Contains(" "+allowed[*action]+" ", " "+item.Name+" ") {
			invalid = true
		}
	})
	if invalid {
		return recovery.ErrConfig
	}
	if f.NArg() != 0 || *deadline < time.Second || *deadline > 24*time.Hour {
		return recovery.ErrConfig
	}
	ctx, cancel := context.WithTimeout(ctx, *deadline)
	defer cancel()
	var report *recovery.Report
	var err error
	open := recovery.OpenConfig{DatabaseInput: *dataInput, RecoveryInput: *keysInput, DatabaseIdentity: *dataIdentity, RecoveryIdentity: *keysIdentity, WorkDirectory: *work}
	switch *action {
	case "keygen":
		var public string
		public, err = recovery.GenerateIdentity(*output)
		if err == nil {
			_, err = fmt.Fprintln(out, public)
		}
		return err
	case "create":
		var specification recovery.Specification
		specification, err = recovery.LoadSpecification(*spec)
		if err != nil {
			return err
		}
		report, err = recovery.Create(ctx, recovery.CreateConfig{DatabaseURL: os.Getenv("OPENUEM_RECOVERY_DATABASE_URL"), DatabaseOutput: *output, RecoveryOutput: *keysOutput, DatabaseRecipient: *dataRecipient, RecoveryRecipient: *keysRecipient, Specification: specification, PGDump: *dump})
	case "verify":
		report, err = recovery.Verify(ctx, open)
	case "restore":
		report, err = recovery.Restore(ctx, recovery.RestoreConfig{OpenConfig: open, DatabaseURL: os.Getenv("OPENUEM_RECOVERY_DATABASE_URL"), ConfirmDatabase: *confirm, ConfirmBackupID: *confirmID, RecoveryDirectory: *extract, PGRestore: *restore})
	default:
		return recovery.ErrConfig
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(report)
}

// Reject duplicate flags, particularly conflicting restore confirmations.
type singleValue struct {
	flag.Value
	seen bool
}

func (v *singleValue) Set(value string) error {
	if v.seen {
		return recovery.ErrConfig
	}
	v.seen = true
	return v.Value.Set(value)
}

func (v *singleValue) String() string {
	if v.Value == nil {
		return ""
	}
	return v.Value.String()
}
