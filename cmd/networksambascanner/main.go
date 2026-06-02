package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"networksambascanner/internal/config"
	"networksambascanner/internal/mailer"
	"networksambascanner/internal/report"
	"networksambascanner/internal/scanner"
	"networksambascanner/pkg/network"
)

// isTerminal returns true when stdout is connected to an interactive terminal
// (i.e. the process was launched from a shell, not cron or a pipe).
func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

const version = "1.0.0"

const usageFmt = `
NetworkSambaScanner %s – SMB/Samba vulnerability scanner

USAGE
  networksambascanner [options]

OPTIONS
  -c, --config <path>     Path to config file (optional; searched automatically)
  --default-config        Write a default config file and exit
  --default-config-path   Print the path where --default-config would write to
  --dry-run               Expand ranges and print hosts; do not actually scan
  --show-config           Print the loaded configuration and exit
  --crontab               Force crontab mode: generate file reports and send email
                          even when run from an interactive terminal
  -v, --version           Print version and exit
  -h, --help              Show this help

CONFIG FILE SEARCH ORDER
  1.  /etc/networksambascanner.yaml
  2.  /usr/local/etc/networksambascanner.yaml
  3.  $HOME/networksambascanner/networksambascanner.yaml
  4.  $HOME/etc/networksambascanner.yaml

EXAMPLES
  # First-time setup – write a default config
  networksambascanner --default-config

  # Run a scan using the auto-located config
  networksambascanner

  # Run a scan with an explicit config file
  networksambascanner -c /path/to/config.yaml

  # Dry-run: see which IPs would be scanned
  networksambascanner --dry-run

CRON EXAMPLE
  # Run daily at 02:00 and email results
  0 2 * * * /usr/local/bin/networksambascanner >> /var/log/networksambascanner/cron.log 2>&1
`

func main() {
	args := os.Args[1:]

	// ── Flag parsing ───────────────────────────────────────────────────────
	var (
		configPath    string
		doDefaultCfg  bool
		doDefaultPath bool
		doShowConfig  bool
		doDryRun      bool
		forceCrontab  bool
		doVersion     bool
		doHelp        bool
	)

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-c", "--config":
			if i+1 >= len(args) {
				fatal("flag %s requires a path argument", args[i])
			}
			i++
			configPath = args[i]
		case "--default-config":
			doDefaultCfg = true
		case "--default-config-path":
			doDefaultPath = true
		case "--show-config":
			doShowConfig = true
		case "--dry-run":
			doDryRun = true
		case "--crontab":
			forceCrontab = true
		case "-v", "--version":
			doVersion = true
		case "-h", "--help":
			doHelp = true
		default:
			fatal("unknown argument: %s\nRun with --help for usage.", args[i])
		}
	}

	// ── One-shot flags that don't need a config ────────────────────────────
	if doHelp {
		fmt.Printf(usageFmt, version)
		return
	}

	if doVersion {
		fmt.Printf("networksambascanner %s\n", version)
		return
	}

	if doDefaultPath {
		fmt.Println(defaultConfigDest())
		return
	}

	if doDefaultCfg {
		dest := defaultConfigDest()
		fmt.Printf("Writing default configuration to: %s\n", dest)
		if err := config.WriteDefault(dest); err != nil {
			fatal("failed to write default config: %v", err)
		}
		color.Green("Default configuration written successfully.")
		fmt.Printf("Edit %s and then run: networksambascanner\n", dest)
		return
	}

	// ── Load configuration ─────────────────────────────────────────────────
	cfg, cfgPath, err := config.Load(configPath)
	if err != nil {
		fatal("loading config: %v", err)
	}

	if cfgPath != "" {
		color.New(color.FgCyan).Printf("Config: %s\n", cfgPath)
	} else {
		color.New(color.FgYellow).Println("No config file found – using built-in defaults.")
		color.New(color.FgYellow).Println("Run 'networksambascanner --default-config' to create one at:")
		color.New(color.FgYellow).Printf("  %s\n\n", defaultConfigDest())
	}

	if doShowConfig {
		printConfig(cfg, cfgPath)
		return
	}

	if doDryRun {
		runDryRun(cfg)
		return
	}

	// ── Normal scan ────────────────────────────────────────────────────────
	runScan(cfg, forceCrontab)
}

// ── Scan ──────────────────────────────────────────────────────────────────────

func runScan(cfg *config.Config, forceCrontab bool) {
	color.New(color.Bold).Println("\nNetworkSambaScanner – starting scan")

	summary, err := scanner.RunWithProgress(cfg)
	if err != nil {
		fatal("scan failed: %v", err)
	}

	// ── Terminal mode: text report to stdout only, no files, no email ──────
	if isTerminal() && !forceCrontab {
		scanner.PrintSummary(summary)
		fmt.Println(strings.Repeat("─", 72))
		if err := report.WriteText(os.Stdout, summary); err != nil {
			warnf("text report error: %v", err)
		}
		return
	}

	// ── Non-interactive / forced crontab mode: generate files + email ───────
	if forceCrontab {
		color.New(color.FgYellow).Println("(crontab mode forced via --crontab)")
	}
	scanner.PrintSummary(summary)

	if !cfg.Report.Enabled || len(cfg.Report.Formats) == 0 {
		return
	}

	fmt.Println("Generating reports...")
	paths, err := report.Generate(summary, cfg)
	if err != nil {
		warnf("report generation error: %v", err)
	}
	for fmt_, path := range paths {
		color.New(color.FgGreen).Printf("  %-6s → %s\n", strings.ToUpper(fmt_), path)
	}

	if !cfg.Email.Enabled {
		return
	}

	shouldSend := !cfg.Email.OnlyOnFindings ||
		summary.CriticalCount > 0 || summary.WarningCount > 0

	if !shouldSend {
		fmt.Println("No findings – email suppressed (only_on_findings: true).")
		return
	}

	fmt.Println("Sending email report...")
	if err := mailer.Send(cfg, paths); err != nil {
		warnf("email delivery failed: %v", err)
	} else {
		color.New(color.FgGreen).Println("Email sent successfully.")
	}
}

// ── Dry-run ───────────────────────────────────────────────────────────────────

func runDryRun(cfg *config.Config) {
	hosts, err := network.ExpandRanges(cfg.Ranges)
	if err != nil {
		fatal("expanding ranges: %v", err)
	}

	fmt.Printf("Dry-run: %d hosts would be scanned across %d range(s)\n\n",
		len(hosts), len(cfg.Ranges))

	for _, r := range cfg.Ranges {
		expanded, _ := network.ExpandCIDR(r)
		fmt.Printf("  %-22s  → %d hosts\n", r, len(expanded))
	}

	if len(hosts) <= 64 {
		fmt.Println("\nHosts:")
		for _, h := range hosts {
			fmt.Printf("  %s\n", h)
		}
	} else {
		fmt.Printf("\nFirst 10 hosts: ")
		for i := 0; i < 10 && i < len(hosts); i++ {
			fmt.Printf("%s  ", hosts[i])
		}
		fmt.Println("...")
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func defaultConfigDest() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/etc/networksambascanner.yaml"
	}
	return filepath.Join(home, "networksambascanner", "networksambascanner.yaml")
}

func printConfig(cfg *config.Config, path string) {
	bold := color.New(color.Bold)
	bold.Println("\nLoaded configuration:")
	if path != "" {
		fmt.Printf("  File     : %s\n", path)
	} else {
		fmt.Println("  File     : (none – using defaults)")
	}
	fmt.Printf("  Workers  : %d\n", cfg.Scanner.Workers)
	fmt.Printf("  Timeout  : %s\n", cfg.Scanner.Timeout)
	fmt.Printf("  SMB port : %d\n", cfg.Scanner.SMBPort)
	fmt.Printf("  Retries  : %d\n", cfg.Scanner.Retries)
	fmt.Println()
	fmt.Println("  Features:")
	fmt.Printf("    detect_samba_version    : %v\n", cfg.Features.DetectSambaVersion)
	fmt.Printf("    enumerate_shares        : %v\n", cfg.Features.EnumerateShares)
	fmt.Printf("    check_share_permissions : %v\n", cfg.Features.CheckSharePermissions)
	fmt.Printf("    check_null_sessions     : %v\n", cfg.Features.CheckNullSessions)
	fmt.Printf("    check_guest_access      : %v\n", cfg.Features.CheckGuestAccess)
	fmt.Printf("    check_dangerous_shares  : %v\n", cfg.Features.CheckDangerousShares)
	fmt.Println()
	fmt.Printf("  Ranges (%d):\n", len(cfg.Ranges))
	for _, r := range cfg.Ranges {
		fmt.Printf("    - %s\n", r)
	}
	fmt.Println()
	fmt.Printf("  Credentials (%d):\n", len(cfg.Credentials))
	for _, c := range cfg.Credentials {
		label := c.Description
		if label == "" {
			label = c.Username
		}
		if label == "" {
			label = "(anonymous)"
		}
		fmt.Printf("    - %s\n", label)
	}
	fmt.Println()
	fmt.Printf("  Report enabled : %v\n", cfg.Report.Enabled)
	fmt.Printf("  Report dir     : %s\n", cfg.Report.OutputDir)
	fmt.Printf("  Report formats : %v\n", cfg.Report.Formats)
	fmt.Println()
	fmt.Printf("  Email enabled  : %v\n", cfg.Email.Enabled)
	if cfg.Email.Enabled {
		fmt.Printf("  SMTP           : %s:%d\n", cfg.Email.SMTPHost, cfg.Email.SMTPPort)
		fmt.Printf("  To             : %v\n", cfg.Email.To)
	}
}

func fatal(format string, args ...interface{}) {
	color.New(color.FgRed, color.Bold).Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}

func warnf(format string, args ...interface{}) {
	color.New(color.FgYellow).Fprintf(os.Stderr, "WARN: "+format+"\n", args...)
}
