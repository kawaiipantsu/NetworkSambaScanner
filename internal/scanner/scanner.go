package scanner

import (
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
	"networksambascanner/internal/config"
	"networksambascanner/pkg/network"
)

// ProgressCallback is called after each host finishes scanning.
// It receives the completed result and the running count of finished hosts.
type ProgressCallback func(result *HostResult, done, total int)

// Run expands all configured ranges, scans every host concurrently up to
// cfg.Scanner.Workers goroutines, and returns a ScanSummary.
func Run(cfg *config.Config, callback ProgressCallback) (*ScanSummary, error) {
	hosts, err := network.ExpandRanges(cfg.Ranges)
	if err != nil {
		return nil, fmt.Errorf("expanding ranges: %w", err)
	}

	total := len(hosts)
	if total == 0 {
		return nil, fmt.Errorf("no hosts to scan – check your 'ranges' configuration")
	}

	summary := &ScanSummary{
		StartTime:  time.Now(),
		TotalHosts: total,
	}

	// Worker pool
	jobs := make(chan string, total)
	results := make(chan *HostResult, total)

	workers := cfg.Scanner.Workers
	if workers <= 0 {
		workers = 50
	}
	if workers > total {
		workers = total
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				r := ScanHost(host, cfg)
				results <- r
			}
		}()
	}

	// Feed jobs
	for _, h := range hosts {
		jobs <- h
	}
	close(jobs)

	// Collect results in a separate goroutine so we don't deadlock if the
	// channel fills up before all workers finish.
	go func() {
		wg.Wait()
		close(results)
	}()

	done := 0
	for r := range results {
		summary.Results = append(summary.Results, r)
		if r.Reachable {
			summary.ReachableHosts++
		}
		if r.SMBOpen {
			summary.SMBHosts++
		}
		if r.HasCritical() {
			summary.CriticalCount++
		} else if r.HasWarning() {
			summary.WarningCount++
		}
		done++
		if callback != nil {
			callback(r, done, total)
		}
	}

	summary.EndTime = time.Now()

	// Sort results by host IP for deterministic output
	sort.Slice(summary.Results, func(i, j int) bool {
		return summary.Results[i].Host < summary.Results[j].Host
	})

	return summary, nil
}

// RunWithProgress is a convenience wrapper around Run that renders a live
// progress bar and per-finding notifications to stdout.
func RunWithProgress(cfg *config.Config) (*ScanSummary, error) {
	hosts, err := network.ExpandRanges(cfg.Ranges)
	if err != nil {
		return nil, err
	}
	total := len(hosts)

	bar := progressbar.NewOptions(total,
		progressbar.OptionSetDescription("Scanning"),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionSetItsString("hosts"),
		progressbar.OptionThrottle(100*time.Millisecond),
		progressbar.OptionClearOnFinish(),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionFullWidth(),
		progressbar.OptionSetRenderBlankState(true),
	)

	crit := color.New(color.FgRed, color.Bold)
	warn := color.New(color.FgYellow)
	info := color.New(color.FgCyan)

	cb := func(r *HostResult, done, _ int) {
		bar.Add(1) //nolint:errcheck
		if !r.SMBOpen {
			return
		}
		for _, f := range r.Findings {
			switch f.Severity {
			case SeverityCritical:
				crit.Fprintf(os.Stderr, "\n  [CRITICAL] %s – %s\n", r.Host, f.Title) //nolint:errcheck
			case SeverityWarning:
				warn.Fprintf(os.Stderr, "\n  [WARNING]  %s – %s\n", r.Host, f.Title) //nolint:errcheck
			default:
				info.Fprintf(os.Stderr, "\n  [INFO]     %s – %s\n", r.Host, f.Title) //nolint:errcheck
			}
		}
	}

	return Run(cfg, cb)
}

// PrintSummary writes a colourised scan summary to stdout.
func PrintSummary(s *ScanSummary) {
	bold := color.New(color.Bold)
	crit := color.New(color.FgRed, color.Bold)
	warn := color.New(color.FgYellow, color.Bold)
	good := color.New(color.FgGreen)

	fmt.Println()
	bold.Println("══════════════════════════════════════════════════")
	bold.Println("  NetworkSambaScanner – Scan Complete")
	bold.Println("══════════════════════════════════════════════════")
	fmt.Printf("  Started  : %s\n", s.StartTime.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Finished : %s\n", s.EndTime.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Duration : %s\n", s.Duration().Round(time.Second))
	fmt.Println()
	fmt.Printf("  Total hosts    : %d\n", s.TotalHosts)
	fmt.Printf("  Reachable      : %d\n", s.ReachableHosts)
	fmt.Printf("  SMB open       : %d\n", s.SMBHosts)

	if s.CriticalCount > 0 {
		crit.Printf("  Critical issues: %d\n", s.CriticalCount)
	} else {
		good.Printf("  Critical issues: %d\n", s.CriticalCount)
	}

	if s.WarningCount > 0 {
		warn.Printf("  Warnings       : %d\n", s.WarningCount)
	} else {
		good.Printf("  Warnings       : %d\n", s.WarningCount)
	}

	bold.Println("══════════════════════════════════════════════════")
	fmt.Println()

	// List hosts with findings
	for _, r := range s.Results {
		if !r.SMBOpen || len(r.Findings) == 0 {
			continue
		}

		bold.Printf("  %s  [%s]\n", r.Host, r.SMBVersion)
		for _, f := range r.Findings {
			switch f.Severity {
			case SeverityCritical:
				crit.Printf("    ● [CRITICAL] %s\n", f.Title)
			case SeverityWarning:
				warn.Printf("    ● [WARNING]  %s\n", f.Title)
			default:
				fmt.Printf("    ● [INFO]     %s\n", f.Title)
			}
		}
		fmt.Println()
	}
}
