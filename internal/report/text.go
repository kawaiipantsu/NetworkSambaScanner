package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"networksambascanner/internal/scanner"
)

// WriteText writes a plain-text report of the scan summary to w.
func WriteText(w io.Writer, s *scanner.ScanSummary) error {
	sep := strings.Repeat("=", 72)
	thin := strings.Repeat("-", 72)

	writeln := func(format string, args ...interface{}) {
		fmt.Fprintf(w, format+"\n", args...)
	}

	writeln("%s", sep)
	writeln("  NETWORK SAMBA SCANNER – SCAN REPORT")
	writeln("%s", sep)
	writeln("  Generated : %s", time.Now().Format("2006-01-02 15:04:05"))
	writeln("  Scan start: %s", s.StartTime.Format("2006-01-02 15:04:05"))
	writeln("  Scan end  : %s", s.EndTime.Format("2006-01-02 15:04:05"))
	writeln("  Duration  : %s", s.Duration().Round(time.Second))
	writeln("%s", sep)
	writeln("")
	writeln("SUMMARY")
	writeln("%s", thin)
	writeln("  Total hosts    : %d", s.TotalHosts)
	writeln("  Reachable      : %d", s.ReachableHosts)
	writeln("  SMB open       : %d", s.SMBHosts)
	writeln("  Critical issues: %d", s.CriticalCount)
	writeln("  Warnings       : %d", s.WarningCount)
	writeln("")

	// Hosts with findings
	writeln("FINDINGS")
	writeln("%s", thin)

	anyFindings := false
	for _, r := range s.Results {
		if !r.SMBOpen {
			continue
		}
		if len(r.Findings) == 0 && len(r.Shares) == 0 {
			continue
		}
		anyFindings = true

		writeln("")
		writeln("  Host: %s", r.Host)
		writeln("  SMB Version : %s", r.SMBVersion)
		if r.OSInfo != "" {
			writeln("  OS Info     : %s", r.OSInfo)
		}
		writeln("  Scan time   : %s", r.Duration.Round(time.Millisecond))

		if len(r.Shares) > 0 {
			writeln("")
			writeln("  Shares:")
			writeln("  %-20s %-12s %-8s %-8s %s", "Name", "Type", "Read", "Write", "Credential")
			writeln("  %s", strings.Repeat("-", 64))
			for _, sh := range r.Shares {
				writeln("  %-20s %-12s %-8v %-8v %s",
					sh.Name,
					sh.Type,
					boolMark(sh.Readable),
					boolMark(sh.Writable),
					sh.Credential,
				)
			}
		}

		if len(r.Findings) > 0 {
			writeln("")
			writeln("  Findings:")
			for _, f := range r.Findings {
				writeln("  [%s] %s", f.Severity, f.Title)
				if f.Description != "" {
					// Word-wrap description at 68 chars
					for _, line := range wrapText(f.Description, 64) {
						writeln("         %s", line)
					}
				}
			}
		}
		writeln("  %s", thin)
	}

	if !anyFindings {
		writeln("  No SMB hosts with findings found.")
	}

	writeln("")
	writeln("ALL SCANNED HOSTS")
	writeln("%s", thin)
	writeln("  %-18s %-12s %-10s %s", "Host", "Reachable", "SMB Open", "Version")
	writeln("  %s", strings.Repeat("-", 60))
	for _, r := range s.Results {
		writeln("  %-18s %-12v %-10v %s",
			r.Host,
			boolMark(r.Reachable),
			boolMark(r.SMBOpen),
			r.SMBVersion,
		)
	}

	writeln("")
	writeln("%s", sep)
	writeln("  END OF REPORT")
	writeln("%s", sep)

	return nil
}

func boolMark(b bool) string {
	if b {
		return "YES"
	}
	return "NO"
}

// wrapText splits text into lines no longer than width characters.
func wrapText(text string, width int) []string {
	words := strings.Fields(text)
	var lines []string
	var current strings.Builder

	for _, word := range words {
		if current.Len() > 0 && current.Len()+1+len(word) > width {
			lines = append(lines, current.String())
			current.Reset()
		}
		if current.Len() > 0 {
			current.WriteByte(' ')
		}
		current.WriteString(word)
	}
	if current.Len() > 0 {
		lines = append(lines, current.String())
	}
	return lines
}
