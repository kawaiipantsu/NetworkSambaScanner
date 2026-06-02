package report

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"networksambascanner/internal/config"
	"networksambascanner/internal/scanner"
)

// Generate writes all configured report formats for s to cfg.Report.OutputDir
// and returns a map of format → file path for each file created.
func Generate(s *scanner.ScanSummary, cfg *config.Config) (map[string]string, error) {
	if !cfg.Report.Enabled {
		return nil, nil
	}

	if err := os.MkdirAll(cfg.Report.OutputDir, 0755); err != nil {
		return nil, fmt.Errorf("creating report directory %s: %w", cfg.Report.OutputDir, err)
	}

	ts := ""
	if cfg.Report.IncludeTimestamp {
		tf := cfg.Report.TimestampFormat
		if tf == "" {
			tf = "2006-01-02_15-04-05"
		}
		ts = "_" + time.Now().Format(tf)
	}
	prefix := cfg.Report.FilenamePrefix
	if prefix == "" {
		prefix = "smb_scan"
	}

	paths := make(map[string]string)

	for _, fmt_ := range cfg.Report.Formats {
		var path string
		var err error

		switch fmt_ {
		case "text", "txt":
			path = filepath.Join(cfg.Report.OutputDir, prefix+ts+".txt")
			err = writeFile(path, func(f *os.File) error { return WriteText(f, s) })

		case "html":
			path = filepath.Join(cfg.Report.OutputDir, prefix+ts+".html")
			err = writeFile(path, func(f *os.File) error { return WriteHTML(f, s) })

		case "pdf":
			path = filepath.Join(cfg.Report.OutputDir, prefix+ts+".pdf")
			err = WritePDF(path, s)

		default:
			return paths, fmt.Errorf("unknown report format %q", fmt_)
		}

		if err != nil {
			return paths, fmt.Errorf("generating %s report: %w", fmt_, err)
		}
		paths[fmt_] = path
	}

	return paths, nil
}

func writeFile(path string, fn func(*os.File) error) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	defer f.Close()
	return fn(f)
}
