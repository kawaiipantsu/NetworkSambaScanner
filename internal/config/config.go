package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration structure.
type Config struct {
	Scanner  ScannerConfig  `yaml:"scanner"`
	Features FeatureConfig  `yaml:"features"`
	Ranges   []string       `yaml:"ranges"`
	Credentials []Credential `yaml:"credentials"`
	Report   ReportConfig   `yaml:"report"`
	Email    EmailConfig    `yaml:"email"`
	Logging  LoggingConfig  `yaml:"logging"`
}

// ScannerConfig controls scanning behaviour.
type ScannerConfig struct {
	Workers     int           `yaml:"workers"`
	Timeout     time.Duration `yaml:"timeout"`
	Retries     int           `yaml:"retries"`
	SMBPort     int           `yaml:"smb_port"`
	NetBIOSPort int           `yaml:"netbios_port"`
}

// FeatureConfig toggles individual probe capabilities.
type FeatureConfig struct {
	DetectSambaVersion    bool `yaml:"detect_samba_version"`
	EnumerateShares       bool `yaml:"enumerate_shares"`
	CheckSharePermissions bool `yaml:"check_share_permissions"`
	CheckNullSessions     bool `yaml:"check_null_sessions"`
	CheckGuestAccess      bool `yaml:"check_guest_access"`
	CheckDangerousShares  bool `yaml:"check_dangerous_shares"`
}

// Credential holds an SMB authentication pair.
type Credential struct {
	Username    string `yaml:"username"`
	Password    string `yaml:"password"`
	Domain      string `yaml:"domain"`
	Description string `yaml:"description"`
}

// ReportConfig controls output file generation.
type ReportConfig struct {
	Enabled          bool     `yaml:"enabled"`
	OutputDir        string   `yaml:"output_dir"`
	Formats          []string `yaml:"formats"`
	FilenamePrefix   string   `yaml:"filename_prefix"`
	TimestampFormat  string   `yaml:"timestamp_format"`
	IncludeTimestamp bool     `yaml:"include_timestamp"`
	MinSeverity      string   `yaml:"min_severity"`
	ShowVulnerableOnly bool   `yaml:"show_vulnerable_only"`
}

// EmailConfig controls SMTP delivery of reports.
type EmailConfig struct {
	Enabled        bool     `yaml:"enabled"`
	SMTPHost       string   `yaml:"smtp_host"`
	SMTPPort       int      `yaml:"smtp_port"`
	SMTPUseTLS     bool     `yaml:"smtp_use_tls"`
	SMTPUseSTARTTLS bool    `yaml:"smtp_use_starttls"`
	SMTPUser       string   `yaml:"smtp_user"`
	SMTPPassword   string   `yaml:"smtp_password"`
	From           string   `yaml:"from"`
	To             []string `yaml:"to"`
	Subject        string   `yaml:"subject"`
	SendFormats    []string `yaml:"send_formats"`
	OnlyOnFindings bool     `yaml:"only_on_findings"`
}

// LoggingConfig controls log output.
type LoggingConfig struct {
	Level      string `yaml:"level"`
	File       string `yaml:"file"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups"`
	Console    bool   `yaml:"console"`
}

// DefaultConfig returns a fully-populated default configuration.
func DefaultConfig() *Config {
	home, _ := os.UserHomeDir()
	return &Config{
		Scanner: ScannerConfig{
			Workers:     50,
			Timeout:     5 * time.Second,
			Retries:     2,
			SMBPort:     445,
			NetBIOSPort: 139,
		},
		Features: FeatureConfig{
			DetectSambaVersion:    true,
			EnumerateShares:       true,
			CheckSharePermissions: true,
			CheckNullSessions:     true,
			CheckGuestAccess:      true,
			CheckDangerousShares:  true,
		},
		Ranges: []string{
			"192.168.1.0/24",
		},
		Credentials: []Credential{
			{Username: "", Password: "", Domain: "", Description: "Anonymous/Null session"},
			{Username: "guest", Password: "", Domain: "", Description: "Guest account"},
		},
		Report: ReportConfig{
			Enabled:          true,
			OutputDir:        filepath.Join("/var/log/networksambascanner"),
			Formats:          []string{"text", "html"},
			FilenamePrefix:   "smb_scan",
			TimestampFormat:  "2006-01-02_15-04-05",
			IncludeTimestamp: true,
			MinSeverity:      "info",
			ShowVulnerableOnly: false,
		},
		Email: EmailConfig{
			Enabled:         false,
			SMTPHost:        "smtp.example.com",
			SMTPPort:        587,
			SMTPUseTLS:      false,
			SMTPUseSTARTTLS: true,
			SMTPUser:        "scanner@example.com",
			SMTPPassword:    "",
			From:            "SMB Scanner <scanner@example.com>",
			To:              []string{"admin@example.com"},
			Subject:         "Network SMB Scan Report - {{.Date}}",
			SendFormats:     []string{"html"},
			OnlyOnFindings:  true,
		},
		Logging: LoggingConfig{
			Level:      "info",
			File:       filepath.Join(home, "networksambascanner", "scanner.log"),
			MaxSizeMB:  10,
			MaxBackups: 5,
			Console:    true,
		},
	}
}

// searchPaths returns the ordered list of directories to look for the config
// file, honouring /etc, /usr/local/etc, $HOME/networksambascanner, $HOME/etc.
func searchPaths() []string {
	home, _ := os.UserHomeDir()
	return []string{
		"/etc",
		"/usr/local/etc",
		filepath.Join(home, "networksambascanner"),
		filepath.Join(home, "etc"),
	}
}

const configFilename = "networksambascanner.yaml"

// Load reads the configuration from a well-known location.
// If path is non-empty that specific file is used; otherwise the search path
// is tried in order. If no file is found the default config is returned.
func Load(path string) (*Config, string, error) {
	candidates := []string{}

	if path != "" {
		candidates = []string{path}
	} else {
		for _, dir := range searchPaths() {
			candidates = append(candidates, filepath.Join(dir, configFilename))
		}
	}

	for _, candidate := range candidates {
		data, err := os.ReadFile(candidate)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, "", fmt.Errorf("reading config %s: %w", candidate, err)
		}

		cfg := DefaultConfig()
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, "", fmt.Errorf("parsing config %s: %w", candidate, err)
		}

		// Apply defaults for zero values
		if cfg.Scanner.SMBPort == 0 {
			cfg.Scanner.SMBPort = 445
		}
		if cfg.Scanner.NetBIOSPort == 0 {
			cfg.Scanner.NetBIOSPort = 139
		}
		if cfg.Scanner.Workers == 0 {
			cfg.Scanner.Workers = 50
		}
		if cfg.Scanner.Timeout == 0 {
			cfg.Scanner.Timeout = 5 * time.Second
		}

		return cfg, candidate, nil
	}

	// No config found – use defaults
	return DefaultConfig(), "", nil
}

// WriteDefault serialises the default configuration to dest.
func WriteDefault(dest string) error {
	cfg := DefaultConfig()

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshalling default config: %w", err)
	}

	header := `# NetworkSambaScanner Configuration
# Generated by: networksambascanner --default-config
#
# Place this file at one of:
#   /etc/networksambascanner.yaml
#   /usr/local/etc/networksambascanner.yaml
#   $HOME/networksambascanner/networksambascanner.yaml
#   $HOME/etc/networksambascanner.yaml
#
# All durations accept Go notation: 5s, 500ms, 1m, etc.

`
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	return os.WriteFile(dest, append([]byte(header), data...), 0640)
}
