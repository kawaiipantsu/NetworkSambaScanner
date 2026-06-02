# NetworkSambaScanner

A Go terminal application for scanning network ranges for SMB/Samba vulnerabilities.

## Features

- **SMB version detection** – identifies SMBv1, SMBv2.x, and SMBv3.x via raw negotiate packets
- **Share enumeration** – lists all available shares via NetShareEnum (null session, guest, or configured credentials)
- **Permission testing** – tests read and write access per share per credential
- **Dangerous share detection** – flags `ADMIN$`, `C$`, `IPC$`, `PRINT$`, etc.
- **Severity classification** – findings rated INFO / WARNING / CRITICAL
- **Multiple report formats** – plain text, self-contained HTML, and PDF
- **Email delivery** – sends reports via SMTP with STARTTLS or implicit TLS
- **Cron-friendly** – designed for one-shot CLI or scheduled cron execution
- **Global config file** – all settings in one YAML file; all features individually toggleable

## Quick Start

```bash
# Build
make

# Write a default config file
./dist/networksambascanner --default-config

# Edit the config
$EDITOR ~/networksambascanner/networksambascanner.yaml

# Run a scan
./dist/networksambascanner
```

## Installation

```bash
# Install to /usr/local/bin with config in /etc/
sudo make install

# Or specify a custom prefix
sudo make install PREFIX=/opt/networksambascanner
```

## Config File Locations (searched in order)

1. `/etc/networksambascanner.yaml`
2. `/usr/local/etc/networksambascanner.yaml`
3. `$HOME/networksambascanner/networksambascanner.yaml`
4. `$HOME/etc/networksambascanner.yaml`

Pass `-c <path>` to use a specific file.

## Usage

```
networksambascanner [options]

  -c, --config <path>     Path to config file
  --default-config        Write default config and exit
  --default-config-path   Print where --default-config would write to
  --dry-run               Show which hosts would be scanned (no network probes)
  --show-config           Print loaded config and exit
  -v, --version           Print version
  -h, --help              Show help
```

## Cron Example

```cron
# Scan daily at 02:00, append output to cron log
0 2 * * * /usr/local/bin/networksambascanner >> /var/log/networksambascanner/cron.log 2>&1
```

## Report Formats

| Format | Description |
|--------|-------------|
| `text` | Human-readable plain text |
| `html` | Self-contained dark-theme HTML report |
| `pdf`  | PDF document via go-pdf/fpdf |

## Build Targets

```bash
make              # build for current platform
make build-debug  # build with race detector
make test         # run tests
make release      # cross-compile Linux/macOS/Windows
make install      # install to /usr/local/bin
make clean        # remove dist/
```

## Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/hirochachacha/go-smb2` | SMB2/3 client (share enumeration) |
| `github.com/fatih/color` | Terminal colours |
| `github.com/schollz/progressbar/v3` | Live progress bar |
| `github.com/go-pdf/fpdf` | PDF generation |
| `gopkg.in/yaml.v3` | YAML config parsing |

SMBv1 detection uses a hand-crafted raw TCP negotiate packet with no external dependency.
