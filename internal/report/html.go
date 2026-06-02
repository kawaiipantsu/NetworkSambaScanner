package report

import (
	"html/template"
	"io"
	"time"

	"networksambascanner/internal/scanner"
)

// htmlTemplate is the full HTML report template.
var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"severityClass": func(s scanner.Severity) string {
		switch s {
		case scanner.SeverityCritical:
			return "critical"
		case scanner.SeverityWarning:
			return "warning"
		default:
			return "info"
		}
	},
	"boolIcon": func(b bool) template.HTML {
		if b {
			return template.HTML(`<span class="yes">&#10003;</span>`)
		}
		return template.HTML(`<span class="no">&#10007;</span>`)
	},
	"now": func() string { return time.Now().Format("2006-01-02 15:04:05") },
}).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SMB Scan Report – {{ .Summary.StartTime.Format "2006-01-02" }}</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',Arial,sans-serif;background:#0f1117;color:#c9d1d9;line-height:1.6}
  .wrapper{max-width:1200px;margin:0 auto;padding:2rem}
  h1{color:#58a6ff;font-size:1.8rem;margin-bottom:.25rem}
  h2{color:#79c0ff;font-size:1.2rem;margin:1.5rem 0 .5rem;border-bottom:1px solid #30363d;padding-bottom:.3rem}
  h3{color:#e3b341;font-size:1rem;margin:.75rem 0 .25rem}
  .meta{color:#8b949e;font-size:.85rem;margin-bottom:1.5rem}
  .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1rem;margin:1rem 0 2rem}
  .stat{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;text-align:center}
  .stat .val{font-size:2rem;font-weight:bold;display:block}
  .stat .lbl{font-size:.75rem;color:#8b949e;text-transform:uppercase;letter-spacing:.05em}
  .stat.critical .val{color:#f85149}
  .stat.warning  .val{color:#e3b341}
  .stat.good     .val{color:#3fb950}
  .stat.blue     .val{color:#58a6ff}
  table{width:100%;border-collapse:collapse;font-size:.88rem;margin:.5rem 0}
  th{background:#161b22;color:#8b949e;text-align:left;padding:.5rem .75rem;border:1px solid #30363d;font-weight:600;text-transform:uppercase;font-size:.75rem;letter-spacing:.04em}
  td{padding:.45rem .75rem;border:1px solid #21262d;vertical-align:top}
  tr:nth-child(even) td{background:#161b22}
  .badge{display:inline-block;padding:.15rem .5rem;border-radius:12px;font-size:.75rem;font-weight:600;text-transform:uppercase}
  .badge.critical{background:#3d1a1a;color:#f85149;border:1px solid #f85149}
  .badge.warning {background:#2d2000;color:#e3b341;border:1px solid #e3b341}
  .badge.info    {background:#0d2137;color:#58a6ff;border:1px solid #58a6ff}
  .host-card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem 1.25rem;margin-bottom:1.25rem}
  .host-card.has-critical{border-left:3px solid #f85149}
  .host-card.has-warning {border-left:3px solid #e3b341}
  .host-title{font-size:1rem;font-weight:600;color:#e6edf3;margin-bottom:.25rem}
  .host-meta{font-size:.8rem;color:#8b949e;margin-bottom:.75rem}
  .finding{padding:.4rem .6rem;border-radius:4px;margin:.3rem 0;font-size:.85rem}
  .finding.critical{background:#1a0c0c;border-left:3px solid #f85149}
  .finding.warning {background:#1a1400;border-left:3px solid #e3b341}
  .finding.info    {background:#0d1f30;border-left:3px solid #58a6ff}
  .finding .f-title{font-weight:600}
  .finding .f-desc {color:#8b949e;font-size:.82rem;margin-top:.2rem}
  .yes{color:#3fb950;font-weight:bold}
  .no {color:#6e7681}
  .smb1{color:#f85149;font-weight:600}
  .smb2,.smb3{color:#3fb950}
  footer{margin-top:3rem;text-align:center;color:#30363d;font-size:.78rem}
  .no-findings{color:#8b949e;font-style:italic;padding:.5rem 0}
</style>
</head>
<body>
<div class="wrapper">
  <h1>&#128272; Network Samba Scanner</h1>
  <div class="meta">
    Report generated: {{ now }} &nbsp;|&nbsp;
    Scan started: {{ .Summary.StartTime.Format "2006-01-02 15:04:05" }} &nbsp;|&nbsp;
    Duration: {{ .Summary.Duration }}
  </div>

  <!-- Stats row -->
  <div class="stats">
    <div class="stat blue">
      <span class="val">{{ .Summary.TotalHosts }}</span>
      <span class="lbl">Hosts Scanned</span>
    </div>
    <div class="stat blue">
      <span class="val">{{ .Summary.ReachableHosts }}</span>
      <span class="lbl">Reachable</span>
    </div>
    <div class="stat blue">
      <span class="val">{{ .Summary.SMBHosts }}</span>
      <span class="lbl">SMB Open</span>
    </div>
    <div class="stat {{ if gt .Summary.CriticalCount 0 }}critical{{ else }}good{{ end }}">
      <span class="val">{{ .Summary.CriticalCount }}</span>
      <span class="lbl">Critical</span>
    </div>
    <div class="stat {{ if gt .Summary.WarningCount 0 }}warning{{ else }}good{{ end }}">
      <span class="val">{{ .Summary.WarningCount }}</span>
      <span class="lbl">Warnings</span>
    </div>
  </div>

  <!-- Findings section -->
  <h2>Findings</h2>
  {{ $hasFinding := false }}
  {{ range .Summary.Results }}
    {{ if and .SMBOpen (or .Findings .Shares) }}
      {{ $hasFinding = true }}
      <div class="host-card {{ if .HasCritical }}has-critical{{ else if .HasWarning }}has-warning{{ end }}">
        <div class="host-title">{{ .Host }}</div>
        <div class="host-meta">
          SMB Version: <strong class="{{ if eq .SMBVersion.String "SMBv1" }}smb1{{ else }}smb2{{ end }}">{{ .SMBVersion }}</strong>
          {{ if .OSInfo }}&nbsp;|&nbsp; OS: {{ .OSInfo }}{{ end }}
          &nbsp;|&nbsp; Scan time: {{ .Duration }}
        </div>

        {{ if .Shares }}
        <h3>Shares</h3>
        <table>
          <tr><th>Name</th><th>Type</th><th>Readable</th><th>Writable</th><th>Credential</th></tr>
          {{ range .Shares }}
          <tr>
            <td>{{ .Name }}</td>
            <td>{{ .Type }}</td>
            <td>{{ boolIcon .Readable }}</td>
            <td>{{ boolIcon .Writable }}</td>
            <td>{{ if .Credential }}{{ .Credential }}{{ else }}&ndash;{{ end }}</td>
          </tr>
          {{ end }}
        </table>
        {{ end }}

        {{ if .Findings }}
        <h3>Issues</h3>
        {{ range .Findings }}
        <div class="finding {{ severityClass .Severity }}">
          <div class="f-title">
            <span class="badge {{ severityClass .Severity }}">{{ .Severity }}</span>
            &nbsp;{{ .Title }}
          </div>
          {{ if .Description }}<div class="f-desc">{{ .Description }}</div>{{ end }}
        </div>
        {{ end }}
        {{ end }}
      </div>
    {{ end }}
  {{ end }}
  {{ if not $hasFinding }}
  <p class="no-findings">No SMB hosts with findings were detected.</p>
  {{ end }}

  <!-- Full host table -->
  <h2>All Scanned Hosts</h2>
  <table>
    <tr>
      <th>Host</th>
      <th>Reachable</th>
      <th>SMB Open</th>
      <th>SMB Version</th>
      <th>Shares</th>
      <th>Critical</th>
      <th>Warnings</th>
    </tr>
    {{ range .Summary.Results }}
    <tr>
      <td>{{ .Host }}</td>
      <td>{{ boolIcon .Reachable }}</td>
      <td>{{ boolIcon .SMBOpen }}</td>
      <td>{{ if eq .SMBVersion.String "SMBv1" }}<span class="smb1">{{ .SMBVersion }}</span>{{ else }}<span class="smb2">{{ .SMBVersion }}</span>{{ end }}</td>
      <td>{{ len .Shares }}</td>
      <td>{{ if .HasCritical }}<span class="badge critical">YES</span>{{ else }}&ndash;{{ end }}</td>
      <td>{{ if .HasWarning }}<span class="badge warning">YES</span>{{ else }}&ndash;{{ end }}</td>
    </tr>
    {{ end }}
  </table>

  <footer>Generated by NetworkSambaScanner &bull; {{ now }}</footer>
</div>
</body>
</html>
`))

// templateData is passed to the HTML template.
type templateData struct {
	Summary *scanner.ScanSummary
}

// WriteHTML renders the HTML report to w.
func WriteHTML(w io.Writer, s *scanner.ScanSummary) error {
	return htmlTemplate.Execute(w, templateData{Summary: s})
}
