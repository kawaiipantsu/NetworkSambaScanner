package report

import (
	"fmt"
	"time"

	"github.com/go-pdf/fpdf"
	"networksambascanner/internal/scanner"
)

// colour triplet
type pdfRGB struct{ r, g, b int }

// palette
var (
	pdfColBg    = pdfRGB{15, 17, 23}
	pdfColText  = pdfRGB{201, 209, 217}
	pdfColHead  = pdfRGB{88, 166, 255}
	pdfColCrit  = pdfRGB{248, 81, 73}
	pdfColWarn  = pdfRGB{227, 179, 65}
	pdfColGood  = pdfRGB{63, 185, 80}
	pdfColMuted = pdfRGB{139, 148, 158}
	pdfColRow   = pdfRGB{22, 27, 34}
)

// WritePDF generates a PDF report and writes it to path.
func WritePDF(path string, s *scanner.ScanSummary) error {
	f := fpdf.New("P", "mm", "A4", "")
	f.SetMargins(15, 15, 15)
	f.SetAutoPageBreak(true, 20)

	setFill := func(c pdfRGB) { f.SetFillColor(c.r, c.g, c.b) }
	setDraw := func(c pdfRGB) { f.SetDrawColor(c.r, c.g, c.b) }
	setTxt := func(c pdfRGB) { f.SetTextColor(c.r, c.g, c.b) }

	// ── Cover page ────────────────────────────────────────────────────────
	f.AddPage()

	setFill(pdfColBg)
	f.Rect(0, 0, 210, 297, "F")

	setTxt(pdfColHead)
	f.SetFont("Helvetica", "B", 26)
	f.SetXY(15, 50)
	f.CellFormat(180, 12, "Network Samba Scanner", "", 1, "C", false, 0, "")

	setTxt(pdfColText)
	f.SetFont("Helvetica", "", 13)
	f.SetXY(15, 68)
	f.CellFormat(180, 8, "SMB Vulnerability Scan Report", "", 1, "C", false, 0, "")

	setTxt(pdfColMuted)
	f.SetFont("Helvetica", "", 10)
	f.SetXY(15, 82)
	f.CellFormat(180, 6, fmt.Sprintf("Generated: %s", time.Now().Format("2006-01-02 15:04:05")), "", 1, "C", false, 0, "")
	f.SetXY(15, 89)
	f.CellFormat(180, 6, fmt.Sprintf("Scan: %s  to  %s  (%s)",
		s.StartTime.Format("2006-01-02 15:04:05"),
		s.EndTime.Format("2006-01-02 15:04:05"),
		s.Duration().Round(time.Second),
	), "", 1, "C", false, 0, "")

	// Stat boxes
	drawStat := func(x, y float64, val, label string, vc pdfRGB) {
		setFill(pdfColRow)
		setDraw(pdfColRow)
		f.RoundedRect(x, y, 36, 22, 3, "1234", "FD")
		setTxt(vc)
		f.SetFont("Helvetica", "B", 16)
		f.SetXY(x, y+3)
		f.CellFormat(36, 8, val, "", 1, "C", false, 0, "")
		setTxt(pdfColMuted)
		f.SetFont("Helvetica", "", 7)
		f.SetXY(x, y+12)
		f.CellFormat(36, 4, label, "", 1, "C", false, 0, "")
	}

	critCol := pdfColGood
	if s.CriticalCount > 0 {
		critCol = pdfColCrit
	}
	warnCol := pdfColGood
	if s.WarningCount > 0 {
		warnCol = pdfColWarn
	}

	drawStat(15, 110, fmt.Sprintf("%d", s.TotalHosts), "TOTAL HOSTS", pdfColHead)
	drawStat(55, 110, fmt.Sprintf("%d", s.ReachableHosts), "REACHABLE", pdfColHead)
	drawStat(95, 110, fmt.Sprintf("%d", s.SMBHosts), "SMB OPEN", pdfColHead)
	drawStat(135, 110, fmt.Sprintf("%d", s.CriticalCount), "CRITICAL", critCol)
	drawStat(158, 110, fmt.Sprintf("%d", s.WarningCount), "WARNINGS", warnCol)

	// ── Page helpers ──────────────────────────────────────────────────────
	addDarkPage := func() {
		f.AddPage()
		setFill(pdfColBg)
		f.Rect(0, 0, 210, 297, "F")
	}

	sectionHeader := func(title string) {
		setTxt(pdfColHead)
		f.SetFont("Helvetica", "B", 13)
		f.Ln(4)
		f.CellFormat(180, 8, title, "B", 1, "L", false, 0, "")
		f.Ln(2)
		setTxt(pdfColText)
		f.SetFont("Helvetica", "", 9)
	}

	// ── Findings page ──────────────────────────────────────────────────────
	addDarkPage()
	sectionHeader("Findings")

	for _, r := range s.Results {
		if !r.SMBOpen || (len(r.Findings) == 0 && len(r.Shares) == 0) {
			continue
		}

		if f.GetY() > 240 {
			addDarkPage()
			sectionHeader("Findings (continued)")
		}

		// Host header bar
		setFill(pdfColRow)
		setDraw(pdfColRow)
		f.RoundedRect(15, f.GetY(), 180, 8, 2, "1234", "FD")
		setTxt(pdfColHead)
		f.SetFont("Helvetica", "B", 10)
		f.CellFormat(90, 8, fmt.Sprintf("  %s", r.Host), "", 0, "L", false, 0, "")
		setTxt(pdfColMuted)
		f.SetFont("Helvetica", "", 8)
		f.CellFormat(90, 8, fmt.Sprintf("SMB: %s", r.SMBVersion), "", 1, "R", false, 0, "")
		f.Ln(1)

		// Shares table
		if len(r.Shares) > 0 {
			colW := []float64{55, 30, 20, 20, 55}
			headers := []string{"Share Name", "Type", "Read", "Write", "Credential"}

			setTxt(pdfColMuted)
			f.SetFont("Helvetica", "B", 7.5)
			for i, h := range headers {
				f.CellFormat(colW[i], 5, h, "B", 0, "L", false, 0, "")
			}
			f.Ln(-1)

			f.SetFont("Helvetica", "", 8)
			for idx, sh := range r.Shares {
				if f.GetY() > 265 {
					addDarkPage()
				}
				if idx%2 == 0 {
					setFill(pdfColRow)
					f.Rect(15, f.GetY(), 180, 5, "F")
				}
				setTxt(pdfColText)
				f.CellFormat(colW[0], 5, sh.Name, "", 0, "L", false, 0, "")
				f.CellFormat(colW[1], 5, sh.Type.String(), "", 0, "L", false, 0, "")

				rCol := pdfColGood
				if !sh.Readable {
					rCol = pdfColMuted
				}
				wCol := pdfColCrit
				if !sh.Writable {
					wCol = pdfColMuted
				}
				setTxt(rCol)
				f.CellFormat(colW[2], 5, pdfYesNo(sh.Readable), "", 0, "C", false, 0, "")
				setTxt(wCol)
				f.CellFormat(colW[3], 5, pdfYesNo(sh.Writable), "", 0, "C", false, 0, "")
				setTxt(pdfColText)
				f.CellFormat(colW[4], 5, sh.Credential, "", 1, "L", false, 0, "")
			}
			f.Ln(2)
		}

		// Finding rows
		for _, finding := range r.Findings {
			if f.GetY() > 260 {
				addDarkPage()
				sectionHeader("Findings (continued)")
			}

			var fc pdfRGB
			switch finding.Severity {
			case scanner.SeverityCritical:
				fc = pdfColCrit
			case scanner.SeverityWarning:
				fc = pdfColWarn
			default:
				fc = pdfColHead
			}

			setTxt(fc)
			f.SetFont("Helvetica", "B", 8.5)
			f.CellFormat(20, 5, fmt.Sprintf("[%s]", finding.Severity), "", 0, "L", false, 0, "")
			setTxt(pdfColText)
			f.SetFont("Helvetica", "B", 8.5)
			f.MultiCell(160, 5, finding.Title, "", "L", false)

			if finding.Description != "" {
				setTxt(pdfColMuted)
				f.SetFont("Helvetica", "", 7.5)
				f.SetX(35)
				f.MultiCell(160, 4, finding.Description, "", "L", false)
			}
			f.Ln(1)
		}
		f.Ln(3)
	}

	// ── Full host table ────────────────────────────────────────────────────
	addDarkPage()
	sectionHeader("All Scanned Hosts")

	colW := []float64{45, 25, 25, 45, 20, 20}
	hdrs := []string{"Host", "Reachable", "SMB Open", "SMB Version", "Critical", "Warn"}

	setTxt(pdfColMuted)
	f.SetFont("Helvetica", "B", 7.5)
	for i, h := range hdrs {
		f.CellFormat(colW[i], 5, h, "B", 0, "C", false, 0, "")
	}
	f.Ln(-1)

	f.SetFont("Helvetica", "", 8)
	for idx, r := range s.Results {
		if f.GetY() > 265 {
			addDarkPage()
			sectionHeader("All Scanned Hosts (continued)")
			setTxt(pdfColMuted)
			f.SetFont("Helvetica", "B", 7.5)
			for i, h := range hdrs {
				f.CellFormat(colW[i], 5, h, "B", 0, "C", false, 0, "")
			}
			f.Ln(-1)
			f.SetFont("Helvetica", "", 8)
		}

		if idx%2 == 0 {
			setFill(pdfColRow)
			f.Rect(15, f.GetY(), 180, 5, "F")
		}

		setTxt(pdfColText)
		f.CellFormat(colW[0], 5, r.Host, "", 0, "L", false, 0, "")

		setTxt(pdfBoolColor(r.Reachable, pdfColGood, pdfColMuted))
		f.CellFormat(colW[1], 5, pdfYesNo(r.Reachable), "", 0, "C", false, 0, "")

		setTxt(pdfBoolColor(r.SMBOpen, pdfColGood, pdfColMuted))
		f.CellFormat(colW[2], 5, pdfYesNo(r.SMBOpen), "", 0, "C", false, 0, "")

		vc := pdfColGood
		if r.SMBVersion == scanner.SMBVersion1 {
			vc = pdfColWarn
		} else if r.SMBVersion == scanner.SMBVersionUnknown {
			vc = pdfColMuted
		}
		setTxt(vc)
		f.CellFormat(colW[3], 5, r.SMBVersion.String(), "", 0, "C", false, 0, "")

		setTxt(pdfBoolColor(r.HasCritical(), pdfColCrit, pdfColMuted))
		f.CellFormat(colW[4], 5, pdfFlag(r.HasCritical()), "", 0, "C", false, 0, "")

		setTxt(pdfBoolColor(r.HasWarning(), pdfColWarn, pdfColMuted))
		f.CellFormat(colW[5], 5, pdfFlag(r.HasWarning()), "", 0, "C", false, 0, "")

		f.Ln(-1)
	}

	return f.OutputFileAndClose(path)
}

func pdfYesNo(b bool) string {
	if b {
		return "YES"
	}
	return "NO"
}

func pdfFlag(b bool) string {
	if b {
		return "!"
	}
	return "-"
}

func pdfBoolColor(b bool, yes, no pdfRGB) pdfRGB {
	if b {
		return yes
	}
	return no
}
