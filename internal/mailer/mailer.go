package mailer

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"mime"
	"mime/multipart"
	"net"
	"net/smtp"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"networksambascanner/internal/config"
)

// Send delivers the report files in attachments via the configured SMTP server.
// attachments is a map of format → file path (as returned by report.Generate).
func Send(cfg *config.Config, attachments map[string]string) error {
	if !cfg.Email.Enabled {
		return nil
	}
	if len(cfg.Email.To) == 0 {
		return fmt.Errorf("email.to is empty")
	}

	subject, err := renderSubject(cfg.Email.Subject)
	if err != nil {
		return fmt.Errorf("rendering email subject: %w", err)
	}

	// Build message body (MIME multipart/mixed)
	var buf bytes.Buffer
	boundary := fmt.Sprintf("----=_Part_%d", time.Now().UnixNano())

	// Headers
	writeHeader := func(k, v string) { fmt.Fprintf(&buf, "%s: %s\r\n", k, v) }
	writeHeader("From", cfg.Email.From)
	writeHeader("To", strings.Join(cfg.Email.To, ", "))
	writeHeader("Subject", mime.QEncoding.Encode("utf-8", subject))
	writeHeader("MIME-Version", "1.0")
	writeHeader("Date", time.Now().Format("Mon, 02 Jan 2006 15:04:05 -0700"))
	writeHeader("Content-Type", fmt.Sprintf("multipart/mixed; boundary=%q", boundary))
	fmt.Fprintf(&buf, "\r\n")

	mw := multipart.NewWriter(&buf)
	mw.SetBoundary(boundary) //nolint:errcheck

	// Inline HTML part (preferred) or plain-text fallback
	inlineAdded := false
	for _, fmt_ := range cfg.Email.SendFormats {
		path, ok := attachments[fmt_]
		if !ok {
			continue
		}

		switch fmt_ {
		case "html":
			if inlineAdded {
				break
			}
			data, err := os.ReadFile(path)
			if err != nil {
				break
			}
			ph := textproto.MIMEHeader{}
			ph.Set("Content-Type", "text/html; charset=utf-8")
			ph.Set("Content-Transfer-Encoding", "quoted-printable")
			pw, err := mw.CreatePart(ph)
			if err != nil {
				break
			}
			pw.Write(data) //nolint:errcheck
			inlineAdded = true

		case "text", "txt":
			if inlineAdded {
				break
			}
			data, err := os.ReadFile(path)
			if err != nil {
				break
			}
			ph := textproto.MIMEHeader{}
			ph.Set("Content-Type", "text/plain; charset=utf-8")
			pw, err := mw.CreatePart(ph)
			if err != nil {
				break
			}
			pw.Write(data) //nolint:errcheck
			inlineAdded = true
		}
	}

	// Attach remaining files
	for _, fmt_ := range cfg.Email.SendFormats {
		path, ok := attachments[fmt_]
		if !ok {
			continue
		}

		// Skip formats already written inline
		if (fmt_ == "html" || fmt_ == "text" || fmt_ == "txt") && inlineAdded {
			continue
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading attachment %s: %w", path, err)
		}

		ct := mimeTypeFor(path)
		ph := textproto.MIMEHeader{}
		ph.Set("Content-Type", ct)
		ph.Set("Content-Transfer-Encoding", "base64")
		ph.Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=%q", filepath.Base(path)))

		pw, err := mw.CreatePart(ph)
		if err != nil {
			return fmt.Errorf("creating MIME part: %w", err)
		}

		enc := base64.NewEncoder(base64.StdEncoding, pw)
		enc.Write(data) //nolint:errcheck
		enc.Close()
	}
	mw.Close() //nolint:errcheck

	// ── SMTP delivery ─────────────────────────────────────────────────────
	addr := fmt.Sprintf("%s:%d", cfg.Email.SMTPHost, cfg.Email.SMTPPort)

	var auth smtp.Auth
	if cfg.Email.SMTPUser != "" {
		auth = smtp.PlainAuth("", cfg.Email.SMTPUser, cfg.Email.SMTPPassword, cfg.Email.SMTPHost)
	}

	msg := buf.Bytes()

	if cfg.Email.SMTPUseTLS {
		// Implicit TLS (SMTPS, typically port 465)
		tlsCfg := &tls.Config{ServerName: cfg.Email.SMTPHost}
		conn, err := tls.Dial("tcp", addr, tlsCfg)
		if err != nil {
			return fmt.Errorf("TLS dial %s: %w", addr, err)
		}
		client, err := smtp.NewClient(conn, cfg.Email.SMTPHost)
		if err != nil {
			return fmt.Errorf("SMTP client: %w", err)
		}
		return sendViaSMTPClient(client, auth, cfg, msg)
	}

	// STARTTLS or plain
	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("SMTP dial %s: %w", addr, err)
	}

	if cfg.Email.SMTPUseSTARTTLS {
		tlsCfg := &tls.Config{ServerName: cfg.Email.SMTPHost}
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(tlsCfg); err != nil {
				return fmt.Errorf("STARTTLS: %w", err)
			}
		}
	}

	return sendViaSMTPClient(client, auth, cfg, msg)
}

func sendViaSMTPClient(c *smtp.Client, auth smtp.Auth, cfg *config.Config, msg []byte) error {
	defer c.Quit() //nolint:errcheck

	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("SMTP auth: %w", err)
		}
	}

	from := extractAddr(cfg.Email.From)
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("SMTP MAIL FROM: %w", err)
	}

	for _, to := range cfg.Email.To {
		if err := c.Rcpt(to); err != nil {
			return fmt.Errorf("SMTP RCPT TO %s: %w", to, err)
		}
	}

	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("SMTP write: %w", err)
	}
	return w.Close()
}

// extractAddr strips a display name from "Name <addr>" format.
func extractAddr(s string) string {
	if i := strings.Index(s, "<"); i >= 0 {
		if j := strings.Index(s, ">"); j > i {
			return strings.TrimSpace(s[i+1 : j])
		}
	}
	return strings.TrimSpace(s)
}

// mimeTypeFor returns a MIME type suitable for the file's extension.
func mimeTypeFor(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".pdf":
		return "application/pdf"
	case ".html", ".htm":
		return "text/html"
	case ".txt":
		return "text/plain"
	default:
		return "application/octet-stream"
	}
}

// renderSubject expands simple Go template variables in the subject line.
func renderSubject(subject string) (string, error) {
	tmpl, err := template.New("subject").Parse(subject)
	if err != nil {
		return subject, err
	}
	data := struct{ Date, Time, Host string }{
		Date: time.Now().Format("2006-01-02"),
		Time: time.Now().Format("15:04:05"),
	}
	if h, err := net.LookupAddr("127.0.0.1"); err == nil && len(h) > 0 {
		data.Host = h[0]
	}
	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return subject, err
	}
	return buf.String(), nil
}
