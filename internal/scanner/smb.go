package scanner

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
	"networksambascanner/internal/config"
)

// dangerousShareNames are administrative/special shares that expose elevated risk.
var dangerousShareNames = map[string]bool{
	"ADMIN$": true,
	"C$":     true,
	"D$":     true,
	"E$":     true,
	"IPC$":   true,
	"PRINT$": true,
	"FAX$":   true,
}

// -----------------------------------------------------------------------
// Low-level SMB version detection via raw TCP
// -----------------------------------------------------------------------

// buildSMB1NegotiatePacket constructs a minimal SMBv1 NEGOTIATE request that
// also advertises SMB2 dialects so that the server can up-select.
func buildSMB1NegotiatePacket() []byte {
	dialects := []string{
		"\x02NT LM 0.12\x00",
		"\x02SMB 2.002\x00",
		"\x02SMB 2.???\x00",
	}
	var dialectBytes []byte
	for _, d := range dialects {
		dialectBytes = append(dialectBytes, []byte(d)...)
	}

	// SMB header (32 bytes)
	hdr := make([]byte, 32)
	copy(hdr[0:], []byte{0xFF, 0x53, 0x4D, 0x42}) // \xffSMB
	hdr[4] = 0x72                                   // NEGOTIATE command
	// Status bytes 5-8 remain zero
	hdr[9] = 0x18 // Flags
	binary.LittleEndian.PutUint16(hdr[10:], 0x0001) // Flags2
	binary.LittleEndian.PutUint16(hdr[24:], 0xFFFF) // TID
	binary.LittleEndian.PutUint16(hdr[26:], 0xFEFF) // PID

	// Parameters
	params := []byte{0x00} // WordCount = 0

	// Data: ByteCount + dialects
	bc := uint16(len(dialectBytes))
	data := []byte{byte(bc & 0xFF), byte(bc >> 8)}
	data = append(data, dialectBytes...)

	body := hdr
	body = append(body, params...)
	body = append(body, data...)

	// NetBIOS Session Message header (4 bytes)
	nb := make([]byte, 4)
	nb[0] = 0x00
	l := len(body)
	nb[1] = byte(l >> 16)
	nb[2] = byte(l >> 8)
	nb[3] = byte(l)

	return append(nb, body...)
}

// buildSMB2NegotiatePacket constructs a minimal SMBv2 NEGOTIATE request for
// dialects 2.0.2 through 3.1.1.
func buildSMB2NegotiatePacket() []byte {
	dialects := []uint16{0x0202, 0x0210, 0x0300, 0x0302, 0x0311}

	// SMB2 NEGOTIATE request body (36 bytes fixed + dialect list)
	bodySize := 36 + len(dialects)*2
	neg := make([]byte, bodySize)
	binary.LittleEndian.PutUint16(neg[0:], 36)                    // StructureSize
	binary.LittleEndian.PutUint16(neg[2:], uint16(len(dialects))) // DialectCount
	binary.LittleEndian.PutUint16(neg[4:], 0x0001)                // SecurityMode: signing enabled
	// bytes 6-35 remain zero (Capabilities, ClientGUID, etc.)
	for i, d := range dialects {
		binary.LittleEndian.PutUint16(neg[36+i*2:], d)
	}

	// SMB2 header (64 bytes)
	hdr := make([]byte, 64)
	copy(hdr[0:], []byte{0xFE, 0x53, 0x4D, 0x42}) // \xfeSMB
	binary.LittleEndian.PutUint16(hdr[4:], 64)     // StructureSize
	binary.LittleEndian.PutUint16(hdr[12:], 0)     // Command: NEGOTIATE
	binary.LittleEndian.PutUint16(hdr[14:], 31)    // CreditsRequested

	body := append(hdr, neg...)

	// NetBIOS header
	nb := make([]byte, 4)
	nb[0] = 0x00
	l := len(body)
	nb[1] = byte(l >> 16)
	nb[2] = byte(l >> 8)
	nb[3] = byte(l)

	return append(nb, body...)
}

// detectSMBVersion connects to a host and negotiates to determine the highest
// SMB dialect supported.
func detectSMBVersion(host string, port int, timeout time.Duration) SMBVersion {
	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return SMBVersionUnknown
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout)) //nolint:errcheck

	// Step 1 – send an SMBv1 NEGOTIATE that includes SMB2 dialects.
	pkt := buildSMB1NegotiatePacket()
	if _, err := conn.Write(pkt); err != nil {
		return SMBVersionUnknown
	}

	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil || n < 8 {
		return SMBVersionUnknown
	}

	magic := resp[4:8]

	switch {
	case bytes.Equal(magic, []byte{0xFE, 0x53, 0x4D, 0x42}):
		// Server responded with an SMB2 packet – probe for exact dialect.
		return detectSMB2Dialect(host, port, timeout)

	case bytes.Equal(magic, []byte{0xFF, 0x53, 0x4D, 0x42}):
		return SMBVersion1

	default:
		return SMBVersionUnknown
	}
}

// detectSMB2Dialect sends a proper SMB2 NEGOTIATE to obtain the exact dialect.
func detectSMB2Dialect(host string, port int, timeout time.Duration) SMBVersion {
	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return SMBVersion2
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout)) //nolint:errcheck

	pkt := buildSMB2NegotiatePacket()
	if _, err := conn.Write(pkt); err != nil {
		return SMBVersion2
	}

	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	// SMB2 response: 4 (NetBIOS) + 64 (header) + ≥4 (body) = 72 bytes minimum
	if err != nil || n < 74 {
		return SMBVersion2
	}

	// Dialect is at byte offset 72:
	//   4  (NetBIOS)
	// + 64 (SMB2 header)
	// + 2  (StructureSize of NEGOTIATE_RESPONSE)
	// + 2  (SecurityMode)
	// = 72 → DialectRevision at [72:74]
	dialect := binary.LittleEndian.Uint16(resp[72:74])
	switch dialect {
	case 0x0202:
		return SMBVersion2_02
	case 0x0210:
		return SMBVersion2_1
	case 0x0300:
		return SMBVersion3_0
	case 0x0302:
		return SMBVersion3_02
	case 0x0311:
		return SMBVersion3_11
	default:
		return SMBVersion2
	}
}

// -----------------------------------------------------------------------
// Share enumeration and permission testing via go-smb2
// -----------------------------------------------------------------------

// dialSMB2 creates an authenticated SMB2 session using the supplied credential.
func dialSMB2(host string, port int, cred config.Credential, timeout time.Duration) (*smb2.Session, net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, nil, err
	}

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     cred.Username,
			Password: cred.Password,
			Domain:   cred.Domain,
		},
	}

	sess, err := d.Dial(conn)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	return sess, conn, nil
}

// enumerateShares lists share names via go-smb2 for the given credential.
func enumerateShares(host string, port int, cred config.Credential, timeout time.Duration) ([]string, error) {
	sess, conn, err := dialSMB2(host, port, cred, timeout)
	if err != nil {
		return nil, err
	}
	defer sess.Logoff() //nolint:errcheck
	defer conn.Close()

	names, err := sess.ListSharenames()
	if err != nil {
		return nil, err
	}
	return names, nil
}

// checkSharePerms attempts to mount and read/write a share, returning the
// access level granted by the supplied credential.
func checkSharePerms(host string, port int, shareName string, cred config.Credential, timeout time.Duration) (readable, writable bool) {
	sess, conn, err := dialSMB2(host, port, cred, timeout)
	if err != nil {
		return false, false
	}
	defer sess.Logoff() //nolint:errcheck
	defer conn.Close()

	fs, err := sess.Mount(shareName)
	if err != nil {
		return false, false
	}
	defer fs.Umount() //nolint:errcheck

	// Read check: attempt to open the root directory.
	if d, err := fs.Open("."); err == nil {
		d.Close()
		readable = true
	}

	// Write check: create then remove a sentinel file.
	testName := fmt.Sprintf(".nss_probe_%d", time.Now().UnixNano())
	if f, err := fs.Create(testName); err == nil {
		f.Close()
		fs.Remove(testName) //nolint:errcheck
		writable = true
	}

	return readable, writable
}

// -----------------------------------------------------------------------
// Per-host scan logic
// -----------------------------------------------------------------------

// ScanHost performs a complete SMB probe on a single host and returns the
// result.  It is safe to call from multiple goroutines concurrently.
func ScanHost(host string, cfg *config.Config) *HostResult {
	result := &HostResult{
		Host:     host,
		ScanTime: time.Now(),
	}
	start := time.Now()
	defer func() { result.Duration = time.Since(start) }()

	port := cfg.Scanner.SMBPort
	timeout := cfg.Scanner.Timeout

	// ── 1. Connectivity check ─────────────────────────────────────────────
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		result.Reachable = false
		result.Error = err.Error()
		return result
	}
	conn.Close()
	result.Reachable = true
	result.SMBOpen = true

	// ── 2. Version detection ───────────────────────────────────────────────
	if cfg.Features.DetectSambaVersion {
		result.SMBVersion = detectSMBVersion(host, port, timeout)

		if result.SMBVersion == SMBVersion1 {
			result.Findings = append(result.Findings, Finding{
				Severity: SeverityWarning,
				Title:    "SMBv1 Detected",
				Description: fmt.Sprintf(
					"Host %s supports SMBv1, which is insecure and associated with exploits "+
						"such as EternalBlue/WannaCry. Disable SMBv1 immediately.",
					host,
				),
			})
		}
	}

	// ── 3. Share enumeration ───────────────────────────────────────────────
	if !cfg.Features.EnumerateShares {
		return result
	}

	// Try each configured credential; collect all shares found.
	shareSet := make(map[string]*Share) // name → share

	for _, cred := range cfg.Credentials {
		// Honour null-session / guest flags
		isNull := cred.Username == ""
		isGuest := strings.EqualFold(cred.Username, "guest")

		if isNull && !cfg.Features.CheckNullSessions {
			continue
		}
		if isGuest && !cfg.Features.CheckGuestAccess {
			continue
		}

		names, err := enumerateShares(host, port, cred, timeout)
		if err != nil {
			continue
		}

		credLabel := cred.Username
		if credLabel == "" {
			credLabel = "(anonymous)"
		}

		for _, name := range names {
			upper := strings.ToUpper(name)
			sh, exists := shareSet[upper]
			if !exists {
				sh = &Share{Name: name}
				// Classify share type
				switch {
				case upper == "IPC$":
					sh.Type = ShareTypeIPC
				case dangerousShareNames[upper]:
					sh.Type = ShareTypeSpecial
				default:
					sh.Type = ShareTypeDisk
				}
				shareSet[upper] = sh
			}

			// ── 4. Permission check ─────────────────────────────────────
			if cfg.Features.CheckSharePermissions {
				r, w := checkSharePerms(host, port, name, cred, timeout)
				if r || w {
					sh.Readable = sh.Readable || r
					sh.Writable = sh.Writable || w
					sh.Credential = credLabel
				}
			}
		}
	}

	// ── 5. Build findings from share data ─────────────────────────────────
	for _, sh := range shareSet {
		result.Shares = append(result.Shares, *sh)

		upper := strings.ToUpper(sh.Name)

		// Writable share accessible to everyone
		if sh.Writable {
			sev := SeverityCritical
			title := fmt.Sprintf("Share '%s' is writable by %s", sh.Name, sh.Credential)
			desc := fmt.Sprintf(
				"The share \\\\%s\\%s grants write access to credential '%s'. "+
					"An attacker could plant executables or exfiltrate data.",
				host, sh.Name, sh.Credential,
			)
			if upper == "IPC$" {
				// Writable IPC$ is normal; downgrade severity
				sev = SeverityInfo
				title = fmt.Sprintf("IPC$ accessible via %s", sh.Credential)
				desc = ""
			}
			sh.Severity = sev
			if desc != "" {
				result.Findings = append(result.Findings, Finding{
					Severity:    sev,
					Title:       title,
					Description: desc,
				})
			}
		} else if sh.Readable {
			sh.Severity = SeverityWarning
			result.Findings = append(result.Findings, Finding{
				Severity: SeverityWarning,
				Title:    fmt.Sprintf("Share '%s' is readable by %s", sh.Name, sh.Credential),
				Description: fmt.Sprintf(
					"The share \\\\%s\\%s grants read access to credential '%s'. "+
						"Verify that no sensitive data is exposed.",
					host, sh.Name, sh.Credential,
				),
			})
		}

		// Dangerous / admin share accessible
		if cfg.Features.CheckDangerousShares && dangerousShareNames[upper] {
			if sh.Readable || sh.Writable {
				result.Findings = append(result.Findings, Finding{
					Severity: SeverityCritical,
					Title:    fmt.Sprintf("Administrative share '%s' is accessible", sh.Name),
					Description: fmt.Sprintf(
						"Administrative share \\\\%s\\%s is reachable without privileged "+
							"credentials. This may indicate a misconfiguration or weak password.",
						host, sh.Name,
					),
				})
			}
		}
	}

	return result
}
