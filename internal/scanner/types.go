package scanner

import "time"

// Severity classifies a finding.
type Severity int

const (
	SeverityInfo     Severity = iota // Informational – not necessarily bad
	SeverityWarning                  // Possible risk (e.g. SMBv1 enabled)
	SeverityCritical                 // High risk (writable share for everyone)
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityWarning:
		return "WARNING"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// SMBVersion represents the negotiated SMB dialect.
type SMBVersion int

const (
	SMBVersionUnknown SMBVersion = iota
	SMBVersion1
	SMBVersion2     // generic SMB2 (dialect not determined)
	SMBVersion2_02  // SMB 2.0.2
	SMBVersion2_1   // SMB 2.1
	SMBVersion3_0   // SMB 3.0
	SMBVersion3_02  // SMB 3.0.2
	SMBVersion3_11  // SMB 3.1.1
)

func (v SMBVersion) String() string {
	switch v {
	case SMBVersion1:
		return "SMBv1"
	case SMBVersion2:
		return "SMBv2 (dialect unknown)"
	case SMBVersion2_02:
		return "SMBv2.0.2"
	case SMBVersion2_1:
		return "SMBv2.1"
	case SMBVersion3_0:
		return "SMBv3.0"
	case SMBVersion3_02:
		return "SMBv3.0.2"
	case SMBVersion3_11:
		return "SMBv3.1.1"
	default:
		return "Unknown"
	}
}

// Severity returns the risk level of running this SMB version.
func (v SMBVersion) Severity() Severity {
	if v == SMBVersion1 {
		return SeverityWarning
	}
	return SeverityInfo
}

// ShareType categorises a share.
type ShareType int

const (
	ShareTypeDisk  ShareType = iota
	ShareTypePrint
	ShareTypeIPC
	ShareTypeSpecial // ADMIN$, C$, IPC$, etc.
)

func (t ShareType) String() string {
	switch t {
	case ShareTypeDisk:
		return "Disk"
	case ShareTypePrint:
		return "Print"
	case ShareTypeIPC:
		return "IPC"
	case ShareTypeSpecial:
		return "Special/Admin"
	default:
		return "Unknown"
	}
}

// Share holds information about a single discovered share.
type Share struct {
	Name        string
	Type        ShareType
	Comment     string
	Readable    bool
	Writable    bool
	Credential  string // which credential granted access, "" = none
	Severity    Severity
}

// Finding is a human-readable vulnerability note attached to a host.
type Finding struct {
	Severity    Severity
	Title       string
	Description string
}

// HostResult captures all scan data for a single host.
type HostResult struct {
	Host       string
	Reachable  bool
	SMBOpen    bool     // port 445 reachable
	SMBVersion SMBVersion
	OSInfo     string   // OS info from NTLMSSP, if available
	Shares     []Share
	Findings   []Finding
	ScanTime   time.Time
	Duration   time.Duration
	Error      string
}

// HasCritical returns true if any finding is critical severity.
func (r *HostResult) HasCritical() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityCritical {
			return true
		}
	}
	return false
}

// HasWarning returns true if any finding is warning or above.
func (r *HostResult) HasWarning() bool {
	for _, f := range r.Findings {
		if f.Severity >= SeverityWarning {
			return true
		}
	}
	return false
}

// ScanSummary aggregates results from a completed scan run.
type ScanSummary struct {
	StartTime     time.Time
	EndTime       time.Time
	TotalHosts    int
	ReachableHosts int
	SMBHosts      int
	CriticalCount int
	WarningCount  int
	Results       []*HostResult
}

func (s *ScanSummary) Duration() time.Duration {
	return s.EndTime.Sub(s.StartTime)
}
