package windows

import (
	"errors"
)

const (
	syncMLNS            = "SYNCML:SYNCML1.2"
	syncMLMetaNS        = "syncml:metinf"
	syncMLMicrosoftNS   = "http://schemas.microsoft.com/MobileDevice/MDM"
	MaxSyncMLBytes      = 1 << 20
	MaxSyncMLDataBytes  = 256 << 10
	MaxSyncMLCommands   = 256
	MaxSyncMLItems      = 1024
	MaxSyncMLReferences = 1024
)

var ErrSyncML = errors.New("invalid or unsupported native Windows SyncML message")

// SyncMLMessage is a wire document, not an authenticated session. Use
// ParseSyncML and EncodeSyncML for transport. Ordinary serialization intentionally
// omits potentially sensitive payloads and credentials.
type SyncMLMessage struct {
	Header   SyncMLHeader    `json:"-" xml:"-"`
	Commands []SyncMLCommand `json:"-" xml:"-"`
	Final    bool            `json:"-" xml:"-"`
}

type SyncMLHeader struct {
	SessionID   string            `json:"-" xml:"-"`
	MessageID   string            `json:"-" xml:"-"`
	Target      SyncMLLocation    `json:"-" xml:"-"`
	Source      SyncMLLocation    `json:"-" xml:"-"`
	ResponseURI string            `json:"-" xml:"-"`
	Credential  *SyncMLCredential `json:"-" xml:"-"`
	Meta        *SyncMLMeta       `json:"-" xml:"-"`
}

type SyncMLLocation struct {
	URI  string `json:"-" xml:"-"`
	Name string `json:"-" xml:"-"`
}

type SyncMLCredential struct {
	Digest string `json:"-" xml:"-"`
}

type SyncMLMeta struct {
	Format         string   `json:"-" xml:"-"`
	Type           string   `json:"-" xml:"-"`
	Mark           string   `json:"-" xml:"-"`
	Version        string   `json:"-" xml:"-"`
	NextNonce      string   `json:"-" xml:"-"`
	Size           *uint64  `json:"-" xml:"-"`
	MaxMessageSize *uint64  `json:"-" xml:"-"`
	MaxObjectSize  *uint64  `json:"-" xml:"-"`
	EMI            []string `json:"-" xml:"-"`
}

// Text preserves decoded character data exactly, including whitespace. XML is
// optional self-contained markup instead of Text; its namespaces must not depend
// on the enclosing SyncML envelope. OriginalError is the MS-MDM error hint and
// never overrides a Status code or proves a successful operation.
type SyncMLData struct {
	Text          string `json:"-" xml:"-"`
	XML           string `json:"-" xml:"-"`
	OriginalError string `json:"-" xml:"-"`
}

type SyncMLItem struct {
	Target   *SyncMLLocation `json:"-" xml:"-"`
	Source   *SyncMLLocation `json:"-" xml:"-"`
	Meta     *SyncMLMeta     `json:"-" xml:"-"`
	Data     *SyncMLData     `json:"-" xml:"-"`
	MoreData bool            `json:"-" xml:"-"`
}

// Commands remain in wire order, including nested groups. References retain
// their wire strings: correlation against actually dispatched commands belongs to
// the session transaction. Parsing a device-originated mutation never executes it.
type SyncMLCommand struct {
	Kind        string          `json:"-" xml:"-"`
	ID          string          `json:"-" xml:"-"`
	MessageRef  string          `json:"-" xml:"-"`
	CommandRef  string          `json:"-" xml:"-"`
	CommandName string          `json:"-" xml:"-"`
	TargetRefs  []string        `json:"-" xml:"-"`
	SourceRefs  []string        `json:"-" xml:"-"`
	Meta        *SyncMLMeta     `json:"-" xml:"-"`
	Challenge   *SyncMLMeta     `json:"-" xml:"-"`
	Data        *SyncMLData     `json:"-" xml:"-"`
	Items       []SyncMLItem    `json:"-" xml:"-"`
	Commands    []SyncMLCommand `json:"-" xml:"-"`
}

func (SyncMLMessage) String() string        { return "[protected Windows SyncML message]" }
func (m SyncMLMessage) GoString() string    { return m.String() }
func (SyncMLHeader) String() string         { return "[protected Windows SyncML header]" }
func (m SyncMLHeader) GoString() string     { return m.String() }
func (SyncMLLocation) String() string       { return "[protected Windows SyncML location]" }
func (m SyncMLLocation) GoString() string   { return m.String() }
func (SyncMLCredential) String() string     { return "[protected Windows SyncML credential]" }
func (m SyncMLCredential) GoString() string { return m.String() }
func (SyncMLMeta) String() string           { return "[protected Windows SyncML metadata]" }
func (m SyncMLMeta) GoString() string       { return m.String() }
func (SyncMLData) String() string           { return "[protected Windows SyncML data]" }
func (m SyncMLData) GoString() string       { return m.String() }
func (SyncMLItem) String() string           { return "[protected Windows SyncML item]" }
func (m SyncMLItem) GoString() string       { return m.String() }
func (SyncMLCommand) String() string        { return "[protected Windows SyncML command]" }
func (m SyncMLCommand) GoString() string    { return m.String() }
