package v2

// EASettings is the Enterprise Assistant settings shape of
// /api/v2/admin/enterprise-assistant/settings. GET never fills Password or
// BindPassword; PasswordSet and BindPasswordSet say whether one is stored.
// On PUT an empty password keeps the stored one and the *Set flags are ignored.
type EASettings struct {
	Enabled              bool                   `json:"enabled"`
	URL                  string                 `json:"url"`
	Username             string                 `json:"username"`
	Password             string                 `json:"password"`
	PasswordSet          bool                   `json:"passwordSet"`
	DeviceNameType       string                 `json:"deviceNameType"`
	ActiveDirectory      EAActiveDirectory      `json:"activeDirectory"`
	CertificateAuthority EACertificateAuthority `json:"certificateAuthority"`
}

// EAActiveDirectory says how Console reaches Active Directory over LDAPS.
type EAActiveDirectory struct {
	Domain             string   `json:"domain"`
	Server             string   `json:"server"`
	BindUsername       string   `json:"bindUsername"`
	BindPassword       string   `json:"bindPassword"`
	BindPasswordSet    bool     `json:"bindPasswordSet"`
	ComputerOU         string   `json:"computerOU"`
	SecurityGroups     []string `json:"securityGroups"`
	InsecureSkipVerify bool     `json:"insecureSkipVerify"`
}

// EACertificateAuthority says how Console reaches the Microsoft CA and how it
// names the certificates it requests.
type EACertificateAuthority struct {
	Host       string   `json:"host"`
	Name       string   `json:"name"`
	Template   string   `json:"template"`
	CommonName string   `json:"commonName"`
	AltNames   []string `json:"altNames"`
}

// EATestResult is the answer of POST /admin/enterprise-assistant/test.
type EATestResult struct {
	ActiveDirectory      EACheck `json:"activeDirectory"`
	CertificateAuthority EACheck `json:"certificateAuthority"`
}

// EACheck is the outcome of one connectivity check.
type EACheck struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// EAAuthority is an enterprise CA published in Active Directory.
type EAAuthority struct {
	Name      string   `json:"name"`
	Host      string   `json:"host"`
	Templates []string `json:"templates"`
}

// EADeviceRequest is the body rpc-go posts to /ea/api/configure/*.
// Field names match the legacy .NET Enterprise Assistant exactly.
type EADeviceRequest struct {
	NodeID        string `json:"nodeid"`
	Domain        string `json:"domain"`
	ReqID         string `json:"reqid"`
	AuthProtocol  int    `json:"authProtocol"`
	OSName        string `json:"osname"`
	DevName       string `json:"devname"`
	Icon          int    `json:"icon"`
	Ver           string `json:"ver"`
	DERKey        string `json:"DERKey"`
	KeyInstanceID string `json:"keyInstanceId"`
	SignedCSR     string `json:"signedcsr"`
	Cert          string `json:"cert"`
	CertID        string `json:"certid"`
}

// EADeviceResponse echoes the request and adds the satellite envelope and the
// subaction-specific Response.
type EADeviceResponse struct {
	EADeviceRequest

	Action         string               `json:"action"`
	SatelliteFlags int                  `json:"satelliteFlags"`
	SubAction      string               `json:"subaction"`
	Response       EADeviceResponseBody `json:"response"`
}

// EADeviceResponseBody carries only the fields each subaction defines, hence
// omitempty everywhere. AuthProtocol is a pointer so 0 (EAP-TLS) is sent.
type EADeviceResponseBody struct {
	CSR           string `json:"csr,omitempty"`
	KeyInstanceID string `json:"keyInstanceId,omitempty"`
	AuthProtocol  *int   `json:"authProtocol,omitempty"`
	Certificate   string `json:"certificate,omitempty"`
	Domain        string `json:"domain,omitempty"`
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	RootCert      string `json:"rootcert,omitempty"`
	CertID        string `json:"certid,omitempty"`
}

// EARemoveResult is the answer of DELETE /ea/api/configure/:guid.
type EARemoveResult struct {
	Status  string `json:"status"`
	Removed bool   `json:"removed"`
}
