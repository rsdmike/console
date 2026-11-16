package enterpriseassistant

import (
	"slices"
	"strings"

	"github.com/device-management-toolkit/console/config"
	dto "github.com/device-management-toolkit/console/internal/entity/dto/v2"
	"github.com/device-management-toolkit/console/pkg/ea/ad"
	"github.com/device-management-toolkit/console/pkg/ea/csr"
)

// Name kinds shared by ea.ca.commonName and ea.ca.altNames.
const (
	nameDistinguishedName = "distinguishedname"
	nameDNSFQDN           = "dnsfqdn"
	nameHostname          = "hostname"
	nameUPN               = "userprincipalname"
	nameSAMAccountName    = "samaccountname"
	nameUUID              = "uuid"

	deviceNameHostname = "hostname"
	deviceNameNodeID   = "nodeid"

	nodeIDNameLength = 12
)

var nameKinds = []string{nameDistinguishedName, nameDNSFQDN, nameHostname, nameUPN, nameSAMAccountName, nameUUID}

// amtServicePorts are the AMT ports whose HTTP/<fqdn>:<port> service
// principal names go into the CSR as UPN SANs.
var amtServicePorts = []string{"16992", "16993", "623", "664", "16994", "16995", "5900"}

// nodeIDName is the AMT GUID without dashes, first 12 characters.
func nodeIDName(nodeID string) string {
	id := strings.ReplaceAll(nodeID, "-", "")
	if len(id) > nodeIDNameLength {
		id = id[:nodeIDNameLength]
	}

	return id
}

// computerName picks the AD computer name per ea.deviceNameType.
func computerName(s *config.EA, req *dto.EADeviceRequest) string {
	if strings.EqualFold(s.DeviceNameType, deviceNameNodeID) || req.DevName == "" {
		return nodeIDName(req.NodeID)
	}

	return req.DevName
}

func computerDescription(req *dto.EADeviceRequest) string {
	if req.Ver != "" {
		return "Intel(R) AMT v" + req.Ver + " - " + req.NodeID
	}

	return "Intel(R) AMT device - " + req.NodeID
}

func computerRequest(s *config.EA, req *dto.EADeviceRequest) ad.ComputerRequest {
	return ad.ComputerRequest{
		Name:           computerName(s, req),
		Description:    computerDescription(req),
		OU:             s.AD.ComputerOU,
		SecurityGroups: slices.Clone(s.AD.SecurityGroups),
	}
}

func nameValue(kind string, c *ad.Computer) string {
	switch kind {
	case nameDistinguishedName:
		return c.DistinguishedName
	case nameDNSFQDN:
		return c.DNSFQDN
	case nameHostname:
		return c.HostName
	case nameUPN:
		return c.UserPrincipalName
	case nameSAMAccountName:
		return c.SAMAccountName
	case nameUUID:
		return c.GUID
	default:
		return ""
	}
}

// subjectDN mirrors the .NET EA: the computer DN for distinguishedname,
// otherwise CN=<value>. Unknown kinds fall back to dnsfqdn.
func subjectDN(commonName string, c *ad.Computer) string {
	kind := strings.ToLower(commonName)
	if kind == nameDistinguishedName {
		return c.DistinguishedName
	}

	value := nameValue(kind, c)
	if value == "" {
		value = c.DNSFQDN
	}

	return "CN=" + value
}

// altNames builds the SANs: every configured kind except the one used as the
// subject CN (as the .NET EA did), then the AMT service principal names.
func altNames(s *config.EA, c *ad.Computer) csr.Names {
	var names csr.Names

	commonName := strings.ToLower(s.CA.CommonName)

	for _, raw := range s.CA.AltNames {
		kind := strings.ToLower(raw)
		if kind == commonName {
			continue
		}

		value := nameValue(kind, c)
		if value == "" {
			continue
		}

		switch kind {
		case nameDistinguishedName:
			names.URI = append(names.URI, "LDAP://"+value)
		case nameUPN:
			names.UPN = append(names.UPN, value)
		default: // dnsfqdn, hostname, samaccountname, uuid
			names.DNS = append(names.DNS, value)
		}
	}

	if c.DNSFQDN != "" {
		for _, port := range amtServicePorts {
			names.UPN = append(names.UPN, "HTTP/"+c.DNSFQDN+":"+port)
		}
	}

	return names
}

func csrRequest(s *config.EA, c *ad.Computer, publicKey []byte) csr.Request {
	return csr.Request{
		SubjectDN: subjectDN(s.CA.CommonName, c),
		PublicKey: publicKey,
		Template:  s.CA.Template,
		Names:     altNames(s, c),
	}
}
