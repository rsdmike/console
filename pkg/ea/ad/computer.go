package ad

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"

	"github.com/go-ldap/ldap/v3"
)

// workstationTrustAccountDontExpirePassword is userAccountControl
// WORKSTATION_TRUST_ACCOUNT (0x1000) | DONT_EXPIRE_PASSWORD (0x10000).
const workstationTrustAccountDontExpirePassword = "69632"

const (
	passwordLength      = 20
	passwordRandomBytes = 20
	maxPasswordAttempts = 1000
	guidLength          = 16
)

// EnsureComputer creates the computer object or finds the existing one,
// deletes same-named objects elsewhere in the domain, sets a new random
// password, reads objectGUID and joins the security groups.
func (c *Client) EnsureComputer(ctx context.Context, req ComputerRequest) (Computer, error) {
	if err := ctx.Err(); err != nil {
		return Computer{}, fmt.Errorf("ad.EnsureComputer: %w", err)
	}

	if req.Name == "" {
		return Computer{}, ErrNoName
	}

	password, err := generatePassword(rand.Reader)
	if err != nil {
		return Computer{}, fmt.Errorf("ad.EnsureComputer: %w", err)
	}

	computer := c.computerNames(req.Name, req.OU)
	computer.Password = password

	if err := c.deleteStrays(computer); err != nil {
		return Computer{}, fmt.Errorf("ad.EnsureComputer: %w", err)
	}

	present, err := c.exists(computer.DistinguishedName)
	if err != nil {
		return Computer{}, fmt.Errorf("ad.EnsureComputer: %w", err)
	}

	computer.AlreadyPresent = present

	if !present {
		if err := c.conn.Add(newComputerRequest(computer, req.Description)); err != nil {
			return Computer{}, fmt.Errorf("ad.EnsureComputer: add %s: %w", computer.DistinguishedName, err)
		}
	}

	if err := ctx.Err(); err != nil {
		return Computer{}, fmt.Errorf("ad.EnsureComputer: %w", err)
	}

	modify := ldap.NewModifyRequest(computer.DistinguishedName, nil)
	modify.Replace("unicodePwd", []string{unicodePwd(password)})

	if err := c.conn.Modify(modify); err != nil {
		return Computer{}, fmt.Errorf("ad.EnsureComputer: set password: %w", err)
	}

	computer.GUID, err = c.objectGUID(computer.DistinguishedName)
	if err != nil {
		return Computer{}, fmt.Errorf("ad.EnsureComputer: %w", err)
	}

	if err := c.joinGroups(computer.DistinguishedName, req.SecurityGroups); err != nil {
		return Computer{}, fmt.Errorf("ad.EnsureComputer: %w", err)
	}

	return computer, nil
}

// computerNames derives the object's names as the .NET EA did.
func (c *Client) computerNames(name, ou string) Computer {
	host := "iME-" + name

	return Computer{
		HostName:          host,
		SAMAccountName:    "iME$" + name + "$",
		DNSFQDN:           host + "." + c.domain,
		UserPrincipalName: host + "@" + c.domain,
		DistinguishedName: c.computerDN(name, ou),
	}
}

func (c *Client) computerDN(name, ou string) string {
	if ou == "" {
		ou = defaultOU
	}

	return "CN=" + escapeDNValue("iME-"+name) + "," + ou + "," + c.baseDN
}

// deleteStrays tree-deletes computers with the same UPN at another DN.
func (c *Client) deleteStrays(computer Computer) error {
	filter := "(&(objectCategory=computer)(userPrincipalName=" + ldap.EscapeFilter(computer.UserPrincipalName) + "))"

	res, err := c.conn.Search(ldap.NewSearchRequest(c.baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter, []string{attrDN}, nil))
	if err != nil {
		return fmt.Errorf("search %s: %w", computer.UserPrincipalName, err)
	}

	for _, e := range res.Entries {
		if sameDN(e.DN, computer.DistinguishedName) {
			continue
		}

		if err := c.treeDelete(e.DN); err != nil {
			return fmt.Errorf("delete stray %s: %w", e.DN, err)
		}
	}

	return nil
}

func newComputerRequest(computer Computer, description string) *ldap.AddRequest {
	add := ldap.NewAddRequest(computer.DistinguishedName, nil)
	add.Attribute("objectClass", []string{"computer"})
	add.Attribute("sAMAccountName", []string{computer.SAMAccountName})
	add.Attribute("userAccountControl", []string{workstationTrustAccountDontExpirePassword})
	add.Attribute("dNSHostName", []string{computer.DNSFQDN})
	add.Attribute("userPrincipalName", []string{computer.UserPrincipalName})

	if description != "" {
		add.Attribute("description", []string{description})
	}

	return add
}

func (c *Client) objectGUID(dn string) (string, error) {
	res, err := c.conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"objectGUID"}, nil))
	if err != nil {
		return "", fmt.Errorf("read objectGUID: %w", err)
	}

	if len(res.Entries) == 0 {
		return "", fmt.Errorf("read objectGUID: %w", ErrBadGUID)
	}

	return formatGUID(res.Entries[0].GetRawAttributeValue("objectGUID"))
}

// joinGroups adds dn to each existing group; missing groups are skipped and
// existing membership is success.
func (c *Client) joinGroups(dn string, groups []string) error {
	for _, group := range groups {
		if group == "" {
			continue
		}

		exists, err := c.exists(group)
		if err != nil {
			return fmt.Errorf("look up group %s: %w", group, err)
		}

		if !exists {
			continue
		}

		modify := ldap.NewModifyRequest(group, nil)
		modify.Add("member", []string{dn})

		err = c.conn.Modify(modify)
		if err != nil && !ldap.IsErrorAnyOf(err, ldap.LDAPResultEntryAlreadyExists, ldap.LDAPResultAttributeOrValueExists) {
			return fmt.Errorf("join group %s: %w", group, err)
		}
	}

	return nil
}

// sameDN compares DNs case-insensitively, tolerating formatting differences.
func sameDN(a, b string) bool {
	if strings.EqualFold(a, b) {
		return true
	}

	pa, errA := ldap.ParseDN(a)
	pb, errB := ldap.ParseDN(b)

	if errA != nil || errB != nil {
		return false
	}

	return pa.EqualFold(pb)
}

// escapeDNValue escapes an attribute value for use in a DN (RFC 4514).
func escapeDNValue(s string) string {
	var b strings.Builder

	for i := 0; i < len(s); i++ {
		ch := s[i]

		switch {
		case strings.IndexByte(`,+"\<>;=`, ch) >= 0,
			i == 0 && (ch == ' ' || ch == '#'),
			i == len(s)-1 && ch == ' ':
			b.WriteByte('\\')
			b.WriteByte(ch)
		default:
			b.WriteByte(ch)
		}
	}

	return b.String()
}

// unicodePwd encodes a password for the unicodePwd attribute: the quoted
// password in UTF-16LE.
func unicodePwd(password string) string {
	units := utf16.Encode([]rune(`"` + password + `"`))
	out := make([]byte, 0, len(units)*2) //nolint:mnd // two bytes per UTF-16 unit

	for _, u := range units {
		out = append(out, byte(u&0xff), byte(u>>8)) //nolint:mnd // little-endian bytes
	}

	return string(out)
}

// formatGUID formats objectGUID bytes like .NET Guid.ToString(): the first
// three groups are little-endian.
func formatGUID(b []byte) (string, error) {
	if len(b) != guidLength {
		return "", fmt.Errorf("%w: got %d", ErrBadGUID, len(b))
	}

	order := []byte{3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15}
	swapped := make([]byte, guidLength)

	for i, j := range order {
		swapped[i] = b[j]
	}

	h := hex.EncodeToString(swapped)

	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}

// generatePassword returns a random 20-character password that Intel AMT
// accepts: at least one digit, lowercase, uppercase and one of '+' '/'.
func generatePassword(r io.Reader) (string, error) {
	buf := make([]byte, passwordRandomBytes)

	for range maxPasswordAttempts {
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", fmt.Errorf("generate password: %w", err)
		}

		candidate := base64.StdEncoding.EncodeToString(buf)[:passwordLength]
		if amtPasswordOK(candidate) {
			return candidate, nil
		}
	}

	return "", ErrPasswordGeneration
}

func amtPasswordOK(s string) bool {
	if len(s) != passwordLength {
		return false
	}

	var digit, lower, upper, symbol bool

	for i := 0; i < len(s); i++ {
		c := s[i]

		switch {
		case c >= '0' && c <= '9':
			digit = true
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= 'A' && c <= 'Z':
			upper = true
		case c == '+' || c == '/':
			symbol = true
		}
	}

	return digit && lower && upper && symbol
}
