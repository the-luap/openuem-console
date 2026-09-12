package windows

import (
	"encoding/base64"
	"encoding/xml"
	"strings"
	"time"
	"unicode"
)

// ParseWSTEPRenewalRequest decodes the certificate-authenticated Renew form.
// It grants no authority: the HTTP boundary must bind the actual TLS leaf and
// the store must validate its current enrollment and CMS proof. Account-password
// and federated renewal require their own configured authentication flows.
func ParseWSTEPRenewalRequest(data []byte, expectedURL string) (*CertificateRenewalRequest, error) {
	message, err := parseWSTEPMessage(data, expectedURL)
	if err != nil {
		return nil, err
	}
	return parseWSTEPRenewal(message)
}

func parseWSTEPRenewal(message *soapMessage) (*CertificateRenewalRequest, error) {
	requestType, err := wstepRequestType(message)
	if err != nil || requestType != trustNS+"/Renew" {
		return nil, ErrWSTEP
	}
	body := message.Body
	if len(body.Children) < 3 || len(body.Children) > 4 {
		return nil, ErrWSTEP
	}
	typeElement, err := body.one(trustNS, "TokenType")
	if err != nil {
		return nil, ErrWSTEP
	}
	value, err := typeElement.plainText(256)
	if err != nil || value != deviceTokenType {
		return nil, ErrWSTEP
	}
	token, err := body.one(securityNS, "BinarySecurityToken")
	if err != nil || len(token.Children) != 0 || len(token.Attrs) != 2 {
		return nil, ErrWSTEP
	}
	for _, attr := range token.Attrs {
		if attr.Name.Space != "" {
			return nil, ErrWSTEP
		}
		switch attr.Name.Local {
		case "ValueType":
			if attr.Value != securityNS+"#PKCS7" {
				return nil, ErrWSTEP
			}
		case "EncodingType":
			if attr.Value != binaryEncodingType {
				return nil, ErrWSTEP
			}
		default:
			return nil, ErrWSTEP
		}
	}
	encoded := strings.Map(func(r rune) rune {
		if strings.ContainsRune(" \t\r\n", r) {
			return -1
		}
		return r
	}, token.Text)
	if len(encoded) == 0 || len(encoded) > base64.StdEncoding.EncodedLen(MaxWindowsRenewalProofBytes) {
		return nil, ErrRenewalProof
	}
	der, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(der) > MaxWindowsRenewalProofBytes || base64.StdEncoding.EncodeToString(der) != encoded {
		return nil, ErrRenewalProof
	}
	context, err := body.optional(contextNS, "AdditionalContext")
	if err != nil || (len(body.Children) == 4 && context == nil) {
		return nil, ErrWSTEP
	}
	if context != nil {
		items, err := parseWSTEPContext(context)
		if err != nil || validateEnrollmentContextShape(items, false) != nil {
			return nil, ErrWSTEP
		}
		// Optional device hints never select the identity, issuer or scope and
		// are not persisted or included in the request's protected result.
	}
	request := &CertificateRenewalRequest{MessageID: message.MessageID, CMSDER: der}
	if err := parseRenewalSecurity(message.Header, request); err != nil {
		return nil, err
	}
	return request, nil
}

func renewalSecurityID(element *xmlElement) (string, error) {
	if len(element.Attrs) != 1 || element.Attrs[0].Name != (xml.Name{Space: securityUtilityNS, Local: "Id"}) {
		return "", ErrWSTEP
	}
	id := element.Attrs[0].Value
	if len(id) == 0 || len(id) > 128 || !xmlNameStart.MatchString(id) || strings.Contains(id, ":") || strings.IndexFunc(id, unicode.IsSpace) >= 0 {
		return "", ErrWSTEP
	}
	if _, err := parseXML([]byte("<"+id+"/>"), 132); err != nil {
		return "", ErrWSTEP
	}
	return id, nil
}

func parseRenewalSecurity(header *xmlElement, request *CertificateRenewalRequest) error {
	security, err := header.optional(securityNS, "Security")
	if err != nil {
		return ErrWSTEP
	}
	if security == nil {
		return nil
	}
	if !security.container() || len(security.Children) > 2 {
		return ErrWSTEP
	}
	seen := map[xml.Name]bool{}
	ids := map[string]bool{}
	for _, child := range security.Children {
		if seen[child.Name] || !child.container() {
			return ErrWSTEP
		}
		seen[child.Name] = true
		id, err := renewalSecurityID(child)
		if err != nil || ids[id] {
			return ErrWSTEP
		}
		ids[id] = true
		switch child.Name {
		case xml.Name{Space: securityUtilityNS, Local: "Timestamp"}:
			if len(child.Children) != 2 {
				return ErrWSTEP
			}
			for name, target := range map[string]**time.Time{"Created": &request.CreatedAt, "Expires": &request.ExpiresAt} {
				element, err := child.one(securityUtilityNS, name)
				if err != nil {
					return ErrWSTEP
				}
				text, err := element.plainText(64)
				if err != nil || !strings.HasSuffix(text, "Z") {
					return ErrWSTEP
				}
				value, err := time.Parse(time.RFC3339Nano, text)
				if err != nil {
					return ErrWSTEP
				}
				*target = &value
			}
			if !request.ExpiresAt.After(*request.CreatedAt) || request.ExpiresAt.Sub(*request.CreatedAt) > 10*time.Minute {
				return ErrWSTEP
			}
		case xml.Name{Space: securityNS, Local: "UsernameToken"}:
			if len(child.Children) != 2 {
				return ErrWSTEP
			}
			username, err := child.one(securityNS, "Username")
			if err != nil {
				return ErrWSTEP
			}
			name, err := username.plainText(512)
			if err != nil || name == "" || strings.IndexFunc(name, unicode.IsControl) >= 0 {
				return ErrWSTEP
			}
			password, err := child.one(securityNS, "Password")
			if err != nil || len(password.Children) != 0 || len(password.Attrs) != 1 || password.Attrs[0].Name.Local != "Type" || (password.Attrs[0].Name.Space != "" && password.Attrs[0].Name.Space != securityNS) || password.Attrs[0].Value != passwordTextType || len(password.Text) > 1024 {
				return ErrWSTEP
			}
			// Microsoft's certificate-authenticated example retains an account
			// hint with an empty password. Never silently ignore a supplied secret.
			if !xmlWhitespace(password.Text) {
				return ErrCredential
			}
		default:
			return ErrWSTEP
		}
	}
	return nil
}
