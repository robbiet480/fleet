// Command okta-device-posture-poc is a throwaway SAML IdP used to reverse-engineer
// Okta's Device Posture Provider (Early Access) integration.
//
// It captures and logs EVERYTHING Okta sends to the IdP (headers, query params,
// form bodies, and the decoded SAML AuthnRequest XML), and can reply with a signed
// SAML assertion containing device posture facts (IsManaged/IsCompliant) so the
// full round trip can be tested.
//
// Usage:
//
//	go run ./tools/okta-device-posture-poc
//	ngrok http 9999
//
// Then configure the Okta IdP with:
//   - IdP Issuer URI:        https://<ngrok-domain>/metadata
//   - IdP Single Sign-On URL: https://<ngrok-domain>/sso
//   - Signature certificate:  okta-poc-state/idp-cert.pem (printed on startup)
//
// See README.md in this directory for the full Okta setup walkthrough.
package main

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

const devicePostureAuthnContext = "urn:okta:saml:2.0:DevicePosture"

var (
	addr        = flag.String("addr", ":9999", "listen address")
	issuerFlag  = flag.String("issuer", "", "IdP issuer/entityID; defaults to https://<request-host>/metadata")
	managed     = flag.Bool("managed", true, "value for the IsManaged fact")
	compliant   = flag.Bool("compliant", true, "value for the IsCompliant fact")
	respond     = flag.Bool("respond", true, "send a SAML response back to Okta (false = capture only, return 200)")
	failAuthn   = flag.Bool("fail", false, "respond with an AuthnFailed/DEVICE_NOT_MANAGED error status instead of an assertion")
	deviceID    = flag.String("device-id", "fleet-poc-device-1", "value for the Device ID attribute. To test how Okta correlates posture to a device, try the device's UDID, serial, or Okta device id")
	osVersion   = flag.String("os-version", "15.5", "value for the Device OSVersion attribute")
	stateDir    = flag.String("state-dir", "okta-poc-state", "directory for the generated signing cert/key")
	capturesDir = flag.String("captures-dir", "okta-poc-captures", "directory where raw requests/responses are saved")
)

type idpServer struct {
	cert    *x509.Certificate
	certDER []byte
	key     *rsa.PrivateKey
}

func main() {
	flag.Parse()

	srv := &idpServer{}
	if err := srv.loadOrCreateKeyPair(); err != nil {
		log.Fatalf("generate signing keypair: %v", err)
	}
	if err := os.MkdirAll(*capturesDir, 0o755); err != nil {
		log.Fatalf("create captures dir: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.certDER})
	fmt.Printf(`
Okta Device Posture Provider POC IdP
====================================
Listening on %s

Upload this signature certificate to the Okta IdP config
(also saved at %s):

%s
Okta IdP settings (after starting ngrok, e.g. "ngrok http 9999"):
  IdP Usage:                Device posture provider
  IdP Issuer URI:           https://<ngrok-domain>/metadata
  IdP Single Sign-On URL:   https://<ngrok-domain>/sso
  Destination:              https://<ngrok-domain>/sso

Response mode: respond=%t fail=%t IsManaged=%t IsCompliant=%t
`, *addr, filepath.Join(*stateDir, "idp-cert.pem"), certPEM, *respond, *failAuthn, *managed, *compliant)

	mux := http.NewServeMux()
	mux.HandleFunc("/metadata", srv.handleMetadata)
	mux.HandleFunc("/sso", srv.handleSSO)
	mux.HandleFunc("/", srv.handleCatchAll)

	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(httpServer.ListenAndServe())
}

func (s *idpServer) loadOrCreateKeyPair() error {
	if err := os.MkdirAll(*stateDir, 0o755); err != nil {
		return err
	}
	certPath := filepath.Join(*stateDir, "idp-cert.pem")
	keyPath := filepath.Join(*stateDir, "idp-key.pem")

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		certBlock, _ := pem.Decode(certPEM)
		keyBlock, _ := pem.Decode(keyPEM)
		if certBlock == nil || keyBlock == nil {
			return fmt.Errorf("invalid PEM in %s or %s, delete them to regenerate", certPath, keyPath)
		}
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return err
		}
		key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return err
		}
		s.cert, s.certDER, s.key = cert, certBlock.Bytes, key
		log.Printf("loaded existing signing keypair from %s", *stateDir)
		return nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "Fleet Okta device posture POC IdP"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(2, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
		return err
	}
	s.cert, s.certDER, s.key = cert, der, key
	log.Printf("generated new signing keypair in %s", *stateDir)
	return nil
}

// baseURL derives the public base URL from the incoming request so that ngrok
// domains work without configuration.
func baseURL(r *http.Request) string {
	scheme := "https"
	// Only honor a forwarded scheme if it's one of the two valid values, so a
	// spoofed X-Forwarded-Proto header can't inject arbitrary text into URLs.
	if xfp := r.Header.Get("X-Forwarded-Proto"); xfp == "http" || xfp == "https" {
		scheme = xfp
	} else if strings.HasPrefix(r.Host, "localhost") || strings.HasPrefix(r.Host, "127.") {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

func (s *idpServer) issuer(r *http.Request) string {
	if *issuerFlag != "" {
		return *issuerFlag
	}
	return baseURL(r) + "/metadata"
}

func (s *idpServer) handleMetadata(w http.ResponseWriter, r *http.Request) {
	s.dumpRequest("metadata", w, r)
	certB64 := base64.StdEncoding.EncodeToString(s.certDER)

	// Build with etree rather than string interpolation so request-derived
	// values (entityID, SSO URLs) are XML-attribute-escaped.
	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	ed := doc.CreateElement("EntityDescriptor")
	ed.CreateAttr("xmlns", "urn:oasis:names:tc:SAML:2.0:metadata")
	ed.CreateAttr("entityID", s.issuer(r))
	idp := ed.CreateElement("IDPSSODescriptor")
	idp.CreateAttr("WantAuthnRequestsSigned", "false")
	idp.CreateAttr("protocolSupportEnumeration", "urn:oasis:names:tc:SAML:2.0:protocol")
	kd := idp.CreateElement("KeyDescriptor")
	kd.CreateAttr("use", "signing")
	ki := kd.CreateElement("KeyInfo")
	ki.CreateAttr("xmlns", "http://www.w3.org/2000/09/xmldsig#")
	ki.CreateElement("X509Data").CreateElement("X509Certificate").SetText(certB64)
	idp.CreateElement("NameIDFormat").SetText("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
	ssoURL := baseURL(r) + "/sso"
	for _, binding := range []string{
		"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
	} {
		sso := idp.CreateElement("SingleSignOnService")
		sso.CreateAttr("Binding", binding)
		sso.CreateAttr("Location", ssoURL)
	}
	doc.Indent(2)
	out, err := doc.WriteToBytes()
	if err != nil {
		log.Printf("!! failed to build metadata: %v", err)
		http.Error(w, "failed to build metadata", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write(out)
}

func (s *idpServer) handleCatchAll(w http.ResponseWriter, r *http.Request) {
	s.dumpRequest("catchall", w, r)
	http.NotFound(w, r)
}

func (s *idpServer) handleSSO(w http.ResponseWriter, r *http.Request) {
	dump := s.dumpRequest("sso", w, r)

	samlRequest := r.URL.Query().Get("SAMLRequest")
	binding := "redirect"
	if samlRequest == "" {
		samlRequest = r.PostFormValue("SAMLRequest")
		binding = "post"
	}
	relayState := r.URL.Query().Get("RelayState")
	if relayState == "" {
		relayState = r.PostFormValue("RelayState")
	}
	if samlRequest == "" {
		log.Printf("!! /sso hit with no SAMLRequest parameter")
		fmt.Fprintln(w, "no SAMLRequest parameter; see server log for the full request dump")
		return
	}

	reqXML, err := decodeSAMLRequest(samlRequest, binding)
	if err != nil {
		log.Printf("!! failed to decode SAMLRequest (%s binding): %v", binding, err)
		http.Error(w, "failed to decode SAMLRequest", http.StatusBadRequest)
		return
	}

	pretty := prettyXML(reqXML)
	log.Printf(">> decoded AuthnRequest (%s binding):\n%s", binding, pretty)
	saveCapture(dump.prefix+"-authnrequest.xml", []byte(pretty))

	authnReq, err := parseAuthnRequest(reqXML)
	if err != nil {
		log.Printf("!! failed to parse AuthnRequest: %v", err)
		http.Error(w, "failed to parse AuthnRequest", http.StatusBadRequest)
		return
	}
	log.Printf(">> parsed: ID=%s ACS=%s Issuer=%s NameID=%q RequestedAuthnContext=%q",
		authnReq.ID, authnReq.ACSURL, authnReq.Issuer, authnReq.NameID, authnReq.RequestedContext)

	if !*respond {
		fmt.Fprintln(w, "captured; --respond=false so not sending a SAML response")
		return
	}
	if authnReq.ACSURL == "" {
		log.Printf("!! AuthnRequest has no AssertionConsumerServiceURL; cannot respond")
		http.Error(w, "no ACS URL in request", http.StatusBadRequest)
		return
	}

	var responseXML []byte
	if *failAuthn {
		responseXML, err = s.buildErrorResponse(authnReq, s.issuer(r))
	} else {
		responseXML, err = s.buildPostureResponse(authnReq, s.issuer(r))
	}
	if err != nil {
		log.Printf("!! failed to build SAML response: %v", err)
		http.Error(w, "failed to build SAML response", http.StatusInternalServerError)
		return
	}

	log.Printf("<< sending SAML response to %s:\n%s", authnReq.ACSURL, prettyXML(responseXML))
	saveCapture(dump.prefix+"-response.xml", responseXML)

	form := template.Must(template.New("form").Parse(`<!DOCTYPE html><html><body onload="document.forms[0].submit()">
<form method="post" action="{{.ACS}}">
<input type="hidden" name="SAMLResponse" value="{{.Response}}"/>
{{if .RelayState}}<input type="hidden" name="RelayState" value="{{.RelayState}}"/>{{end}}
<noscript><input type="submit" value="Continue"/></noscript>
</form></body></html>`))
	w.Header().Set("Content-Type", "text/html")
	_ = form.Execute(w, map[string]string{
		"ACS":        authnReq.ACSURL,
		"Response":   base64.StdEncoding.EncodeToString(responseXML),
		"RelayState": relayState,
	})
}

type authnRequest struct {
	ID               string
	ACSURL           string
	Destination      string
	Issuer           string
	NameID           string
	RequestedContext string
	// Okta application context (sent when "Send Okta application context" is
	// enabled on the IdP). Okta REQUIRES these be echoed back in the response's
	// AttributeStatement, else it fails with "The AppContext response from the
	// Identity Provider is invalid".
	AppInstanceID string
	AppName       string
}

func decodeSAMLRequest(value, binding string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("base64 decode: %w", err)
		}
	}
	if binding == "post" {
		return decoded, nil
	}
	// Redirect binding deflates the XML before base64-encoding it. Some
	// implementations skip the deflate step, so fall back to the raw bytes.
	inflated, err := io.ReadAll(flate.NewReader(bytes.NewReader(decoded)))
	if err != nil || len(inflated) == 0 {
		return decoded, nil
	}
	return inflated, nil
}

func parseAuthnRequest(reqXML []byte) (*authnRequest, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(reqXML); err != nil {
		return nil, err
	}
	root := doc.Root()
	if root == nil {
		return nil, fmt.Errorf("empty document")
	}
	out := &authnRequest{
		ID:          root.SelectAttrValue("ID", ""),
		ACSURL:      root.SelectAttrValue("AssertionConsumerServiceURL", ""),
		Destination: root.SelectAttrValue("Destination", ""),
	}
	if el := findByLocalName(root, "Issuer"); el != nil {
		out.Issuer = strings.TrimSpace(el.Text())
	}
	if el := findByLocalName(root, "Subject"); el != nil {
		if nameID := findByLocalName(el, "NameID"); nameID != nil {
			out.NameID = strings.TrimSpace(nameID.Text())
		}
	}
	if el := findByLocalName(root, "AuthnContextClassRef"); el != nil {
		out.RequestedContext = strings.TrimSpace(el.Text())
	}
	if el := findByLocalName(root, "OktaAppInstanceId"); el != nil {
		out.AppInstanceID = strings.TrimSpace(el.Text())
	}
	if el := findByLocalName(root, "OktaAppName"); el != nil {
		out.AppName = strings.TrimSpace(el.Text())
	}
	return out, nil
}

// findByLocalName does a depth-first search for an element by local tag name,
// ignoring namespace prefixes (Okta uses saml2/saml2p, examples use saml/samlp).
func findByLocalName(el *etree.Element, tag string) *etree.Element {
	for _, child := range el.ChildElements() {
		if child.Tag == tag {
			return child
		}
		if found := findByLocalName(child, tag); found != nil {
			return found
		}
	}
	return nil
}

func randomID() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return "_" + hex.EncodeToString(b)
}

const timeFormat = "2006-01-02T15:04:05.000Z"

// buildPostureResponse builds a SAML response per Okta's device posture data
// contract: the assertion's AuthnStatement carries an AuthnContextDecl with an
// AuthenticationContextDeclaration/Extension/Device/Posture/Fact structure in
// the urn:okta:saml:2.0:DevicePosture namespace.
func (s *idpServer) buildPostureResponse(req *authnRequest, issuer string) ([]byte, error) {
	now := time.Now().UTC()
	notAfter := now.Add(5 * time.Minute)

	assertion := etree.NewElement("saml:Assertion")
	assertion.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	assertion.CreateAttr("ID", randomID())
	assertion.CreateAttr("IssueInstant", now.Format(timeFormat))
	assertion.CreateAttr("Version", "2.0")

	issuerEl := assertion.CreateElement("saml:Issuer")
	issuerEl.SetText(issuer)

	subject := assertion.CreateElement("saml:Subject")
	nameID := subject.CreateElement("saml:NameID")
	nameID.CreateAttr("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
	nameID.CreateAttr("NameQualifier", issuer)
	nameIDValue := req.NameID
	if nameIDValue == "" {
		nameIDValue = "unknown@example.com"
	}
	nameID.SetText(nameIDValue)
	subjConf := subject.CreateElement("saml:SubjectConfirmation")
	subjConf.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	subjConfData := subjConf.CreateElement("saml:SubjectConfirmationData")
	subjConfData.CreateAttr("InResponseTo", req.ID)
	subjConfData.CreateAttr("NotOnOrAfter", notAfter.Format(timeFormat))
	subjConfData.CreateAttr("Recipient", req.ACSURL)

	conditions := assertion.CreateElement("saml:Conditions")
	conditions.CreateAttr("NotBefore", now.Add(-30*time.Second).Format(timeFormat))
	conditions.CreateAttr("NotOnOrAfter", notAfter.Format(timeFormat))
	audienceRestriction := conditions.CreateElement("saml:AudienceRestriction")
	audience := audienceRestriction.CreateElement("saml:Audience")
	audience.SetText(req.Issuer)

	authnStatement := assertion.CreateElement("saml:AuthnStatement")
	authnStatement.CreateAttr("AuthnInstant", now.Format(timeFormat))
	authnStatement.CreateAttr("SessionIndex", randomID())
	authnContext := authnStatement.CreateElement("saml:AuthnContext")
	classRef := authnContext.CreateElement("saml:AuthnContextClassRef")
	classRef.SetText(devicePostureAuthnContext)

	decl := authnContext.CreateElement("saml:AuthnContextDecl")
	acd := decl.CreateElement("AuthenticationContextDeclaration")
	acd.CreateAttr("xmlns", devicePostureAuthnContext)
	acd.CreateElement("AuthnMethod")
	extension := acd.CreateElement("Extension")
	device := extension.CreateElement("Device")
	device.CreateAttr("ID", *deviceID)
	device.CreateAttr("Vendor", "Apple")
	device.CreateAttr("Model", "MacBookPro")
	device.CreateAttr("OS", "macOS")
	device.CreateAttr("OSVersion", *osVersion)
	posture := device.CreateElement("Posture")
	managedFact := posture.CreateElement("Fact")
	managedFact.CreateAttr("Name", "IsManaged")
	managedFact.CreateAttr("Value", fmt.Sprintf("%t", *managed))
	compliantFact := posture.CreateElement("Fact")
	compliantFact.CreateAttr("Name", "IsCompliant")
	compliantFact.CreateAttr("Value", fmt.Sprintf("%t", *compliant))

	// Echo Okta application context back. When "Send Okta application context"
	// is enabled, Okta sends OktaAppInstanceId/OktaAppName in the request and
	// requires them returned in the AttributeStatement, or it rejects the
	// response ("The AppContext response from the Identity Provider is invalid").
	if req.AppInstanceID != "" || req.AppName != "" {
		attrStmt := assertion.CreateElement("saml:AttributeStatement")
		for _, a := range []struct{ name, value string }{
			{"OktaAppInstanceId", req.AppInstanceID},
			{"OktaAppName", req.AppName},
		} {
			attr := attrStmt.CreateElement("saml:Attribute")
			attr.CreateAttr("Name", a.name)
			attr.CreateAttr("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified")
			val := attr.CreateElement("saml:AttributeValue")
			val.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
			val.CreateAttr("xmlns:xs", "http://www.w3.org/2001/XMLSchema")
			val.CreateAttr("xsi:type", "xs:string")
			val.SetText(a.value)
		}
	}

	signedAssertion, err := s.signElement(assertion)
	if err != nil {
		return nil, fmt.Errorf("sign assertion: %w", err)
	}

	response := s.newResponseElement(req, issuer, now)
	status := response.CreateElement("samlp:Status")
	statusCode := status.CreateElement("samlp:StatusCode")
	statusCode.CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")
	response.AddChild(signedAssertion)

	doc := etree.NewDocument()
	doc.SetRoot(response)
	return doc.WriteToBytes()
}

// buildErrorResponse builds the AuthnFailed/DEVICE_NOT_MANAGED error response
// from Okta's data contract, used when the device cannot be identified.
func (s *idpServer) buildErrorResponse(req *authnRequest, issuer string) ([]byte, error) {
	response := s.newResponseElement(req, issuer, time.Now().UTC())
	status := response.CreateElement("samlp:Status")
	statusCode := status.CreateElement("samlp:StatusCode")
	statusCode.CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Responder")
	inner := statusCode.CreateElement("samlp:StatusCode")
	inner.CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed")
	statusMessage := status.CreateElement("samlp:StatusMessage")
	statusMessage.SetText("DEVICE_NOT_MANAGED")

	doc := etree.NewDocument()
	doc.SetRoot(response)
	return doc.WriteToBytes()
}

func (s *idpServer) newResponseElement(req *authnRequest, issuer string, now time.Time) *etree.Element {
	response := etree.NewElement("samlp:Response")
	response.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	response.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	response.CreateAttr("ID", randomID())
	response.CreateAttr("InResponseTo", req.ID)
	response.CreateAttr("Version", "2.0")
	response.CreateAttr("IssueInstant", now.Format(timeFormat))
	response.CreateAttr("Destination", req.ACSURL)
	// Response-level Issuer. A SAML Response carries its own Issuer in addition
	// to the Assertion's; Okta validates THIS one against the IdP's configured
	// Issuer URI. It must be the first child (before Status) per the schema.
	response.CreateElement("saml:Issuer").SetText(issuer)
	return response
}

// signElement signs el with an enveloped XML signature and moves the Signature
// element directly after Issuer, as SAML requires. Moving the signature is safe
// because the enveloped-signature transform excludes it from the digest.
func (s *idpServer) signElement(el *etree.Element) (*etree.Element, error) {
	keyStore := dsig.TLSCertKeyStore(tls.Certificate{
		Certificate: [][]byte{s.certDER},
		PrivateKey:  s.key,
		Leaf:        s.cert,
	})
	signingCtx := dsig.NewDefaultSigningContext(keyStore)
	signingCtx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signingCtx.Hash = crypto.SHA256
	if err := signingCtx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		return nil, err
	}
	signed, err := signingCtx.SignEnveloped(el)
	if err != nil {
		return nil, err
	}
	// SignEnveloped appends the Signature as the last child; SAML schema wants
	// it right after Issuer. Remove by explicit index rather than RemoveChild:
	// goxmldsig appends via a raw slice append that never sets the signature's
	// parent pointer, so RemoveChild (which checks parent == el) silently
	// no-ops and InsertChildAt then duplicates the element. A duplicate
	// enveloped signature makes Okta reject the assertion ("Unable to validate
	// incoming SAML Assertion").
	sigToken := signed.RemoveChildAt(len(signed.Child) - 1)
	signed.InsertChildAt(1, sigToken.(*etree.Element))
	return signed, nil
}

type requestDump struct {
	prefix string
}

// dumpRequest logs the complete incoming request and saves it to the captures
// directory. This is the whole point of this tool: seeing exactly what Okta
// (via the user's browser) sends us.
func (s *idpServer) dumpRequest(label string, _ http.ResponseWriter, r *http.Request) requestDump {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s\n", r.Method, r.RequestURI, r.Proto)
	fmt.Fprintf(&b, "Host: %s\nRemoteAddr: %s\n", r.Host, r.RemoteAddr)

	keys := make([]string, 0, len(r.Header))
	for k := range r.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range r.Header[k] {
			fmt.Fprintf(&b, "%s: %s\n", k, v)
		}
	}

	if r.Method == http.MethodPost {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err == nil {
			fmt.Fprintf(&b, "\n%s\n", body)
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
	} else if r.URL.RawQuery != "" {
		fmt.Fprintf(&b, "\nQuery params:\n")
		for k, vs := range r.URL.Query() {
			for _, v := range vs {
				fmt.Fprintf(&b, "  %s = %s\n", k, v)
			}
		}
	}

	dump := b.String()
	log.Printf(">> [%s] incoming request:\n%s", label, dump)

	prefix := fmt.Sprintf("%s-%s", time.Now().UTC().Format("20060102T150405.000"), label)
	saveCapture(prefix+"-request.txt", []byte(dump))
	return requestDump{prefix: prefix}
}

func saveCapture(name string, data []byte) {
	path := filepath.Join(*capturesDir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		log.Printf("!! failed to save capture %s: %v", path, err)
	}
}

func prettyXML(raw []byte) string {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return string(raw)
	}
	doc.Indent(2)
	out, err := doc.WriteToString()
	if err != nil {
		return string(raw)
	}
	return out
}
