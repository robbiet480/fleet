package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

func testServer(t *testing.T) *idpServer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &idpServer{cert: cert, certDER: der, key: key}
}

// countSignatures returns how many direct-child ds:Signature elements the
// assertion has, and the index of the first one (Issuer is expected at 0).
func countSignatures(assertion *etree.Element) (int, int) {
	count, firstIdx := 0, -1
	for i, child := range assertion.ChildElements() {
		if child.Tag == "Signature" {
			count++
			if firstIdx == -1 {
				firstIdx = i
			}
		}
	}
	return count, firstIdx
}

func TestSignElementSingleSignatureAfterIssuer(t *testing.T) {
	s := testServer(t)

	assertion := etree.NewElement("saml:Assertion")
	assertion.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	assertion.CreateAttr("ID", "_testid")
	assertion.CreateElement("saml:Issuer").SetText("https://idp.example/metadata")
	assertion.CreateElement("saml:Subject")
	assertion.CreateElement("saml:Conditions")
	assertion.CreateElement("saml:AuthnStatement")

	signed, err := s.signElement(assertion)
	if err != nil {
		t.Fatalf("signElement: %v", err)
	}

	count, firstIdx := countSignatures(signed)
	t.Logf("signature count=%d firstIndex=%d", count, firstIdx)
	if count != 1 {
		t.Fatalf("expected exactly 1 ds:Signature, got %d", count)
	}
	if firstIdx != 1 {
		t.Fatalf("expected ds:Signature at index 1 (right after Issuer), got %d", firstIdx)
	}

	// Verify the signature validates against our own cert via goxmldsig.
	certStore := dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{s.cert}}
	vctx := dsig.NewDefaultValidationContext(&certStore)
	// goxmldsig requires the signed element to be re-parsed standalone.
	doc := etree.NewDocument()
	doc.SetRoot(signed.Copy())
	buf, _ := doc.WriteToBytes()
	reparsed := etree.NewDocument()
	if err := reparsed.ReadFromBytes(buf); err != nil {
		t.Fatal(err)
	}
	if _, err := vctx.Validate(reparsed.Root()); err != nil {
		t.Fatalf("signature failed self-validation: %v", err)
	}
	t.Log("signature self-validates OK")
}

func TestPostureResponseHasResponseAndAssertionIssuer(t *testing.T) {
	s := testServer(t)
	req := &authnRequest{
		ID:     "id-okta-123",
		ACSURL: "https://login.example.com/sso/saml2/abc",
		Issuer: "https://www.okta.com/saml2/service-provider/xyz",
		NameID: "user@example.com",
	}
	const issuer = "https://idp.example/metadata"

	out, err := s.buildPostureResponse(req, issuer)
	if err != nil {
		t.Fatalf("buildPostureResponse: %v", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(out); err != nil {
		t.Fatal(err)
	}
	resp := doc.Root()

	// Okta validates the Response-level Issuer against the IdP's configured
	// Issuer URI; a missing one yields "Issuer did not match".
	respIssuer := resp.SelectElement("saml:Issuer")
	if respIssuer == nil || respIssuer.Text() != issuer {
		t.Fatalf("response-level Issuer missing or wrong: %v", respIssuer)
	}
	// It must precede Status per the SAML schema.
	if resp.ChildElements()[0].Tag != "Issuer" {
		t.Fatalf("response Issuer must be the first child, got %q", resp.ChildElements()[0].Tag)
	}
	// The assertion keeps its own Issuer too.
	assertion := resp.SelectElement("saml:Assertion")
	if assertion == nil {
		t.Fatal("no assertion in response")
	}
	if ai := assertion.SelectElement("saml:Issuer"); ai == nil || ai.Text() != issuer {
		t.Fatalf("assertion-level Issuer missing or wrong: %v", ai)
	}
}
