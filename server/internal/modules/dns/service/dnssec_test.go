package dns

import (
	"crypto"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type fixtureDNSSECChainFetcher struct {
	keys map[string][]*dns.DNSKEY
	sigs map[string][]*dns.RRSIG
	ds   map[string][]*dns.DS
	dsig map[string][]*dns.RRSIG
	deny map[string]dnssecDenialProof
}

func (f fixtureDNSSECChainFetcher) DNSKEY(zone string) ([]*dns.DNSKEY, []*dns.RRSIG, error) {
	keys, ok := f.keys[zone]
	if !ok {
		return nil, nil, fmt.Errorf("missing DNSKEY fixture for %s", zone)
	}
	return keys, f.sigs[zone], nil
}

func (f fixtureDNSSECChainFetcher) DS(zone string) ([]*dns.DS, []*dns.RRSIG, dnssecDenialProof, error) {
	return f.ds[zone], f.dsig[zone], f.deny[zone], nil
}

func TestBuildZoneChain(t *testing.T) {
	got := buildZoneChain("www.example.co.uk.")
	want := []string{".", "uk.", "co.uk.", "example.co.uk.", "www.example.co.uk."}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildZoneChain() = %#v, want %#v", got, want)
	}
}

func TestRootTrustAnchors(t *testing.T) {
	want := map[uint16]string{
		20326: "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
		38696: "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
	}
	for _, anchor := range rootTrustAnchors {
		if digest, ok := want[anchor.KeyTag]; !ok || anchor.Digest != digest {
			t.Fatalf("unexpected root trust anchor: keyTag=%d digest=%s", anchor.KeyTag, anchor.Digest)
		}
		delete(want, anchor.KeyTag)
	}
	if len(want) != 0 {
		t.Fatalf("missing root trust anchors: %#v", want)
	}
}

func TestValidateDNSSECChainWithFetcher(t *testing.T) {
	fetcher, anchors := newDNSSECChainFixture(t)

	records, info := validateDNSSECChainWithFetcher(fetcher, "example.com.", anchors)
	if info.Status != "SECURE" {
		t.Fatalf("validateDNSSECChainWithFetcher() status = %q, message = %q, want SECURE", info.Status, info.Message)
	}
	if len(records) == 0 {
		t.Fatal("validateDNSSECChainWithFetcher() returned no target records")
	}

	delete(fetcher.ds, "example.com.")
	delete(fetcher.dsig, "example.com.")
	_, info = validateDNSSECChainWithFetcher(fetcher, "example.com.", anchors)
	if info.Status != "INSECURE" {
		t.Fatalf("missing DS status = %q, message = %q, want INSECURE", info.Status, info.Message)
	}
}

func TestValidateDNSSECChainRejectsBogusDS(t *testing.T) {
	fetcher, anchors := newDNSSECChainFixture(t)
	fetcher.ds["example.com."][0].Digest = "00" + fetcher.ds["example.com."][0].Digest

	_, info := validateDNSSECChainWithFetcher(fetcher, "example.com.", anchors)
	if info.Status != "BOGUS" {
		t.Fatalf("bogus DS status = %q, message = %q, want BOGUS", info.Status, info.Message)
	}
}

func TestValidateDNSSECChainRejectsMissingDSWithoutAuthenticatedDenial(t *testing.T) {
	fetcher, anchors := newDNSSECChainFixture(t)
	delete(fetcher.ds, "example.com.")
	delete(fetcher.dsig, "example.com.")
	delete(fetcher.deny, "example.com.")

	_, info := validateDNSSECChainWithFetcher(fetcher, "example.com.", anchors)
	if info.Status != "BOGUS" {
		t.Fatalf("missing DS without proof status = %q, message = %q, want BOGUS", info.Status, info.Message)
	}
}

func TestHasMatchingDS(t *testing.T) {
	key := newTestDNSKEY(t)
	if _, err := key.Generate(1024); err != nil {
		t.Fatalf("DNSKEY.Generate() error = %v", err)
	}
	ds := key.ToDS(dns.SHA256)
	if ds == nil {
		t.Fatal("DNSKEY.ToDS() returned nil")
	}

	if !hasMatchingDS([]*dns.DNSKEY{key}, []*dns.DS{ds}) {
		t.Fatal("hasMatchingDS() = false for matching DS")
	}

	ds.Digest = "00" + ds.Digest
	if hasMatchingDS([]*dns.DNSKEY{key}, []*dns.DS{ds}) {
		t.Fatal("hasMatchingDS() = true for mismatched digest")
	}
}

func TestValidateDNSSECIntegration(t *testing.T) {
	if os.Getenv("RUN_DNS_INTEGRATION_TESTS") != "1" {
		t.Skip("bỏ qua integration test DNSSEC; đặt RUN_DNS_INTEGRATION_TESTS=1 để chạy")
	}

	endpoint := dnssecDoHEndpoint("cloudflare")
	zone, err := findAuthoritativeZone(endpoint, "cloudflare.com")
	if err != nil {
		t.Fatalf("findAuthoritativeZone(%q) error = %v", endpoint, err)
	}
	t.Logf("authoritative zone = %s", zone)

	info := ValidateDNSSEC("cloudflare", "cloudflare.com")
	if info.Status != "SECURE" {
		t.Fatalf("ValidateDNSSEC() status = %q, message = %q, want SECURE", info.Status, info.Message)
	}

	unsignedInfo := ValidateDNSSEC("cloudflare", "neverssl.com")
	if unsignedInfo.Status != "INSECURE" {
		t.Fatalf("ValidateDNSSEC() unsigned status = %q, message = %q, want INSECURE", unsignedInfo.Status, unsignedInfo.Message)
	}
}

func TestHasValidDNSKEYSignature(t *testing.T) {
	key := newTestDNSKEY(t)
	privateKey, err := key.Generate(1024)
	if err != nil {
		t.Fatalf("DNSKEY.Generate() error = %v", err)
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		t.Fatalf("DNSKEY.Generate() type = %T, want crypto.Signer", privateKey)
	}

	now := uint32(time.Now().Unix())
	signature := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   key.Hdr.Name,
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    key.Hdr.Ttl,
		},
		TypeCovered: dns.TypeDNSKEY,
		Algorithm:   key.Algorithm,
		Labels:      uint8(dns.CountLabel(key.Hdr.Name)),
		OrigTtl:     key.Hdr.Ttl,
		Expiration:  now + 3600,
		Inception:   now - 60,
		KeyTag:      key.KeyTag(),
		SignerName:  key.Hdr.Name,
	}
	if err := signature.Sign(signer, []dns.RR{key}); err != nil {
		t.Fatalf("RRSIG.Sign() error = %v", err)
	}

	if !hasValidDNSKEYSignature([]*dns.DNSKEY{key}, []*dns.RRSIG{signature}) {
		t.Fatal("hasValidDNSKEYSignature() = false for valid signature")
	}

	signature.Expiration = now - 1
	if hasValidDNSKEYSignature([]*dns.DNSKEY{key}, []*dns.RRSIG{signature}) {
		t.Fatal("hasValidDNSKEYSignature() = true for expired signature")
	}

	signature.Expiration = now + 3600
	signature.Signature = "invalid"
	if hasValidDNSKEYSignature([]*dns.DNSKEY{key}, []*dns.RRSIG{signature}) {
		t.Fatal("hasValidDNSKEYSignature() = true for invalid signature")
	}
}

func newTestDNSKEY(t *testing.T) *dns.DNSKEY {
	t.Helper()
	key := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
	}
	return key
}

func newDNSSECChainFixture(t *testing.T) (fixtureDNSSECChainFetcher, []*dns.DS) {
	t.Helper()
	rootKey, rootSigner := newSignedFixtureKey(t, ".")
	comKey, comSigner := newSignedFixtureKey(t, "com.")
	exampleKey, exampleSigner := newSignedFixtureKey(t, "example.com.")

	comDS := comKey.ToDS(dns.SHA256)
	exampleDS := exampleKey.ToDS(dns.SHA256)
	exampleDenial := &dns.NSEC{
		Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: "next.example.com.",
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG},
	}
	fetcher := fixtureDNSSECChainFetcher{
		keys: map[string][]*dns.DNSKEY{
			".":            {rootKey},
			"com.":         {comKey},
			"example.com.": {exampleKey},
		},
		sigs: map[string][]*dns.RRSIG{
			".":            {signRRSet(t, ".", dns.TypeDNSKEY, []dns.RR{rootKey}, rootKey, rootSigner)},
			"com.":         {signRRSet(t, "com.", dns.TypeDNSKEY, []dns.RR{comKey}, comKey, comSigner)},
			"example.com.": {signRRSet(t, "example.com.", dns.TypeDNSKEY, []dns.RR{exampleKey}, exampleKey, exampleSigner)},
		},
		ds: map[string][]*dns.DS{
			"com.":         {comDS},
			"example.com.": {exampleDS},
		},
		dsig: map[string][]*dns.RRSIG{
			"com.":         {signRRSet(t, "com.", dns.TypeDS, []dns.RR{comDS}, rootKey, rootSigner)},
			"example.com.": {signRRSet(t, "example.com.", dns.TypeDS, []dns.RR{exampleDS}, comKey, comSigner)},
		},
		deny: map[string]dnssecDenialProof{
			"example.com.": {
				nsecs:      []*dns.NSEC{exampleDenial},
				signatures: []*dns.RRSIG{signRRSet(t, "example.com.", dns.TypeNSEC, []dns.RR{exampleDenial}, comKey, comSigner)},
			},
		},
	}
	return fetcher, []*dns.DS{rootKey.ToDS(dns.SHA256)}
}

func newSignedFixtureKey(t *testing.T, zone string) (*dns.DNSKEY, crypto.Signer) {
	t.Helper()
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
	}
	privateKey, err := key.Generate(1024)
	if err != nil {
		t.Fatalf("DNSKEY.Generate() error = %v", err)
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		t.Fatalf("DNSKEY.Generate() type = %T, want crypto.Signer", privateKey)
	}
	return key, signer
}

func signRRSet(t *testing.T, zone string, coveredType uint16, rrset []dns.RR, key *dns.DNSKEY, signer crypto.Signer) *dns.RRSIG {
	t.Helper()
	now := uint32(time.Now().Unix())
	signature := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: zone, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		TypeCovered: coveredType,
		Algorithm:   key.Algorithm,
		Labels:      uint8(dns.CountLabel(zone)),
		OrigTtl:     300,
		Expiration:  now + 3600,
		Inception:   now - 60,
		KeyTag:      key.KeyTag(),
		SignerName:  key.Hdr.Name,
	}
	if err := signature.Sign(signer, rrset); err != nil {
		t.Fatalf("RRSIG.Sign() error = %v", err)
	}
	return signature
}
