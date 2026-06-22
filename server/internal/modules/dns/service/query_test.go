package dns

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"tools.bctechvibe.com/server/internal/modules/dns/models"
)

func TestQueryDNSUDP_SRV(t *testing.T) {
	// Setup a mock DNS server
	addr := "127.0.0.1:0" // Random port
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("Failed to listen on UDP: %v", err)
	}
	defer pc.Close()
	serverPort := pc.LocalAddr().String()

	go func() {
		for {
			buf := make([]byte, 512)
			n, remoteAddr, err := pc.ReadFrom(buf)
			if err != nil {
				return // Closed
			}

			msg := new(dns.Msg)
			if err := msg.Unpack(buf[:n]); err != nil {
				continue
			}

			reply := new(dns.Msg)
			reply.SetReply(msg)

			// Add SRV record to answer
			srvRecord := new(dns.SRV)
			srvRecord.Hdr = dns.RR_Header{Name: "_sip._tcp.example.com.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 300}
			srvRecord.Priority = 10
			srvRecord.Weight = 5
			srvRecord.Port = 5060
			srvRecord.Target = "sip.example.com."
			reply.Answer = append(reply.Answer, srvRecord)

			replyBytes, _ := reply.Pack()
			pc.WriteTo(replyBytes, remoteAddr)
		}
	}()

	// Give the server a moment to start
	time.Sleep(100 * time.Millisecond)

	records := QueryDNSUDP(serverPort, "_sip._tcp.example.com.", dns.TypeSRV)
	if len(records) != 1 {
		t.Fatalf("Expected 1 record, got %d", len(records))
	}

	record, ok := records[0].(models.DNSRecord)
	if !ok {
		t.Fatalf("Expected models.DNSRecord, got %T", records[0])
	}

	if record.Type != "SRV" {
		t.Errorf("Expected Type SRV, got %s", record.Type)
	}
	if record.Target != "sip.example.com" {
		t.Errorf("Expected Target sip.example.com, got %s", record.Target)
	}
	if record.Priority != 10 {
		t.Errorf("Expected Priority 10, got %d", record.Priority)
	}
	if record.Weight != 5 {
		t.Errorf("Expected Weight 5, got %d", record.Weight)
	}
	if record.Port != 5060 {
		t.Errorf("Expected Port 5060, got %d", record.Port)
	}
	if record.TTL != 300 {
		t.Errorf("Expected TTL 300, got %d", record.TTL)
	}
}
