package mock

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"sync"

	"github.com/miekg/dns"
)

// NewMockDNS creats a test DNS server with in-memory TXT record store
func NewMockDNS() *DNS {
	md := &DNS{txtRecords: map[string]string{}, stop: make(chan struct{})}

	port, _ := rand.Int(rand.Reader, big.NewInt(50000))
	port = port.Add(port, big.NewInt(15534))
	md.server = &dns.Server{
		Addr:    ":" + port.String(),
		Net:     "udp",
		Handler: dns.HandlerFunc(md.handleDNSRequest),
	}
	return md
}

// DNS is a test DNS server that stores TXT records in memory
// based on https://github.com/cert-manager/webhook-example/blob/0dcb6537405096ec6415b5e81daa6568323e9833/example/dns.go
type DNS struct {
	txtRecords map[string]string
	server     *dns.Server
	stop       chan struct{}
	sync.RWMutex
}

// Addr returns the address of the mock DNS server
func (d *DNS) Addr() string {
	return d.server.Addr
}

// Run initializes the mock DNS server
func (d *DNS) Run() {
	go func() {
		<-d.stop
		if err := d.server.Shutdown(); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		}
	}()
	go func() {
		if err := d.server.ListenAndServe(); err != nil {
			os.Exit(1)
		}
	}()
}

// Close stops the mock DNS server
func (d *DNS) Close() {
	close(d.stop)
}

// Present adds a TXT record to the mock DNS server
func (d *DNS) Present(fqdn, value string) {
	d.Lock()
	defer d.Unlock()

	d.txtRecords[fqdn] = value
}

// Cleanup removes a TXT record from the mock DNS server
func (d *DNS) Cleanup(fqdn string) {
	d.Lock()
	defer d.Unlock()

	delete(d.txtRecords, fqdn)
}

func (d *DNS) handleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(req)
	switch req.Opcode {
	case dns.OpcodeQuery:
		for _, q := range msg.Question {
			if err := d.addDNSAnswer(q, msg, req); err != nil {
				msg.SetRcode(req, dns.RcodeServerFailure)
				break
			}
		}
	}
	w.WriteMsg(msg)
}

func (d *DNS) addDNSAnswer(q dns.Question, msg *dns.Msg, req *dns.Msg) error {
	switch q.Qtype {
	// Always return loopback for any A query
	case dns.TypeA:
		rr, err := dns.NewRR(fmt.Sprintf("%s 5 IN A 127.0.0.1", q.Name))
		if err != nil {
			return err
		}
		msg.Answer = append(msg.Answer, rr)
		return nil

	// TXT records are the only important record for ACME dns-01 challenges
	case dns.TypeTXT:
		d.RLock()
		record, found := d.txtRecords[q.Name]
		d.RUnlock()
		if !found {
			msg.SetRcode(req, dns.RcodeNameError)
			return nil
		}
		rr, err := dns.NewRR(fmt.Sprintf("%s 5 IN TXT %s", q.Name, record))
		if err != nil {
			return err
		}
		msg.Answer = append(msg.Answer, rr)
		return nil

	// NS and SOA are for authoritative lookups, return obviously invalid data
	case dns.TypeNS:
		rr, err := dns.NewRR(fmt.Sprintf("%s 5 IN NS ns.example-acme-webook.invalid.", q.Name))
		if err != nil {
			return err
		}
		msg.Answer = append(msg.Answer, rr)
		return nil
	case dns.TypeSOA:
		rr, err := dns.NewRR(fmt.Sprintf("%s 5 IN SOA %s 20 5 5 5 5", "ns.example-acme-webook.invalid.", "ns.example-acme-webook.invalid."))
		if err != nil {
			return err
		}
		msg.Answer = append(msg.Answer, rr)
		return nil
	default:
		return fmt.Errorf("unimplemented record type %v", q.Qtype)
	}
}
