// Package pdsql implements a plugin that query powerdns database to resolve the coredns query
package pdsql

import (
	"net"
	"strconv"
	"strings"

	"github.com/voltagex-forks/coredns-pdsql/pdnsmodel"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
	"gorm.io/gorm"
)

const Name = "pdsql"

type PowerDNSGenericSQLBackend struct {
	*gorm.DB
	Debug bool
	Next  plugin.Handler
}

func (pdb PowerDNSGenericSQLBackend) Name() string { return Name }
func (pdb PowerDNSGenericSQLBackend) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	qname := strings.ToLower(state.QName())

	a := new(dns.Msg)
	a.SetReply(r)
	a.Compress = true
	a.Authoritative = true

	var records []*pdnsmodel.Record
	query := pdnsmodel.Record{Name: qname, Type: state.Type(), Disabled: false}
	if query.Name != "." {
		// remove last dot
		query.Name = query.Name[:len(query.Name)-1]
	}

	switch state.QType() {
	case dns.TypeANY:
		query.Type = ""
	}
	//	if err := pdb.Find(&redords, "domain_id = ? and ( ? = 'ANY' or type = ? ) and name ILIKE '%*%'", domain.ID, typ, typ).Error; err != nil {
	if err := pdb.Find(&records, " (type = 'ANY' or type = ? ) and name LIKE ?", query.Type, query.Name).Error; err != nil {
		//if err := pdb.Where(query).Find(&records).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			query.Type = "SOA"
			if pdb.Where(query).Find(&records).Error == nil {
				rr := new(dns.SOA)
				rr.Hdr = dns.RR_Header{Name: qname, Rrtype: dns.TypeSOA, Class: state.QClass()}
				if ParseSOA(rr, records[0].Content) {
					a.Extra = append(a.Extra, rr)
				}
			}
		} else {
			//return dns.RcodeServerFailure, err
			return dns.RcodeNameError, err
		}
	} else {
		if len(records) == 0 {
			records, err = pdb.SearchWildcard(qname, state.QType())
			if err != nil {
				//return dns.RcodeServerFailure, err
				return dns.RcodeNameError, err
			}
		}
		for _, v := range records {
			typ := dns.StringToType[v.Type]
			hdr := dns.RR_Header{Name: qname, Rrtype: typ, Class: state.QClass(), Ttl: v.Ttl}
			if !strings.HasSuffix(hdr.Name, ".") {
				hdr.Name += "."
			}
			rr := dns.TypeToRR[typ]()

			// todo support more type
			// this is enough for most query
			switch rr := rr.(type) {
			case *dns.SOA:
				rr.Hdr = hdr
				if !ParseSOA(rr, v.Content) {
					rr = nil
				}
			case *dns.A:
				rr.Hdr = hdr
				rr.A = net.ParseIP(v.Content)
			case *dns.AAAA:
				rr.Hdr = hdr
				rr.AAAA = net.ParseIP(v.Content)
			case *dns.TXT:
				rr.Hdr = hdr
				rr.Txt = []string{v.Content}
			case *dns.NS:
				rr.Hdr = hdr
				rr.Ns = v.Content
			case *dns.PTR:
				rr.Hdr = hdr
				// pdns don't need the dot but when we answer, we need it
				if strings.HasSuffix(v.Content, ".") {
					rr.Ptr = v.Content
				} else {
					rr.Ptr = v.Content + "."
				}
			default:
				// drop unsupported
			}

			if rr == nil {
				// invalid record
			} else {
				a.Answer = append(a.Answer, rr)
			}
		}
	}
	if len(a.Answer) == 0 {
		return plugin.NextOrFailure(pdb.Name(), pdb.Next, ctx, w, r)
	}

	return 0, w.WriteMsg(a)
}

func (pdb PowerDNSGenericSQLBackend) SearchWildcard(qname string, qtype uint16) (records []*pdnsmodel.Record, err error) {
	// find domain, then find matched sub domain
	name := qname
	qnameNoDot := qname[:len(qname)-1]
	typ := dns.TypeToString[qtype]
	name = qnameNoDot
NEXT_ZONE:
	if i := strings.IndexRune(name, '.'); i > 0 {
		name = name[i+1:]
	} else {
		return
	}
	var domain pdnsmodel.Domain

	if err := pdb.Limit(1).Find(&domain, "name LIKE ?", name).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			goto NEXT_ZONE
		}
		return nil, err
	}

	if err := pdb.Find(&records, "domain_id = ? and ( ? = 'ANY' or type = ? ) and name ILIKE '%*%'", domain.ID, typ, typ).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	// filter
	var matched []*pdnsmodel.Record
	for _, v := range records {
		if WildcardMatch(qnameNoDot, v.Name) {
			matched = append(matched, v)
		}
	}
	records = matched
	return
}

func ParseSOA(rr *dns.SOA, line string) bool {
	splites := strings.Split(line, " ")
	if len(splites) < 7 {
		return false
	}
	rr.Ns = splites[0]
	rr.Mbox = splites[1]
	if i, err := strconv.Atoi(splites[2]); err != nil {
		return false
	} else {
		rr.Serial = uint32(i)
	}
	if i, err := strconv.Atoi(splites[3]); err != nil {
		return false
	} else {
		rr.Refresh = uint32(i)
	}
	if i, err := strconv.Atoi(splites[4]); err != nil {
		return false
	} else {
		rr.Retry = uint32(i)
	}
	if i, err := strconv.Atoi(splites[5]); err != nil {
		return false
	} else {
		rr.Expire = uint32(i)
	}
	if i, err := strconv.Atoi(splites[6]); err != nil {
		return false
	} else {
		rr.Minttl = uint32(i)
	}
	return true
}

// Dummy wildcard match
func WildcardMatch(s1, s2 string) bool {
	if s1 == "." || s2 == "." {
		return true
	}

	l1 := dns.SplitDomainName(s1)
	l2 := dns.SplitDomainName(s2)

	if len(l1) != len(l2) {
		return false
	}

	for i := range l1 {
		if !equal(l1[i], l2[i]) {
			return false
		}
	}

	return true
}

func equal(a, b string) bool {
	if b == "*" || a == "*" {
		return true
	}
	// might be lifted into API function.
	la := len(a)
	lb := len(b)
	if la != lb {
		return false
	}

	for i := la - 1; i >= 0; i-- {
		ai := a[i]
		bi := b[i]
		if ai >= 'A' && ai <= 'Z' {
			ai |= 'a' - 'A'
		}
		if bi >= 'A' && bi <= 'Z' {
			bi |= 'a' - 'A'
		}
		if ai != bi {
			return false
		}
	}
	return true
}
