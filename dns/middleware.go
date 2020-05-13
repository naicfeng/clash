package dns

import (
	"strings"

	"github.com/Dreamacro/clash/component/fakeip"
	"github.com/Dreamacro/clash/log"

	D "github.com/miekg/dns"
)

type Handler func(w D.ResponseWriter, r *D.Msg)
type middleware func(next Handler) Handler

func withFakeIP(fakePool *fakeip.Pool) middleware {
	return func(next Handler) Handler {
		return func(w D.ResponseWriter, r *D.Msg) {
			q := r.Question[0]

			if q.Qtype == D.TypeAAAA {
				msg := &D.Msg{}
				msg.Answer = []D.RR{}

				msg.SetRcode(r, D.RcodeSuccess)
				msg.Authoritative = true
				msg.RecursionAvailable = true

				w.WriteMsg(msg)
				return
			} else if q.Qtype != D.TypeA {
				next(w, r)
				return
			}

			host := strings.TrimRight(q.Name, ".")
			if fakePool.LookupHost(host) {
				next(w, r)
				return
			}

			rr := &D.A{}
			rr.Hdr = D.RR_Header{Name: q.Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: dnsDefaultTTL}
			ip := fakePool.Lookup(host)
			rr.A = ip
			msg := r.Copy()
			msg.Answer = []D.RR{rr}

			setMsgTTL(msg, 1)
			msg.SetRcode(r, D.RcodeSuccess)
			msg.Authoritative = true
			msg.RecursionAvailable = true

			w.WriteMsg(msg)
			return
		}
	}
}

func withResolver(resolver *Resolver) Handler {
	return func(w D.ResponseWriter, r *D.Msg) {
		msg, err := resolver.Exchange(r)
		if err != nil {
			q := r.Question[0]
			log.Debugln("[DNS Server] Exchange %s failed: %v", q.String(), err)
			D.HandleFailed(w, r)
			return
		}
		msg.SetRcode(r, msg.Rcode)
		msg.Authoritative = true
		w.WriteMsg(msg)
		return
	}
}

func compose(middlewares []middleware, endpoint Handler) Handler {
	length := len(middlewares)
	h := endpoint
	for i := length - 1; i >= 0; i-- {
		middleware := middlewares[i]
		h = middleware(h)
	}

	return h
}

func NewHandler(resolver *Resolver) Handler {
	middlewares := []middleware{}

	if resolver.FakeIPEnabled() {
		middlewares = append(middlewares, withFakeIP(resolver.pool))
	}

	return compose(middlewares, withResolver(resolver))
}
