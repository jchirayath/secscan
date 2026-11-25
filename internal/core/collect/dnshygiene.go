package collect

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jchirayath/secscan/internal/core/finding"
)

// DNSHygiene runs the checks a mail/DNS diagnostic tool performs — forward and
// reverse resolution, SPF, DMARC, DNSSEC, MX sanity.
//
// These are public-record lookups, not probes: nothing is sent to the target,
// nothing is authenticated against, and the answers come from DNS. That makes
// them safe to run against anything, and they cover a category of real risk
// that host-local collectors cannot see at all — a domain with no DMARC policy
// is trivially spoofable no matter how well the server itself is hardened.
type DNSHygiene struct {
	// Resolver is injectable for tests.
	Resolver *net.Resolver
}

func (DNSHygiene) ID() string                 { return "dns-hygiene" }
func (DNSHygiene) Category() finding.Category { return finding.CatServices }

// dns builds a finding attributed to THIS collector. The shared svc() helper
// stamps Engine="services", which would misattribute every DNS finding in the
// coverage drill-down — the one place where "which check produced this?" is the
// entire question being asked.
func dns(a *finding.Asset, sev finding.Severity, rule, title, desc, remedy, cmd string,
	ev []finding.Evidence, sub string) finding.Finding {
	f := svc(a, sev, rule, title, desc, remedy, cmd, ev, sub)
	f.Engine = "dns-hygiene"
	return f
}

func (d DNSHygiene) resolver() *net.Resolver {
	if d.Resolver != nil {
		return d.Resolver
	}
	return net.DefaultResolver
}

// Check runs the lookups for a host name and its parent domain.
func (d DNSHygiene) Check(ctx context.Context, host string, a *finding.Asset) ([]finding.Finding, Note) {
	if host == "" || host == "localhost" {
		return nil, Skip(d.ID(), "no public host name for this target — DNS hygiene needs a resolvable name")
	}
	// A target addressed by IP has no name to check. Before this guard the
	// "parent domain" of 10.30.0.4 came out as "0.4", and the scan reported
	// missing SPF and DMARC records for a domain that cannot exist.
	if net.ParseIP(strings.Trim(host, "[]")) != nil {
		return nil, NotApplicable(d.ID(), "target is addressed by IP ("+host+") — DNS hygiene needs a host name; set the target's address to its FQDN to enable it")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	res := d.resolver()
	var out []finding.Finding

	// --- forward-confirmed reverse DNS -----------------------------------
	// Mail servers and many security tools reject or downgrade hosts whose
	// reverse record does not match forward. It is also a strong signal of
	// how carefully the estate is run.
	addrs, err := res.LookupHost(ctx, host)
	if err != nil || len(addrs) == 0 {
		return nil, Skip(d.ID(), "could not resolve "+host)
	}
	ip := addrs[0]
	names, rerr := res.LookupAddr(ctx, ip)
	switch {
	case rerr != nil || len(names) == 0:
		out = append(out, dns(a, finding.SevLow, "dns.no-ptr",
			"No reverse DNS (PTR) record for "+ip,
			"The address has no PTR record. Receiving mail servers commonly reject or "+
				"heavily penalise mail from hosts without reverse DNS, and its absence is a "+
				"reliable indicator that the address was never properly commissioned.",
			"Ask whoever controls the address block to add a PTR record matching the host name",
			"", []finding.Evidence{{Command: "PTR lookup for " + ip, Output: "no PTR record"}}, "dns"))
	default:
		matched := false
		for _, n := range names {
			if strings.EqualFold(strings.TrimSuffix(n, "."), host) {
				matched = true
			}
		}
		if !matched {
			out = append(out, dns(a, finding.SevInfo, "dns.ptr-mismatch",
				"Reverse DNS does not match the forward name",
				fmt.Sprintf("%s resolves to %s, but that address reverses to %s. Forward-confirmed "+
					"reverse DNS is expected by mail servers and by some security tooling. A "+
					"mismatch is common on cloud hosts and is only a problem if this host sends mail.",
					host, ip, strings.Join(names, ", ")),
				"Align the PTR record with the host name if this host sends mail",
				"", []finding.Evidence{{Command: "PTR lookup for " + ip,
					Output: fmt.Sprintf("forward: %s → %s\nreverse: %s", host, ip, strings.Join(names, ", "))}},
				"dns"))
		}
	}

	// --- mail-domain policy records --------------------------------------
	domain := parentDomain(host)
	mx, _ := res.LookupMX(ctx, domain)
	sendsMail := len(mx) > 0

	spf, hasSPF := lookupTXTPrefix(ctx, res, domain, "v=spf1")
	if !hasSPF {
		sev := finding.SevLow
		if sendsMail {
			sev = finding.SevMedium
		}
		out = append(out, dns(a, sev, "dns.no-spf",
			"No SPF record for "+domain,
			"Without an SPF record, any host on the internet can send mail claiming to be "+
				"from this domain and receiving servers have no published way to tell it is "+
				"forged. This is the cheapest phishing enabler there is.",
			"Publish an SPF record listing your legitimate senders, ending in -all",
			`# example: "v=spf1 include:_spf.google.com -all"`,
			[]finding.Evidence{{Command: "TXT lookup for " + domain, Output: "no v=spf1 record"}}, "mail"))
	} else if strings.Contains(spf, "+all") {
		out = append(out, dns(a, finding.SevHigh, "dns.spf-permits-all",
			"SPF record ends in +all — it authorises the entire internet",
			"'+all' tells receivers that any host may send mail for this domain, which is "+
				"strictly worse than having no SPF at all: it actively vouches for forgeries.",
			"Replace +all with -all (fail) or ~all (softfail)",
			"", []finding.Evidence{{Command: "TXT lookup for " + domain, Output: spf}}, "mail"))
	}

	dmarc, hasDMARC := lookupTXTPrefix(ctx, res, "_dmarc."+domain, "v=DMARC1")
	switch {
	case !hasDMARC:
		sev := finding.SevLow
		if sendsMail {
			sev = finding.SevMedium
		}
		out = append(out, dns(a, sev, "dns.no-dmarc",
			"No DMARC record for "+domain,
			"DMARC tells receiving servers what to do with mail that fails SPF and DKIM, and "+
				"gives you reporting on who is sending as your domain. Without it, spoofed mail "+
				"is delivered and you never find out.",
			"Publish a DMARC record, starting at p=none to observe, then move to quarantine or reject",
			`# _dmarc.`+domain+` TXT "v=DMARC1; p=none; rua=mailto:dmarc@`+domain+`"`,
			[]finding.Evidence{{Command: "TXT lookup for _dmarc." + domain, Output: "no DMARC record"}}, "mail"))
	case strings.Contains(strings.ToLower(dmarc), "p=none"):
		out = append(out, dns(a, finding.SevLow, "dns.dmarc-policy-none",
			"DMARC policy is p=none — nothing is enforced",
			"p=none is the observation mode. It generates reports but instructs receivers to "+
				"deliver failing mail anyway, so spoofed mail still reaches recipients. It is the "+
				"right place to start and the wrong place to stop.",
			"Once the reports look clean, move to p=quarantine and then p=reject",
			"", []finding.Evidence{{Command: "TXT lookup for _dmarc." + domain, Output: dmarc}}, "mail"))
	}

	// --- DNSSEC ----------------------------------------------------------
	// Absence of DS records means the delegation is unsigned, so responses can
	// be forged by anyone able to intercept or poison.
	if sendsMail {
		if _, err := res.LookupNS(ctx, domain); err == nil {
			// A full DNSSEC validation needs a validating resolver; reporting
			// this as informational avoids claiming more than we checked.
			out = append(out, dns(a, finding.SevInfo, "dns.dnssec-unverified",
				"DNSSEC status for "+domain+" was not verified",
				"Confirming a signed delegation needs a validating resolver, which this scan "+
					"does not assume it has. Recorded so the gap is visible rather than silently "+
					"skipped — an unsigned zone means responses can be forged by anyone who can "+
					"intercept or poison a lookup.",
				"Check DNSSEC separately (dig +dnssec DS "+domain+") and sign the zone if it is not",
				"dig +dnssec DS "+domain,
				[]finding.Evidence{{Command: "NS lookup for " + domain, Output: "delegation present; signature state not evaluated"}},
				"dns"))
		}
	}

	return out, Ran(d.ID(), 6)
}

// lookupTXTPrefix finds the first TXT record with the given prefix.
func lookupTXTPrefix(ctx context.Context, res *net.Resolver, name, prefix string) (string, bool) {
	txts, err := res.LookupTXT(ctx, name)
	if err != nil {
		return "", false
	}
	for _, t := range txts {
		if strings.HasPrefix(strings.TrimSpace(t), prefix) {
			return t, true
		}
	}
	return "", false
}

// parentDomain reduces a host name to its registrable-ish parent.
//
// This is the last two labels, which is right for example.com and wrong for
// example.co.uk. Getting it exactly right needs the public-suffix list, which
// is a large dependency for a marginal gain here — so the limitation is
// documented rather than hidden, and the finding names the domain it checked
// so a reader can see if it picked the wrong one.
func parentDomain(host string) string {
	host = strings.TrimSuffix(host, ".")
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}
