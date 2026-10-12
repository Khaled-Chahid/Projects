"""An authoritative SOA check followed by a bounded, unsigned AXFR request."""

from contextlib import closing

from core import Finding, clean


def result(ctx, status, evidence):
    return Finding("DNS-001", "dns", ctx.port, "Unsigned DNS zone transfer accepted", status,
                   "info" if ctx.allow_axfr else "medium", evidence,
                   "The tested source can obtain zone records, potentially revealing infrastructure names and addresses.",
                   "Restrict zone transfers to intended secondary servers and use TSIG where appropriate.",
                   "Only the supplied zone and this scanner's source are tested. Source-IP authorization may be intentional. "
                   "No subdomains or additional targets are followed; capped or incomplete transfers are inconclusive.")


def run(ctx):
    if not ctx.domain:
        return [result(ctx, "skipped", {"reason": "AXFR needs a known zone. Supply --domain."})]
    try:
        import dns.exception
        import dns.flags
        import dns.message
        import dns.name
        import dns.query
        import dns.rcode
        import dns.rdatatype
        import dns.xfr
    except ImportError:
        return [result(ctx, "inconclusive", {"reason": "dnspython is missing; run setup.sh."})]
    evidence = {"zone": ctx.domain, "transport": "tcp", "signed": False}
    try:
        name = dns.name.from_text(ctx.domain)
        question = dns.message.make_query(name, "SOA")
        answer = dns.query.tcp(question, ctx.target, port=ctx.port, timeout=ctx.timeout)
        authoritative = bool(answer.flags & dns.flags.AA) and answer.rcode() == dns.rcode.NOERROR and any(
            rr.name == name and rr.rdtype == dns.rdatatype.SOA for rr in answer.answer)
        evidence["soa_rcode"] = dns.rcode.to_text(answer.rcode())
        evidence["authoritative_soa"] = authoritative
        if not authoritative:
            return [result(ctx, "inconclusive", {**evidence, "reason": "Authoritative SOA for this zone was not established."})]
        count, total_bytes, sample = 0, 0, []
        # The streaming API keeps a hard record/byte cap without building a zone in memory.
        # It also validates the opening/closing SOA. Pinned dnspython retains this API.
        with closing(dns.query.xfr(ctx.target, name, port=ctx.port, timeout=ctx.timeout,
                                   lifetime=min(ctx.tool_timeout, 4 * ctx.timeout), relativize=False)) as transfer:
            for message in transfer:
                for rrset in message.answer:
                    count += len(rrset)
                    total_bytes += len(rrset.to_text().encode("utf-8"))
                    if count > 10000 or total_bytes > 2_097_152:
                        return [result(ctx, "inconclusive", {**evidence, "reason": "AXFR size limit reached; transfer not confirmed complete.",
                                                           "records_observed": count})]
                    if len(sample) < 5:
                        sample.append({"name": clean(rrset.name, 255), "type": dns.rdatatype.to_text(rrset.rdtype),
                                       "count": len(rrset)})
        if count < 2:
            return [result(ctx, "inconclusive", {**evidence, "reason": "No complete AXFR evidence."})]
        return [result(ctx, "detected", {**evidence, "records_received_including_closing_soa": count,
                                        "sample": sample, "completed": True})]
    except dns.xfr.TransferError as exc:
        status = "not_detected" if exc.rcode == dns.rcode.REFUSED else "inconclusive"
        return [result(ctx, status, {**evidence, "axfr_rcode": dns.rcode.to_text(exc.rcode), "reason": clean(exc)})]
    except (dns.exception.DNSException, OSError, ValueError, EOFError) as exc:
        return [result(ctx, "inconclusive", {**evidence, "reason": clean(exc)})]
