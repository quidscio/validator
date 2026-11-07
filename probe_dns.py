"""System-resolver DNS with explicit routing outcomes and bounded lifetimes."""
from __future__ import annotations

import secrets

import dns.exception
import dns.resolver

from probe_common import Deadline, DeadlineExceeded, domain_name


class DNSFailure(RuntimeError):
    pass


class DNSResolver:
    def __init__(self, deadline: Deadline, resolver=None):
        self.deadline = deadline
        self.resolver = resolver if resolver is not None else dns.resolver.Resolver()
        self.queries: list[dict] = []

    def _query(self, host: str, kind: str):
        import time
        entry = {"host": host, "type": kind, "started_seconds": time.monotonic() - self.deadline.started}
        self.queries.append(entry)
        try:
            answer = list(self.resolver.resolve(host, kind, lifetime=self.deadline.budget(), search=False))
            entry.update(status="answered", records=[str(item) for item in answer])
            return answer
        except dns.resolver.NoAnswer:
            entry["status"] = "no_data"
            return []
        except (dns.exception.DNSException, OSError, DeadlineExceeded) as exc:
            entry.update(status="error", error_type=type(exc).__name__, error=str(exc)[:4096])
            raise
        finally:
            entry["ended_seconds"] = time.monotonic() - self.deadline.started

    def resolve_mx(self, domain: str, max_mx: int) -> dict:
        result = {"status": "ready", "explanation": "MX routing resolved.", "records": [], "selected": [], "skipped": []}
        try:
            answer = self._query(domain, "MX")
        except dns.resolver.NXDOMAIN:
            result.update(status="domain_not_found", explanation="The target domain returned NXDOMAIN; no SMTP connection was attempted.")
            return result
        except (dns.exception.DNSException, OSError, DeadlineExceeded) as exc:
            result.update(status="inconclusive", explanation=f"MX lookup failed ({type(exc).__name__}): {str(exc)[:4096]}")
            return result
        records = [{"preference": int(r.preference), "exchange": str(r.exchange)} for r in answer]
        result["records"] = records
        nulls = [r for r in records if r["exchange"] == "."]
        if nulls:
            if len(records) == 1 and records[0]["preference"] == 0:
                result.update(status="domain_no_mail", explanation="The domain publishes a valid null MX and accepts no mail; no connection was attempted.")
            else:
                result.update(status="dns_configuration_error", explanation="Mixed or malformed null MX configuration; no connection was attempted.")
            return result
        if not records:
            result["selected"] = [{"host": domain, "preference": 0, "implicit": True}]
            result["explanation"] = "MX lookup returned no data; use the domain's A/AAAA records as implicit MX."
            return result
        distinct = {}
        try:
            for record in records:
                host = domain_name(record["exchange"], "MX exchange")
                pref = record["preference"]
                if not 0 <= pref <= 65535:
                    raise ValueError("Invalid MX preference")
                if host not in distinct or pref < distinct[host]["preference"]:
                    distinct[host] = {"host": host, "preference": pref, "implicit": False}
        except ValueError as exc:
            result.update(status="dns_configuration_error", explanation=str(exc))
            return result
        ordered = list(distinct.values())
        secrets.SystemRandom().shuffle(ordered)
        ordered.sort(key=lambda mx: mx["preference"])
        result["selected"] = ordered[:max_mx]
        result["skipped"] = [dict(mx, reason="max_mx") for mx in ordered[max_mx:]]
        return result

    def resolve_addresses(self, host: str) -> list[dict]:
        addresses = []
        errors = []
        # dnspython performs these lookups with a lifetime; socket.getaddrinfo
        # is deliberately not used because its platform resolver can block.
        for kind, family in (("A", "IPv4"), ("AAAA", "IPv6")):
            try:
                for record in self._query(host, kind):
                    entry = {"ip": record.address, "family": family}
                    if entry not in addresses:
                        addresses.append(entry)
            except dns.resolver.NXDOMAIN as exc:
                errors.append(f"{kind}: NXDOMAIN ({exc})")
                break
            except (dns.exception.DNSException, OSError) as exc:
                errors.append(f"{kind}: {type(exc).__name__}: {exc}")
        self.deadline.budget()
        if not addresses:
            raise DNSFailure(("; ".join(errors) or "No A or AAAA records for selected MX")[:4096])
        return addresses
