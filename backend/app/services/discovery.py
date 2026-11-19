import ipaddress
import re
from datetime import datetime, timezone

from app.models import AuthorizedScope

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")


def normalize_scope(scope_type: str, value: str) -> str:
    """Canonicalize an explicitly authorized scope; never performs network I/O."""
    cleaned = value.strip().lower().rstrip(".")
    if scope_type == "cidr":
        return str(ipaddress.ip_network(cleaned, strict=False))
    if scope_type == "domain":
        if not DOMAIN_RE.fullmatch(cleaned):
            raise ValueError("Domínio inválido para escopo autorizado")
        return cleaned
    if scope_type == "hostname":
        if not DOMAIN_RE.fullmatch(cleaned) and not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", cleaned):
            raise ValueError("Hostname inválido para escopo autorizado")
        return cleaned
    raise ValueError("Tipo de escopo não suportado")


def scope_is_current(scope: AuthorizedScope, now: datetime | None = None) -> bool:
    if not scope.is_active:
        return False
    current = now or datetime.now(timezone.utc)
    expiry = scope.valid_until
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return expiry > current


def record_matches_scope(scope: AuthorizedScope, hostname: str | None, ip_address: str | None) -> bool:
    """Check imported inventory data against a previously approved CIDR or DNS scope."""
    if scope.scope_type == "cidr" and ip_address:
        try:
            return ipaddress.ip_address(ip_address) in ipaddress.ip_network(scope.value, strict=False)
        except ValueError:
            return False
    if scope.scope_type == "hostname" and hostname:
        return hostname.strip().lower().rstrip(".") == scope.value
    if scope.scope_type == "domain" and hostname:
        candidate = hostname.strip().lower().rstrip(".")
        return candidate == scope.value or candidate.endswith("." + scope.value)
    return False
