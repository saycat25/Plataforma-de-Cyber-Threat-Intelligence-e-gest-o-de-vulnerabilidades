import ipaddress
import re
from urllib.parse import urlparse

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")

def normalize_indicator(value: str, indicator_type: str) -> str:
    value = value.strip()
    if indicator_type in {"ipv4", "ipv6"}:
        address = ipaddress.ip_address(value)
        expected = 4 if indicator_type == "ipv4" else 6
        if address.version != expected:
            raise ValueError("Endereço IP não corresponde ao tipo informado")
        return address.compressed
    if indicator_type == "domain":
        value = value.rstrip(".").lower()
        if not DOMAIN_RE.fullmatch(value):
            raise ValueError("Domínio inválido")
        return value
    if indicator_type == "url":
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("URL deve usar HTTP ou HTTPS e possuir hostname")
        if parsed.username or parsed.password:
            raise ValueError("URLs com credenciais embutidas não são aceitas")
        return value
    lengths = {"md5": 32, "sha1": 40, "sha256": 64}
    if indicator_type in lengths:
        if len(value) != lengths[indicator_type] or not re.fullmatch(r"[A-Fa-f0-9]+", value):
            raise ValueError(f"Hash {indicator_type.upper()} inválido")
        return value.lower()
    raise ValueError("Tipo de indicador não suportado")
