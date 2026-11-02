"""Extraction d'indicateurs (IOC) dans un texte d'article."""
import ipaddress
import re

_BLOCKED = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4")]
URL_RE = re.compile(r"\bhttps?://[^\s'\"<>]+", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+([a-z]{2,})\b", re.I)
HASH_RES = (("sha256", re.compile(r"\b[a-f0-9]{64}\b", re.I)),
            ("sha1", re.compile(r"\b[a-f0-9]{40}\b", re.I)),
            ("md5", re.compile(r"\b[a-f0-9]{32}\b", re.I)))
# extensions de fichiers qui ressemblent à des domaines (heuristique)
FILE_EXT = set("""exe dll zip js json php html htm txt pdf doc docx xls xlsx ps1 bat py
png jpg jpeg gif css xml lnk iso msi jar bin tmp dat log cfg ini rar gz tar sys vbs hta
asp aspx jsp md csv svg ico tif bmp dmp so sh""".split())


def refang(text: str) -> str:
    """hxxp://evil[.]com -> http://evil.com"""
    text = re.sub(r"hxxp", "http", text, flags=re.I)
    text = re.sub(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\[dot\]|\(dot\)", ".", text, flags=re.I)
    return text.replace("[://]", "://").replace("[:]", ":")


def _blocked_ip(ip) -> bool:
    return any(ip in n for n in _BLOCKED)


def extract_iocs(text: str, ignore_domains=()) -> list[tuple[str, str]]:
    """Liste ordonnée, sans doublon, de (type, valeur) : url, ip, sha256/sha1/md5, domain."""
    text = refang(text)
    ignore = {d.lower() for d in ignore_domains}
    out: list[tuple[str, str]] = []
    seen = set()

    def add(kind, value):
        if (kind, value) not in seen:
            seen.add((kind, value))
            out.append((kind, value))

    for m in URL_RE.finditer(text):
        add("url", m.group().rstrip(".,;:)]}"))
    rest = URL_RE.sub(" ", text)                       # domaines/IP déjà couverts par l'URL
    for kind, rx in HASH_RES:
        for m in rx.finditer(rest):
            v = m.group().lower()
            if re.search("[a-f]", v) and re.search("[0-9]", v):
                add(kind, v)
    for m in IP_RE.finditer(rest):
        try:
            ip = ipaddress.ip_address(m.group())
        except ValueError:
            continue
        if not _blocked_ip(ip):
            add("ip", str(ip))
    for m in DOMAIN_RE.finditer(rest):
        name, tld = m.group().lower(), m.group(1).lower()
        if tld in FILE_EXT or not re.search("[a-z]", name[: -len(tld)]):
            continue                                   # nom de fichier ou numéro de version
        if any(name == d or name.endswith("." + d) for d in ignore):
            continue
        add("domain", name)
    return out
