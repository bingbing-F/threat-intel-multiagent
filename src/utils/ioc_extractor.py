"""IOC extraction and normalization utilities."""
import re
from typing import List, Set

try:
    import iocextract

    HAS_IOCEXTRACT = True
except ImportError:
    HAS_IOCEXTRACT = False


class IOCExtractor:
    """Extract and normalize Indicators of Compromise from text."""

    # Regex patterns
    IPV4_PATTERN = re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$"
    )
    DOMAIN_PATTERN = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
    URL_PATTERN = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
    EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
    HASH_MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
    HASH_SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
    HASH_SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
    IP_PATTERN = re.compile(
        r"(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    )
    DOMAIN_EXTRACT_PATTERN = re.compile(
        r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"
    )

    # Common false positive domains
    FALSE_POSITIVE_DOMAINS = {
        "example.com",
        "localhost",
        "test.com",
        "yourdomain.com",
        "domain.com",
    }

    # Private/reserved IP prefixes
    BOGON_PREFIXES = (
        "0.",
        "10.",
        "127.",
        "169.254.",
        "172.16.",
        "192.168.",
        "224.",
        "240.",
        "255.255.255.255",
    )

    @classmethod
    def extract(cls, text: str) -> List[str]:
        """Extract all IOCs from text and return deduplicated list."""
        if HAS_IOCEXTRACT:
            return cls._extract_with_iocextract(text)
        return cls._extract_with_regex(text)

    @classmethod
    def _extract_with_iocextract(cls, text: str) -> List[str]:
        iocs: Set[str] = set()
        extract = getattr(iocextract, "extract_urls", None)
        if extract is not None:
            for url in extract(text, refang=True):
                iocs.add(cls.normalize_url(url))
        extract = getattr(iocextract, "extract_ips", None)
        if extract is not None:
            for ip in extract(text, refang=True):
                iocs.add(cls.normalize_ip(ip))
        extract = getattr(iocextract, "extract_domains", None)
        if extract is not None:
            for domain in extract(text, refang=True):
                iocs.add(cls.normalize_domain(domain))
        extract = getattr(iocextract, "extract_hashes", None)
        if extract is not None:
            for h in extract(text):
                iocs.add(h.lower())
        extract = getattr(iocextract, "extract_emails", None)
        if extract is not None:
            for email in extract(text, refang=True):
                iocs.add(email.lower())
        for cve in cls.extract_cves(text):
            iocs.add(cve.upper())
        return sorted(iocs)

    @classmethod
    def _extract_with_regex(cls, text: str) -> List[str]:
        iocs: Set[str] = set()
        # URLs
        for url in cls.URL_PATTERN.findall(text):
            iocs.add(cls.normalize_url(url))
        # IPs
        for ip in cls.IP_PATTERN.findall(text):
            normalized = cls.normalize_ip(ip)
            if cls.is_valid_ipv4(normalized):
                iocs.add(normalized)
        # Domains (filter out false positives)
        for domain in cls.DOMAIN_EXTRACT_PATTERN.findall(text):
            normalized = cls.normalize_domain(domain)
            if cls.is_valid_domain(normalized):
                iocs.add(normalized)
        # Hashes
        for h in cls.HASH_MD5_PATTERN.findall(text):
            iocs.add(h.lower())
        for h in cls.HASH_SHA1_PATTERN.findall(text):
            iocs.add(h.lower())
        for h in cls.HASH_SHA256_PATTERN.findall(text):
            iocs.add(h.lower())
        # Emails
        for email in cls.EMAIL_PATTERN.findall(text):
            iocs.add(email.lower())
        # CVEs
        for cve in cls.extract_cves(text):
            iocs.add(cve.upper())
        return sorted(iocs)

    @classmethod
    def normalize_url(cls, url: str) -> str:
        url = url.strip().rstrip("/")
        url = re.sub(r"[.,;:!?\"')\]]+$", "", url)
        return url

    @classmethod
    def normalize_ip(cls, ip: str) -> str:
        ip = ip.strip()
        ip = ip.replace("[", "").replace("]", "")
        return ip

    @classmethod
    def normalize_domain(cls, domain: str) -> str:
        domain = domain.strip().lower().rstrip("/")
        domain = re.sub(r"^https?://", "", domain)
        domain = re.sub(r"[.,;:!?\"')\]]+$", "", domain)
        return domain

    @classmethod
    def extract_cves(cls, text: str) -> List[str]:
        """Extract CVE identifiers."""
        return list(set(cls.CVE_PATTERN.findall(text)))

    @classmethod
    def is_valid_ipv4(cls, ip: str) -> bool:
        if not cls.IPV4_PATTERN.match(ip):
            return False
        if ip.startswith(cls.BOGON_PREFIXES):
            return False
        return True

    @classmethod
    def is_valid_domain(cls, domain: str) -> bool:
        if not cls.DOMAIN_PATTERN.match(domain):
            return False
        if domain in cls.FALSE_POSITIVE_DOMAINS:
            return False
        # Exclude if it looks like a URL path or filename extension
        if domain.endswith((".html", ".php", ".jpg", ".png", ".pdf")):
            return False
        return True

    @classmethod
    def filter_valid(cls, iocs: List[str]) -> List[str]:
        """Remove obvious false positives."""
        valid: List[str] = []
        for ioc in iocs:
            # IPv4 validation
            if cls.IPV4_PATTERN.match(ioc):
                if cls.is_valid_ipv4(ioc):
                    valid.append(ioc)
                continue
            # Domain validation
            if "." in ioc and not ioc.startswith("http"):
                if cls.is_valid_domain(ioc):
                    valid.append(ioc)
                continue
            # Hashes, CVEs, URLs, emails
            if (ioc.startswith("http") or cls.CVE_PATTERN.match(ioc) or
                    len(ioc) in (32, 40, 64) or cls.EMAIL_PATTERN.match(ioc)):
                valid.append(ioc)
        return valid
