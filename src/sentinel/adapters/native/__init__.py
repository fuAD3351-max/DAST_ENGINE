"""Native (first-party, in-process) engine adapters."""

from sentinel.adapters.native.crawler import CrawlerAdapter
from sentinel.adapters.native.fingerprint import FingerprintAdapter
from sentinel.adapters.native.headers import HeadersAdapter
from sentinel.adapters.native.tls import TlsAdapter
from sentinel.adapters.native.validator import ValidatorAdapter

__all__ = [
    "CrawlerAdapter",
    "FingerprintAdapter",
    "HeadersAdapter",
    "TlsAdapter",
    "ValidatorAdapter",
]
