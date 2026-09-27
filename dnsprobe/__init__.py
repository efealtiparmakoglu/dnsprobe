"""dnsprobe — educational DNS resolver with hand-rolled wire format,
iterative referral walking, TTL cache and packet dump. Stdlib only."""
__version__ = "1.0.0"

from .cache import DNSCache
from .packet import (DNSFormatError, build_query, build_response, decode_name,
                     encode_name, encode_rr, hexdump, parse_message,
                     parse_rdata)
from .resolver import ROOT_SERVERS, ResolutionError, Resolver

__all__ = [
    "__version__", "DNSCache", "DNSFormatError", "ResolutionError",
    "Resolver", "ROOT_SERVERS", "build_query", "build_response",
    "decode_name", "encode_name", "encode_rr", "hexdump", "parse_message",
    "parse_rdata",
]
