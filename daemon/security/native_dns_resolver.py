"""
Native DNS Resolver - Pure Python DNS Resolution Without External Tools

This module addresses the vulnerability: "DNS Response Verification Uses External Tools"

SECURITY ISSUE WITH EXTERNAL TOOLS:
- dig, nslookup, host can be replaced by attackers
- PATH manipulation attacks possible
- Output parsing can be manipulated
- No verification of tool binary authenticity

THIS MODULE PROVIDES:
1. Pure Python DNS packet construction and parsing
2. Direct UDP/TCP socket communication with resolvers
3. No external tool dependencies
4. DNSSEC-aware queries (when dnspython is available)
5. Multiple resolver verification
6. Response consistency checking

USAGE:
    resolver = NativeDNSResolver()
    result = resolver.resolve('example.com', 'A')
    verified = resolver.verify_across_resolvers('example.com')
"""

import socket
import struct
import secrets
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from enum import IntEnum
from datetime import datetime

logger = logging.getLogger(__name__)


class DNSType(IntEnum):
    """DNS Record Types"""
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    AAAA = 28
    SRV = 33
    ANY = 255


class DNSClass(IntEnum):
    """DNS Classes"""
    IN = 1      # Internet
    CS = 2      # CSNET (obsolete)
    CH = 3      # CHAOS
    HS = 4      # Hesiod


class DNSResponseCode(IntEnum):
    """DNS Response Codes"""
    NOERROR = 0
    FORMERR = 1     # Format error
    SERVFAIL = 2    # Server failure
    NXDOMAIN = 3    # Non-existent domain
    NOTIMP = 4      # Not implemented
    REFUSED = 5     # Query refused


@dataclass
class DNSRecord:
    """Represents a DNS resource record"""
    name: str
    type: int
    class_: int
    ttl: int
    data: str
    raw_data: bytes = field(default_factory=bytes)


@dataclass
class DNSResponse:
    """Represents a complete DNS response"""
    query_id: int
    domain: str
    response_code: int
    is_authoritative: bool
    is_truncated: bool
    recursion_available: bool
    answers: List[DNSRecord]
    authorities: List[DNSRecord]
    additionals: List[DNSRecord]
    response_time_ms: float
    resolver: str

    @property
    def success(self) -> bool:
        return self.response_code == DNSResponseCode.NOERROR

    def get_ips(self) -> List[str]:
        """Get IP addresses from A/AAAA records"""
        ips = []
        for answer in self.answers:
            if answer.type in (DNSType.A, DNSType.AAAA):
                ips.append(answer.data)
        return ips


class DNSPacketBuilder:
    """Builds DNS query packets in pure Python"""

    @staticmethod
    def build_query(domain: str, query_type: int = DNSType.A,
                    query_class: int = DNSClass.IN,
                    recursion_desired: bool = True) -> Tuple[bytes, int]:
        """
        Build a DNS query packet.

        Args:
            domain: Domain name to query
            query_type: DNS record type (A, AAAA, etc.)
            query_class: DNS class (usually IN)
            recursion_desired: Whether to request recursion

        Returns:
            (packet bytes, query ID)
        """
        # Generate cryptographically secure random query ID
        # SECURITY: Using secrets module instead of random to prevent DNS cache poisoning
        query_id = secrets.randbelow(65536)

        # Build header
        # Flags: QR=0 (query), OPCODE=0 (standard), AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0
        flags = 0x0100 if recursion_desired else 0x0000

        # Header structure: ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
        header = struct.pack('>HHHHHH',
                           query_id,    # ID
                           flags,       # Flags
                           1,           # QDCOUNT (1 question)
                           0,           # ANCOUNT
                           0,           # NSCOUNT
                           0)           # ARCOUNT

        # Build question section
        question = DNSPacketBuilder._encode_domain(domain)
        question += struct.pack('>HH', query_type, query_class)

        return header + question, query_id

    @staticmethod
    def _encode_domain(domain: str) -> bytes:
        """
        Encode a domain name to DNS wire format.

        Example: "www.example.com" -> b'\x03www\x07example\x03com\x00'
        """
        result = b''
        for label in domain.rstrip('.').split('.'):
            if len(label) > 63:
                raise ValueError(f"DNS label too long: {label}")
            result += bytes([len(label)]) + label.encode('ascii')
        result += b'\x00'  # Root label
        return result


class DNSPacketParser:
    """Parses DNS response packets in pure Python"""

    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def parse(self) -> Dict:
        """Parse a complete DNS response packet"""
        # Parse header
        header = self._parse_header()

        # Parse questions
        questions = []
        for _ in range(header['qdcount']):
            questions.append(self._parse_question())

        # Parse answers
        answers = []
        for _ in range(header['ancount']):
            answers.append(self._parse_resource_record())

        # Parse authorities
        authorities = []
        for _ in range(header['nscount']):
            authorities.append(self._parse_resource_record())

        # Parse additionals
        additionals = []
        for _ in range(header['arcount']):
            try:
                additionals.append(self._parse_resource_record())
            except Exception:
                break  # Additional section parsing is optional

        return {
            'header': header,
            'questions': questions,
            'answers': answers,
            'authorities': authorities,
            'additionals': additionals,
        }

    def _parse_header(self) -> Dict:
        """Parse DNS header (12 bytes)"""
        if len(self.data) < 12:
            raise ValueError("DNS packet too short for header")

        header = struct.unpack('>HHHHHH', self.data[:12])
        self.offset = 12

        flags = header[1]

        return {
            'id': header[0],
            'qr': (flags >> 15) & 0x1,          # Query/Response
            'opcode': (flags >> 11) & 0xF,      # Operation code
            'aa': (flags >> 10) & 0x1,          # Authoritative Answer
            'tc': (flags >> 9) & 0x1,           # Truncated
            'rd': (flags >> 8) & 0x1,           # Recursion Desired
            'ra': (flags >> 7) & 0x1,           # Recursion Available
            'rcode': flags & 0xF,               # Response code
            'qdcount': header[2],               # Question count
            'ancount': header[3],               # Answer count
            'nscount': header[4],               # Authority count
            'arcount': header[5],               # Additional count
        }

    def _parse_question(self) -> Dict:
        """Parse a question section entry"""
        name = self._parse_domain()
        qtype, qclass = struct.unpack('>HH', self.data[self.offset:self.offset+4])
        self.offset += 4

        return {
            'name': name,
            'type': qtype,
            'class': qclass,
        }

    def _parse_resource_record(self) -> DNSRecord:
        """Parse a resource record (answer, authority, or additional)"""
        name = self._parse_domain()

        if self.offset + 10 > len(self.data):
            raise ValueError("Packet truncated in resource record")

        rtype, rclass, ttl, rdlength = struct.unpack(
            '>HHIH',
            self.data[self.offset:self.offset+10]
        )
        self.offset += 10

        if self.offset + rdlength > len(self.data):
            raise ValueError("Packet truncated in resource data")

        rdata_raw = self.data[self.offset:self.offset+rdlength]
        self.offset += rdlength

        # Parse rdata based on type
        rdata = self._parse_rdata(rtype, rdata_raw)

        return DNSRecord(
            name=name,
            type=rtype,
            class_=rclass,
            ttl=ttl,
            data=rdata,
            raw_data=rdata_raw,
        )

    def _parse_domain(self) -> str:
        """
        Parse a domain name, handling compression.

        DNS compression uses pointers (0xC0 prefix) to refer to
        earlier occurrences of domain name parts.
        """
        labels = []
        jumped = False
        jump_offset = 0

        while True:
            if self.offset >= len(self.data):
                break

            length = self.data[self.offset]

            if length == 0:
                # End of domain
                if not jumped:
                    self.offset += 1
                break

            if (length & 0xC0) == 0xC0:
                # Compression pointer
                if self.offset + 1 >= len(self.data):
                    break
                pointer = struct.unpack('>H', self.data[self.offset:self.offset+2])[0]
                pointer &= 0x3FFF  # Remove compression flag bits

                if not jumped:
                    jump_offset = self.offset + 2

                self.offset = pointer
                jumped = True
                continue

            # Regular label
            self.offset += 1
            if self.offset + length > len(self.data):
                break
            label = self.data[self.offset:self.offset+length].decode('ascii', errors='replace')
            labels.append(label)
            self.offset += length

        if jumped:
            self.offset = jump_offset

        return '.'.join(labels)

    def _parse_rdata(self, rtype: int, rdata: bytes) -> str:
        """Parse resource data based on record type"""
        if rtype == DNSType.A:
            if len(rdata) == 4:
                return socket.inet_ntoa(rdata)
            return f"<invalid A record: {len(rdata)} bytes>"

        elif rtype == DNSType.AAAA:
            if len(rdata) == 16:
                return socket.inet_ntop(socket.AF_INET6, rdata)
            return f"<invalid AAAA record: {len(rdata)} bytes>"

        elif rtype == DNSType.CNAME or rtype == DNSType.NS or rtype == DNSType.PTR:
            # These contain a domain name
            parser = DNSPacketParser(self.data)
            parser.offset = self.offset - len(rdata)
            return parser._parse_domain()

        elif rtype == DNSType.MX:
            if len(rdata) >= 2:
                preference = struct.unpack('>H', rdata[:2])[0]
                parser = DNSPacketParser(self.data)
                parser.offset = self.offset - len(rdata) + 2
                exchange = parser._parse_domain()
                return f"{preference} {exchange}"
            return "<invalid MX>"

        elif rtype == DNSType.TXT:
            # TXT records are one or more <length><string> pairs
            result = []
            pos = 0
            while pos < len(rdata):
                length = rdata[pos]
                pos += 1
                if pos + length <= len(rdata):
                    result.append(rdata[pos:pos+length].decode('utf-8', errors='replace'))
                    pos += length
            return ''.join(result)

        else:
            # Return hex for unknown types
            return rdata.hex()


class NativeDNSResolver:
    """
    Pure Python DNS resolver without external tool dependencies.

    SECURITY: This resolver does NOT call external tools like dig, nslookup, or host.
    All DNS operations are performed using Python's socket library.
    """

    # Default resolvers for verification
    DEFAULT_RESOLVERS = [
        ('1.1.1.1', 'Cloudflare'),
        ('8.8.8.8', 'Google'),
        ('9.9.9.9', 'Quad9'),
        ('208.67.222.222', 'OpenDNS'),
    ]

    # DNS port
    DNS_PORT = 53

    # Timeout settings
    DEFAULT_TIMEOUT = 5.0
    DEFAULT_RETRIES = 2

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        use_tcp_fallback: bool = True,
    ):
        """
        Initialize the native DNS resolver.

        Args:
            timeout: Socket timeout in seconds
            retries: Number of retry attempts
            use_tcp_fallback: Fall back to TCP if UDP response is truncated
        """
        self.timeout = timeout
        self.retries = retries
        self.use_tcp_fallback = use_tcp_fallback

    def resolve(
        self,
        domain: str,
        record_type: int = DNSType.A,
        resolver: str = None,
    ) -> DNSResponse:
        """
        Resolve a domain using pure Python DNS implementation.

        Args:
            domain: Domain name to resolve
            record_type: DNS record type (A, AAAA, etc.)
            resolver: Optional specific resolver IP to use

        Returns:
            DNSResponse object with results
        """
        resolver_ip = resolver or self.DEFAULT_RESOLVERS[0][0]
        resolver_name = resolver or 'system'

        # Build query packet
        query_packet, query_id = DNSPacketBuilder.build_query(
            domain=domain,
            query_type=record_type,
        )

        # Try UDP first
        start_time = time.time()
        response_data = None

        for attempt in range(self.retries + 1):
            try:
                response_data = self._send_udp_query(
                    query_packet,
                    resolver_ip,
                )
                break
            except socket.timeout:
                if attempt < self.retries:
                    continue
                raise
            except Exception as e:
                if attempt < self.retries:
                    continue
                raise

        response_time_ms = (time.time() - start_time) * 1000

        if response_data is None:
            return DNSResponse(
                query_id=query_id,
                domain=domain,
                response_code=DNSResponseCode.SERVFAIL,
                is_authoritative=False,
                is_truncated=False,
                recursion_available=False,
                answers=[],
                authorities=[],
                additionals=[],
                response_time_ms=response_time_ms,
                resolver=resolver_name,
            )

        # Parse response
        try:
            parser = DNSPacketParser(response_data)
            parsed = parser.parse()
        except Exception as e:
            logger.error(f"Failed to parse DNS response: {e}")
            return DNSResponse(
                query_id=query_id,
                domain=domain,
                response_code=DNSResponseCode.FORMERR,
                is_authoritative=False,
                is_truncated=False,
                recursion_available=False,
                answers=[],
                authorities=[],
                additionals=[],
                response_time_ms=response_time_ms,
                resolver=resolver_name,
            )

        header = parsed['header']

        # Check if truncated and retry with TCP
        if header['tc'] and self.use_tcp_fallback:
            try:
                tcp_start = time.time()
                response_data = self._send_tcp_query(query_packet, resolver_ip)
                response_time_ms = (time.time() - tcp_start) * 1000

                parser = DNSPacketParser(response_data)
                parsed = parser.parse()
                header = parsed['header']
            except Exception as e:
                logger.warning(f"TCP fallback failed: {e}")

        return DNSResponse(
            query_id=header['id'],
            domain=domain,
            response_code=header['rcode'],
            is_authoritative=bool(header['aa']),
            is_truncated=bool(header['tc']),
            recursion_available=bool(header['ra']),
            answers=parsed['answers'],
            authorities=parsed['authorities'],
            additionals=parsed['additionals'],
            response_time_ms=response_time_ms,
            resolver=resolver_name,
        )

    def _send_udp_query(self, query: bytes, resolver: str) -> bytes:
        """Send DNS query over UDP"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)

        try:
            sock.sendto(query, (resolver, self.DNS_PORT))
            response, _ = sock.recvfrom(4096)
            return response
        finally:
            sock.close()

    def _send_tcp_query(self, query: bytes, resolver: str) -> bytes:
        """Send DNS query over TCP (for large responses)"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            sock.connect((resolver, self.DNS_PORT))

            # TCP DNS requires 2-byte length prefix
            length_prefix = struct.pack('>H', len(query))
            sock.sendall(length_prefix + query)

            # Read response length
            length_data = sock.recv(2)
            if len(length_data) < 2:
                raise ValueError("TCP response too short")

            response_length = struct.unpack('>H', length_data)[0]

            # Read response data
            response = b''
            while len(response) < response_length:
                chunk = sock.recv(response_length - len(response))
                if not chunk:
                    break
                response += chunk

            return response
        finally:
            sock.close()

    def resolve_with_system(self, domain: str) -> List[str]:
        """
        Resolve using system resolver (getaddrinfo).

        This uses the system's configured DNS but is still pure Python.
        """
        ips = []

        try:
            # Get IPv4 addresses
            for info in socket.getaddrinfo(domain, None, socket.AF_INET):
                ips.append(info[4][0])
        except socket.gaierror:
            pass

        try:
            # Get IPv6 addresses
            for info in socket.getaddrinfo(domain, None, socket.AF_INET6):
                ips.append(info[4][0])
        except socket.gaierror:
            pass

        return list(set(ips))

    def verify_across_resolvers(
        self,
        domain: str,
        record_type: int = DNSType.A,
        resolvers: List[Tuple[str, str]] = None,
    ) -> Dict:
        """
        Verify DNS response by querying multiple resolvers.

        SECURITY: This is the replacement for the vulnerable external tool method.
        All queries are performed using pure Python sockets.

        Args:
            domain: Domain to verify
            record_type: DNS record type
            resolvers: List of (ip, name) tuples for resolvers

        Returns:
            Dict with verification results
        """
        resolvers = resolvers or self.DEFAULT_RESOLVERS

        results = {
            'domain': domain,
            'record_type': record_type,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'consistent': True,
            'responses': {},
            'all_ips': set(),
            'alerts': [],
        }

        for resolver_ip, resolver_name in resolvers:
            try:
                response = self.resolve(
                    domain=domain,
                    record_type=record_type,
                    resolver=resolver_ip,
                )

                ips = response.get_ips()
                results['responses'][resolver_name] = {
                    'ips': ips,
                    'response_code': response.response_code,
                    'response_time_ms': response.response_time_ms,
                    'is_authoritative': response.is_authoritative,
                }
                results['all_ips'].update(ips)

            except socket.timeout:
                results['responses'][resolver_name] = {
                    'error': 'timeout',
                    'ips': [],
                }
            except Exception as e:
                results['responses'][resolver_name] = {
                    'error': str(e),
                    'ips': [],
                }

        # Check consistency
        ip_sets = []
        for resolver_name, data in results['responses'].items():
            if 'error' not in data and data['ips']:
                ip_sets.append(frozenset(data['ips']))

        if len(ip_sets) > 1:
            # Check if all resolvers returned the same IPs
            if len(set(ip_sets)) > 1:
                results['consistent'] = False
                results['alerts'].append(
                    f"Inconsistent DNS responses across resolvers for {domain}"
                )

        # Convert set to list for JSON serialization
        results['all_ips'] = list(results['all_ips'])

        return results

    def check_dnssec(self, domain: str) -> Dict:
        """
        Check DNSSEC status for a domain.

        Returns information about DNSSEC configuration.
        Note: Full DNSSEC validation requires the dnspython library.
        """
        result = {
            'domain': domain,
            'has_dnskey': False,
            'has_ds': False,
            'has_rrsig': False,
            'validation_available': False,
        }

        try:
            # Query DNSKEY record
            response = self.resolve(domain, DNSType.ANY)
            for answer in response.answers:
                if answer.type == 48:  # DNSKEY
                    result['has_dnskey'] = True
                if answer.type == 46:  # RRSIG
                    result['has_rrsig'] = True

            # Try to import dnspython for full validation
            try:
                import dns.resolver
                import dns.dnssec
                result['validation_available'] = True
            except ImportError:
                pass

        except Exception as e:
            result['error'] = str(e)

        return result


class SecureDNSVerifier:
    """
    High-level DNS verification that doesn't use external tools.

    This class replaces the vulnerable subprocess-based DNS verification.
    """

    def __init__(self, event_logger=None):
        self.resolver = NativeDNSResolver()
        self.event_logger = event_logger
        self._baseline: Dict[str, Set[str]] = {}

    def verify_dns_response(
        self,
        domain: str,
        expected_ips: Optional[List[str]] = None,
    ) -> Dict:
        """
        Verify a DNS response using pure Python.

        SECURITY: This method does NOT use external tools like dig, nslookup, or host.
        All DNS queries are performed using Python's socket library.

        Args:
            domain: Domain to verify
            expected_ips: Optional list of expected IP addresses

        Returns:
            Dict with verification results
        """
        # Use native resolver for verification
        results = self.resolver.verify_across_resolvers(domain)

        # Check against expected IPs
        if expected_ips:
            expected_set = set(expected_ips)
            actual_set = set(results['all_ips'])

            if not expected_set.intersection(actual_set):
                results['alerts'].append(
                    f"DNS response doesn't match expected IPs for {domain}. "
                    f"Expected: {list(expected_set)[:3]}, Got: {list(actual_set)[:3]}"
                )

        # Check against baseline
        if domain in self._baseline:
            baseline_ips = self._baseline[domain]
            current_ips = set(results['all_ips'])

            if baseline_ips and current_ips and not baseline_ips.intersection(current_ips):
                results['alerts'].append(
                    f"DNS response differs from baseline for {domain}. "
                    f"Possible DNS spoofing."
                )

        # Update baseline
        if results['all_ips']:
            if domain not in self._baseline:
                self._baseline[domain] = set()
            self._baseline[domain].update(results['all_ips'])

            # Limit baseline size
            if len(self._baseline[domain]) > 20:
                self._baseline[domain] = set(list(self._baseline[domain])[-20:])

        return results

    def detect_spoofing(
        self,
        domain: str,
        response_ips: List[str],
    ) -> Optional[str]:
        """
        Detect DNS spoofing by comparing against baseline.

        Args:
            domain: Domain that was queried
            response_ips: IPs returned in the response

        Returns:
            Alert message if spoofing detected, None otherwise
        """
        if domain not in self._baseline:
            # First time seeing this domain
            self._baseline[domain] = set(response_ips)
            return None

        known_ips = self._baseline[domain]
        new_ips = set(response_ips)

        # If completely different IPs, might be spoofing
        if known_ips and new_ips and not known_ips.intersection(new_ips):
            return (
                f"DNS spoofing suspected: {domain} resolved to unexpected IPs. "
                f"Expected: {list(known_ips)[:3]}, Got: {list(new_ips)[:3]}"
            )

        # Update baseline
        self._baseline[domain].update(response_ips)
        return None

    def get_baseline(self) -> Dict[str, List[str]]:
        """Get current DNS baseline"""
        return {
            domain: list(ips)
            for domain, ips in self._baseline.items()
        }


# Convenience function for quick DNS resolution
def resolve_domain(domain: str, record_type: str = 'A') -> List[str]:
    """
    Resolve a domain using pure Python (no external tools).

    Args:
        domain: Domain to resolve
        record_type: 'A' for IPv4, 'AAAA' for IPv6

    Returns:
        List of IP addresses
    """
    resolver = NativeDNSResolver()
    rtype = DNSType.AAAA if record_type.upper() == 'AAAA' else DNSType.A

    try:
        response = resolver.resolve(domain, rtype)
        return response.get_ips()
    except Exception as e:
        logger.error(f"Failed to resolve {domain}: {e}")
        return []


if __name__ == '__main__':
    import sys

    logging.basicConfig(level=logging.DEBUG)

    print("Native DNS Resolver Test")
    print("=" * 60)
    print("SECURITY: This resolver uses NO external tools (dig, nslookup, etc.)")
    print("=" * 60)

    resolver = NativeDNSResolver()

    # Test basic resolution
    test_domains = [
        'google.com',
        'cloudflare.com',
        'github.com',
    ]

    print("\n--- Basic Resolution ---")
    for domain in test_domains:
        try:
            response = resolver.resolve(domain)
            print(f"{domain}:")
            print(f"  Response code: {response.response_code}")
            print(f"  IPs: {response.get_ips()}")
            print(f"  Response time: {response.response_time_ms:.2f}ms")
        except Exception as e:
            print(f"{domain}: ERROR - {e}")

    # Test verification across resolvers
    print("\n--- Cross-Resolver Verification ---")
    result = resolver.verify_across_resolvers('example.com')
    print(f"Domain: {result['domain']}")
    print(f"Consistent: {result['consistent']}")
    for resolver_name, data in result['responses'].items():
        if 'error' in data:
            print(f"  {resolver_name}: ERROR - {data['error']}")
        else:
            print(f"  {resolver_name}: {data['ips']} ({data['response_time_ms']:.1f}ms)")

    # Test secure verifier
    print("\n--- Secure Verifier ---")
    verifier = SecureDNSVerifier()
    result = verifier.verify_dns_response('google.com')
    print(f"Consistent: {result['consistent']}")
    print(f"All IPs: {result['all_ips']}")
    if result['alerts']:
        print(f"Alerts: {result['alerts']}")

    print("\nTest complete - all DNS operations used pure Python (no external tools)")
