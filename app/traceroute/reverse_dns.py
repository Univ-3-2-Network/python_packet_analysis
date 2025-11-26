# Source - https://codereview.stackexchange.com/q
# Posted by Carcigenicate, modified by community. See post 'Timeline' for change history
# Retrieved 2025-11-27, License - CC BY-SA 4.0

from typing import Union

from scapy.layers.inet import UDP, IP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.sendrecv import sr1


_REVERSE_DOMAIN = ".in-addr.arpa"
_OCTET_DELIMITER = "."


def _reverse_dns_packet(ip: str, dns_server: str) -> DNS:
    reversed_ip = _OCTET_DELIMITER.join(reversed(ip.split(_OCTET_DELIMITER)))
    question = DNSQR(qname=f"{reversed_ip}{_REVERSE_DOMAIN}", qtype=12)
    return IP(dst=dns_server) / UDP(dport=53) / DNS(qd=question)


def reverse_dns_lookup(ip: str, dns_server: str, **sr1_kwargs) -> Union[None, int, str]:
    """
    Returns the str host-name if it could be resolved,
      or an int response code if there was an error,
      or None if the DNS server couldn't be reached.
    Unless you know the DNS server will be reachable, setting a timeout via the kwargs is advised.
    """
    request = _reverse_dns_packet(ip, dns_server)
    resp = sr1(request, **sr1_kwargs)
    if resp is None:
        return None
    resp_code = resp[1][DNS].rcode
    if resp_code == 0:
        raw = resp[1][DNSRR].rdata
        return raw.decode("UTF-8")
    else:
        return resp_code
