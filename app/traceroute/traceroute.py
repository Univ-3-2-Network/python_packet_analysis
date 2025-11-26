# Source - https://codereview.stackexchange.com/q
# Posted by Carcigenicate, modified by community. See post 'Timeline' for change history
# Retrieved 2025-11-27, License - CC BY-SA 4.0

from typing import Tuple, List, Optional, Callable, TypeVar
from collections import Counter
from time import perf_counter
import argparse as ap

from scapy.config import conf
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1

from reverse_dns import reverse_dns_lookup


_MAX_TTL = 255
_DEFAULT_TIMEOUT = 5
_DEFAULT_VERBOSITY = False
_DEFAULT_TESTS_PER = 3
_DEFAULT_RESOLVE_HOSTNAMES = True
_TABLE_SPACING = 10

NO_INFO_SYM = "*"

T = TypeVar("T")


def _new_trace_packet(destination_ip: str, hop_n: int) -> ICMP:
    return IP(dst=destination_ip, ttl=hop_n) / ICMP()


# Credit: https://stackoverflow.com/a/60845191/3000206
def get_gateway_of(ip: str) -> str:
    return conf.route.route(ip)[2]


def _check_hop_n(destination_ip: str, hop_n: int, **sr1_kwargs) -> Optional[Tuple[str, bool]]:
    """
    Returns a tuple of (hop_ip, destination_reached?)
    """
    sr1_kwargs.setdefault("timeout", _DEFAULT_TIMEOUT)
    sr1_kwargs.setdefault("verbose", _DEFAULT_VERBOSITY)

    packet = _new_trace_packet(destination_ip, hop_n)
    reply = sr1(packet, **sr1_kwargs)
    return reply and (reply[IP].src, reply[ICMP].type == 0)


def _find_proper_route(replies: List[ICMP]) -> Optional[Tuple[str, bool]]:
    if not replies:
        return None
    ip_isfin_pairs = [(resp[IP].src, resp[ICMP].type == 0) for resp in replies]
    found_destination = next((ip for ip, isfin in ip_isfin_pairs if isfin), None)
    selected_ip = found_destination or Counter(ip for ip, _ in ip_isfin_pairs).most_common(1)[0][0]
    return selected_ip, bool(found_destination)


def _time_exec(f: Callable[[], T]) -> Tuple[float, T]:
    """
    Executes the function and returns a tuple of [exec_seconds, result].
    """
    start = perf_counter()
    result = f()
    end = perf_counter()
    return end - start, result


def _cell_print(x: str) -> None:
    print(x.ljust(_TABLE_SPACING), end="", flush=True)


def _tracert_hop_row(destination_ip: str,
                     n_tests: int,
                     hop_n: int,
                     resolve_hostname: bool,
                     **sr_kwargs) -> bool:
    sr_kwargs.setdefault("timeout", _DEFAULT_TIMEOUT)
    sr_kwargs.setdefault("verbose", _DEFAULT_VERBOSITY)
    packet = _new_trace_packet(destination_ip, hop_n)
    replies = []
    for _ in range(n_tests):
        secs, reply = _time_exec(lambda: sr1(packet, **sr_kwargs))
        _cell_print(NO_INFO_SYM if reply is None else f"{int(secs * 1000)} ms")
        if reply:
            replies.append(reply)
    if not replies:
        _cell_print(NO_INFO_SYM)
        return False
    best_route, found_destination = _find_proper_route(replies)
    if resolve_hostname:
        host = reverse_dns_lookup(best_route, get_gateway_of(best_route), **sr_kwargs)
        if isinstance(host, str):
            _cell_print(f"{host} [{best_route}]")
        else:
            _cell_print(best_route)
    else:
        _cell_print(best_route)
    return found_destination


def tracert_internal(destination_ip: str,
                     n_tests_per_hop: int = _DEFAULT_TESTS_PER,
                     resolve_hostnames: bool = _DEFAULT_RESOLVE_HOSTNAMES,
                     max_hops: int = _MAX_TTL,
                     **sr_kwargs) -> None:
    for hop_n in range(1, max_hops + 1):
        _cell_print(str(hop_n))
        found_destination = _tracert_hop_row(destination_ip, n_tests_per_hop, hop_n, resolve_hostnames, **sr_kwargs)
        print()
        if found_destination:
            break


def main():
    parser = ap.ArgumentParser()
    parser.add_argument("ip")
    parser.add_argument("-d", action="store_false", default=True,
                        help="Do not resolve addresses to hostnames.")
    parser.add_argument("-o", type=int, default=_MAX_TTL,
                        help="Maximum number of hops to search for target.")
    parser.add_argument("-w", type=float, default=_DEFAULT_TIMEOUT,
                        help="Wait timeout milliseconds for each reply.")
    parser.add_argument("-t", type=int, default=_DEFAULT_TESTS_PER,
                        help="How many per packets to send per hop.")
    args = parser.parse_args()

    try:
        tracert_internal(args.ip, args.t, args.d, args.o, timeout=args.w)
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
