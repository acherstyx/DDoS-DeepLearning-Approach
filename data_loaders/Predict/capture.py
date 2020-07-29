from scapy.all import *
from templates.utils import mkdir


def capture_pcap(pcap_file, interface, time_limit, pkt_limit):
    mkdir(pcap_file)
    dpkt = sniff(iface=interface, count=pkt_limit, timeout=time_limit)
    wrpcap(pcap_file, dpkt)


if __name__ == '__main__':
    PCAP_FILE = "sample.pcap"
    INTERFACE = "Intel(R) Wireless-AC 9462"
    COUNT = 10000
    TIMEOUT = None

    # show all network interface
    show_interfaces()

    capture_pcap(PCAP_FILE, INTERFACE, TIMEOUT, COUNT)
