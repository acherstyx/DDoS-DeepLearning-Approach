import dpkt
import socket


def translate_ip(ip):
    """
    transfer IP(IPv6) address in bin format to string format.

    :param ip:
    :return:
    """
    try:
        return socket.inet_ntop(socket.AF_INET, ip)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, ip)


def get_flow_id(pkt_buf):
    """
    get flow id from a raw dpkt packet

    :param pkt_buf: dpkt unpack buf
    :return: return flow id in string, or return None on failure
    """
    eth = dpkt.ethernet.Ethernet(pkt_buf)
    ip = eth.data
    if not isinstance(ip, dpkt.ip.IP) and not isinstance(ip, dpkt.ip6.IP6):
        return None
    tcp_udp = ip.data
    if not isinstance(tcp_udp, dpkt.tcp.TCP) and not isinstance(tcp_udp, dpkt.udp.UDP):
        return None

    src_ip = translate_ip(ip.src)
    dst_ip = translate_ip(ip.dst)
    src_port = tcp_udp.sport
    dst_port = tcp_udp.dport
    protocol = str(ip.p)

    return str(src_ip) + "-" + str(dst_ip) + "-" + str(src_port) + "-" + str(dst_port) + "-" + protocol


def unpack_feature(timestamp, buf):
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp_udp = ip.data

    feature = {"timestamp": timestamp,
               "pkt_len": len(buf),
               "ip_flags": eth.type,
               "protocols": ip.p}
    # print(ip.p)
    # packet len
    # ip flag
    # protocols
    if isinstance(ip.data, dpkt.tcp.TCP):
        # tcp len
        feature["tcp_len"] = len(tcp_udp)
        # tcp ack
        feature["tcp_ack"] = tcp_udp.ack
        # tcp flags
        feature["tcp_flags"] = tcp_udp.flags
        # tcp win
        feature["tcp_win_size"] = tcp_udp.win
    else:
        # tcp len
        feature["tcp_len"] = 0
        # tcp ack
        feature["tcp_ack"] = 0
        # tcp flags
        feature["tcp_flags"] = 0
        # tcp win
        feature["tcp_win_size"] = 0
    if isinstance(ip.data, dpkt.udp.UDP):
        # udp len
        feature["udp_len"] = len(tcp_udp)
    else:
        feature["udp_len"] = 0

    return feature


def get_label(label_str: str):
    if label_str.lower() == "attack":
        return [1.0, ]
    elif label_str.lower() == "syn":
        return [1.0, ]
    else:
        return [0.0, ]