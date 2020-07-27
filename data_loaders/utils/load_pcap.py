import dpkt
import socket
from utils.normalization.net import *
from utils.normalization.number import *
import numpy as np
import pickle
import logging

logger = logging.getLogger(__name__)


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


def parsing_packet(pkt):
    time = norm_number_clipped(int(pkt["time"] * 1000000), 32)
    pkt_len = norm_number_clipped(pkt["pkt_len"], 16)
    ip_flags = norm_number(pkt["ip_flags"], 16)
    protocols = norm_protocol(pkt["protocols"])  # 8
    tcp_len = norm_number(pkt["tcp_len"], 16)
    tcp_ack = norm_number(pkt["tcp_ack"], 32)
    tcp_flags = norm_number(pkt["tcp_flags"], 8)
    tcp_win_size = norm_number(pkt["tcp_win_size"], 16)
    udp_len = norm_number(pkt["udp_len"], 16)

    feature = time + pkt_len + ip_flags + protocols + tcp_len + tcp_ack + tcp_flags + tcp_win_size + udp_len
    return feature


def parsing_packet_list(flow, with_label, packet_limit):
    pkt_list = []
    label = None
    feature = None
    flow_num = 0

    for pkt in flow:
        time = norm_number_clipped(int(pkt["time"] * 1000000), 32)
        pkt_len = norm_number_clipped(pkt["pkt_len"], 16)
        ip_flags = norm_number(pkt["ip_flags"], 16)
        protocols = norm_protocol(pkt["protocols"])  # 8
        tcp_len = norm_number(pkt["tcp_len"], 16)
        tcp_ack = norm_number(pkt["tcp_ack"], 32)
        tcp_flags = norm_number(pkt["tcp_flags"], 8)
        tcp_win_size = norm_number(pkt["tcp_win_size"], 16)
        udp_len = norm_number(pkt["udp_len"], 16)

        feature = time + pkt_len + ip_flags + protocols + tcp_len + tcp_ack + tcp_flags + tcp_win_size + udp_len
        if with_label:
            label = get_label(pkt["label"])
        flow_num += 1
        pkt_list.append(feature)
        if flow_num >= packet_limit:
            break

    # zero padding for missing packet
    pkt_list = np.pad(pkt_list,
                      ((0, packet_limit - flow_num), (0, 0)),
                      mode="constant",
                      constant_values=(0.0, 0.0))
    try:
        assert np.shape(pkt_list) == (packet_limit, len(feature))
    except AssertionError:
        print(np.shape(pkt_list))
        print(packet_limit, len(feature))
        raise AssertionError
    if with_label:
        return pkt_list, label
    else:
        return pkt_list


def feature_extractor(pcap_file_list, packet_limit, cache_file=None, return_flow_id=False):
    def get_feature_dict():
        for pcap_file in opened_pcap_files:
            for ts, buf in pcap_file:
                flow_id = get_flow_id(buf)

                if flow_id is None:
                    continue

                feature = unpack_feature(ts, buf)

                if flow_id not in data_dict:
                    data_dict[flow_id] = []
                    feature["time"] = 0
                elif ts - data_dict[flow_id][0]["timestamp"] > 10:
                    continue
                else:
                    feature["time"] = ts - data_dict[flow_id][0]["timestamp"]

                data_dict[flow_id].append(feature)

    opened_pcap_files = [dpkt.pcap.Reader(open(file, "rb")) for file in pcap_file_list]
    data_dict = {}

    if cache_file is not None:
        try:
            with open(cache_file, "rb") as f:
                data_dict = pickle.load(f)
        except FileNotFoundError:
            get_feature_dict()
            with open(cache_file, "wb") as f:
                pickle.dump(data_dict, f)
    else:
        get_feature_dict()

    for key, flow in data_dict.items():
        logger.debug(key, flow)

        if not return_flow_id:
            yield parsing_packet_list(flow, with_label=False, packet_limit=packet_limit)
        else:
            yield key, parsing_packet_list(flow, with_label=False, packet_limit=packet_limit)


NORMAL_LIST = ["benign", "normal"]
ATTACK_LIST = ["attack", "syn", "udp", "mssql"]


def get_label(label_str: str):
    if label_str.lower() in NORMAL_LIST:
        return [0.0, ]
    elif label_str.lower() in ATTACK_LIST:
        return [1.0, ]
    else:
        logger.error(f"ERROR: Label {label_str} not in label list.")
        raise ValueError
