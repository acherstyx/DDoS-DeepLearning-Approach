__package__ = "data_loaders.ISCXIDS_2012"

from scapy.all import PcapReader
import time
import dpkt
import socket
from .xml_reader import ISCXIDS_2012_XML_Reader
import json
import pandas as pd
import csv

MAX_FLOW_SAMPLE = 100


class ScapyPcapReader:
    def __init__(self, pcap_file_path):
        self._file = pcap_file_path
        opened_file = open(self._file, 'rb')
        self.packets = PcapReader(opened_file)

        self.data = {}

    def view_data(self):
        for index, pkt in enumerate(self.packets):
            if 'TCP' in pkt:
                print("-----\n",
                      "#:", index, '\n',
                      "time:", time.ctime(int(pkt.time)), "\n",
                      "time:", time.gmtime(int(pkt.time)), "\n",
                      "src_port:", pkt['TCP'].sport, "\n",
                      "dst_port:", pkt['TCP'].dport, "\n",
                      "pkt_len:", pkt['IP'].len, "\n",
                      "ip_flag:", pkt['IP'].flags, "\n",

                      # "tcp_len:", pkt['TCP'].len, "\n",
                      "tcp_flag:", pkt['TCP'].flags, "\n",
                      "tcp_window_size:", pkt['TCP'].window, "\n",
                      "tcp_ack:", pkt['TCP'].ack, "\n",

                      "payload:", pkt['TCP'].payload)
            # pkt.show()

    def unpack_pcap(self):
        for index, pkt in enumerate(self.packets):
            # get flow id
            transport_layer = ""
            network_layer = ""
            try:
                if 'IP' in pkt:
                    network_layer = 'IP'
                elif 'IPv6' in pkt:
                    network_layer = 'IPv6'
                else:
                    print("Warning: no IP or IPv6 layer in this pkt")
                    # pkt.show()
                    continue

                if 'TCP' in pkt:
                    transport_layer = 'TCP'
                elif 'UDP' in pkt:
                    transport_layer = 'UDP'
                else:
                    print("Warning: no TCP or UDP layer in this pkt")
                    # pkt.show()
                    continue

                src_port = pkt[transport_layer].sport
                dst_port = pkt[transport_layer].sport
                src_ip = pkt[network_layer].src
                dst_ip = pkt[network_layer].dst
                # print(src_ip, src_port, dst_ip, dst_port)
            except IndexError as e:
                print(e)
                # pkt.show()
                continue

            flow_id = src_ip + src_port + dst_ip + dst_port

            feature = {}
            # time
            if flow_id not in self.data:
                self.data[flow_id] = []
                feature["time"] = 0
                feature["start_time"] = int(pkt.time)
            else:
                feature["time"] = int(pkt.time) - self.data[flow_id][0]["start_time"]
            # packet len


class ISCXIDS2012PcapDataPreprocess:
    def __init__(self, pcap_file_path, xml_label_file_list, max_flow_sample):
        # parameter
        self.max_flow_sample = max_flow_sample
        # save file path
        self.__pcap_file = pcap_file_path
        self.__xml_label_file = xml_label_file_list
        # statistic
        self.no_match_flow = 0
        self.no_ip = 0
        self.no_tcp_udp = 0
        self.duplicated = 0
        self.accepted = 0
        # open pcap file
        openfile = open(pcap_file_path, 'rb')
        self.packet = dpkt.pcap.Reader(openfile)

        self.data = {}

    @staticmethod
    def __translate_ip(ip):
        try:
            return socket.inet_ntop(socket.AF_INET, ip)
        except ValueError:
            return socket.inet_ntop(socket.AF_INET6, ip)

    def view_data(self):
        for ts, buf in self.packet:
            # print(ts)
            # print(buf)
            eth = dpkt.ethernet.Ethernet(buf)
            # is an IP packet
            if not isinstance(eth.data, dpkt.ip.IP) and not isinstance(eth.data, dpkt.ip6.IP6):
                # print("Not IPv4 or IPv6 packet.")
                continue
            ip = eth.data
            if not isinstance(ip.data, dpkt.tcp.TCP):
                # print("Not TCP or UDP packet.")
                continue
            tcp = ip.data

            src_ip = self.__translate_ip(ip.src)
            dst_ip = self.__translate_ip(ip.dst)
            dst_port = tcp.dport
            # print(src_ip, dst_ip, dst_port, length, eth.type, ip.get_proto(ip.p).__name__)
            # print(src_ip, dst_ip, dst_port, len(ip.data), len(buf))
            print(tcp.win)

    def load(self):
        # load flow label from xml file
        xml_label = ISCXIDS_2012_XML_Reader(self.__xml_label_file)
        self.label = xml_label.get_flow()

        time_start = time.time()
        for index, (ts, buf) in enumerate(self.packet):
            if index % 1000000 == 0:
                print(">total:", index, "\n",
                      "time cost:", time.time() - time_start, "s\n",
                      "no match flow:", self.no_match_flow, "\n",
                      "not ip(v6):", self.no_ip, "\n",
                      "not tcp/udp:", self.no_tcp_udp, "\n",
                      "duplicated:", self.duplicated, "\n",
                      "accept:", self.accepted, "\n",
                      "=====")
            # get flow id
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP) and not isinstance(eth.data, dpkt.ip6.IP6):
                self.no_ip += 1
                continue
            ip = eth.data
            if not isinstance(ip.data, dpkt.tcp.TCP) and not isinstance(ip.data, dpkt.udp.UDP):
                self.no_tcp_udp += 1
                continue
            tcp_udp = ip.data

            src_ip = self.__translate_ip(ip.src)
            dst_ip = self.__translate_ip(ip.dst)
            src_port = tcp_udp.sport
            dst_port = tcp_udp.dport

            flow_id = str(src_ip) + "-" + str(src_port) + "-" + str(dst_ip) + "-" + str(dst_port)

            feature = {}
            # time
            if flow_id not in self.data:
                feature["time"] = 0
                feature["start_time"] = ts
            else:
                if len(self.data[flow_id]) > self.max_flow_sample:
                    self.duplicated += 1
                    continue
                feature["time"] = ts - self.data[flow_id][0]["start_time"]
                # feature["time"] = 0
            # packet len
            feature["pkt_len"] = len(buf)
            # ip flag
            feature["ip_flags"] = eth.type
            # protocols
            feature["protocols"] = ip.get_proto(ip.p).__name__
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
            # get label
            try:
                feature["label"] = self.label[flow_id]
            except KeyError:
                # print(flow_id)
                self.no_match_flow += 1
                continue

            if flow_id not in self.data:
                self.data[flow_id] = []
            self.data[flow_id].append(feature)
            self.accepted += 1

    def cache(self, json_file_path):
        with open(json_file_path, "w") as f:
            json.dump(self.data, f)

    def load_from_cache(self, json_file_path):
        with open(json_file_path, "r") as f:
            self.data = json.load(f)

    def save_to_csv(self, csv_file_path):
        with open(csv_file_path, "w", encoding='utf-8', newline='') as f:
            # writer.writerow(("flow_id", "flow_pkt"))
            for flow_id, flow in self.data.items():
                f.writelines(json.dumps(flow) + "\n")

    def view_csv(self, csv_file_path):
        print("Loadng csv...")
        cache_reader = open(csv_file_path, "r")
        for row in cache_reader:
            print(row, end="")

    def get_data(self):
        return self.data


if __name__ == "__main__":
    file_list = ["dataset/ISCXIDS2012/labeled_flows_xml/TestbedMonJun14Flows.xml",
                 "dataset/ISCXIDS2012/labeled_flows_xml/TestbedTueJun15-1Flows.xml",
                 "dataset/ISCXIDS2012/labeled_flows_xml/TestbedTueJun15-2Flows.xml",
                 "dataset/ISCXIDS2012/labeled_flows_xml/TestbedTueJun15-3Flows.xml"]

    reader = ISCXIDS2012PcapDataPreprocess("dataset/ISCXIDS2012/testbed-15jun.pcap",
                                           file_list,
                                           100)

    # reader.load()
    # reader.cache("dataset/ISCXIDS2012/cache.json")

    # print("Loading from cache...")
    # start_time = time.time()
    # reader.load_from_cache("dataset/ISCXIDS2012/cache.json")
    # print("time cost:", time.time() - start_time, "s")

    reader.view_csv("dataset/ISCXIDS2012/cache.csv")
    # reader.save_to_csv("dataset/ISCXIDS2012/cache.csv")
