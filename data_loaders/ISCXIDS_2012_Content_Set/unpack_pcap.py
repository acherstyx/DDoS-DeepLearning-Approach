__package__ = "data_loaders.ISCXIDS_2012"

# from scapy.all import PcapReader
import time
import dpkt
import socket
from ..ISCXIDS_2012.xml_reader import ISCXIDS_2012_XML_Reader
import json

MAX_FLOW_SAMPLE = 100


class ISCXIDS2012PcapDataPreprocess:
    def __init__(self, pcap_file_path, xml_label_file_list):
        # save file path
        self.__pcap_file = pcap_file_path
        self.__xml_label_file = xml_label_file_list
        # statistic
        self.no_ip = 0
        self.no_tcp_udp = 0

        # open pcap file
        openfile = open(pcap_file_path, 'rb')
        self.packet = dpkt.pcap.Reader(openfile)

        self.data = {}
        self.label = None

    @staticmethod
    def __translate_ip(ip):
        try:
            return socket.inet_ntop(socket.AF_INET, ip)
        except ValueError:
            return socket.inet_ntop(socket.AF_INET6, ip)

    def load(self, with_label=True):
        # load flow label from xml file
        if with_label:
            # load label from xml file
            xml_label = ISCXIDS_2012_XML_Reader(self.__xml_label_file)
            self.label = xml_label.get_flow()

        for index, (ts, buf) in enumerate(self.packet):
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
            print(bytes(eth).decode("utf-8"))

    def cache_save(self, json_file_path):
        with open(json_file_path, "w") as f:
            json.dump(self.data, f)

    def cache_load(self, json_file_path):
        with open(json_file_path, "r") as f:
            self.data = json.load(f)

    def get_data(self):
        return self.data

    def get_statistic(self):
        statistic = {"Attack": 0, "Normal": 0}
        for flow_id, flow in self.data.items():
            statistic[flow[0]["label"]] += 1
        return statistic


if __name__ == "__main__":
    file_list = ["dataset/ISCXIDS2012/labeled_flows_xml/TestbedMonJun14Flows.xml",
                 "dataset/ISCXIDS2012/labeled_flows_xml/TestbedTueJun15-1Flows.xml",
                 "dataset/ISCXIDS2012/labeled_flows_xml/TestbedTueJun15-2Flows.xml",
                 "dataset/ISCXIDS2012/labeled_flows_xml/TestbedTueJun15-3Flows.xml"]

    dataset = ISCXIDS2012PcapDataPreprocess("dataset/ISCXIDS2012/testbed-15jun.pcap",
                                            file_list)
    dataset.load(with_label=False)