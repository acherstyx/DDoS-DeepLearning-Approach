__package__ = "data_loaders.ISCXIDS_2012"

# from scapy.all import PcapReader
import time
import dpkt
import socket
from .xml_reader import ISCXIDS_2012_XML_Reader
import json

MAX_FLOW_SAMPLE = 100
CHECK_INTERVAL = 120  # seconds.


# class ScapyPcapReader:
#     def __init__(self, pcap_file_path):
#         self._file = pcap_file_path
#         opened_file = open(self._file, 'rb')
#         self.packets = PcapReader(opened_file)
#
#         self.data = {}
#
#     def view_data(self):
#         for index, pkt in enumerate(self.packets):
#             if 'TCP' in pkt:
#                 print("-----\n",
#                       "#:", index, '\n',
#                       "time:", time.ctime(int(pkt.time)), "\n",
#                       "time:", time.gmtime(int(pkt.time)), "\n",
#                       "src_port:", pkt['TCP'].sport, "\n",
#                       "dst_port:", pkt['TCP'].dport, "\n",
#                       "pkt_len:", pkt['IP'].len, "\n",
#                       "ip_flag:", pkt['IP'].flags, "\n",
#
#                       # "tcp_len:", pkt['TCP'].len, "\n",
#                       "tcp_flag:", pkt['TCP'].flags, "\n",
#                       "tcp_window_size:", pkt['TCP'].window, "\n",
#                       "tcp_ack:", pkt['TCP'].ack, "\n",
#
#                       "payload:", pkt['TCP'].payload)
#             # pkt.show()
#
#     def unpack_pcap(self):
#         for index, pkt in enumerate(self.packets):
#             # get flow id
#             transport_layer = ""
#             network_layer = ""
#             try:
#                 if 'IP' in pkt:
#                     network_layer = 'IP'
#                 elif 'IPv6' in pkt:
#                     network_layer = 'IPv6'
#                 else:
#                     print("Warning: no IP or IPv6 layer in this pkt")
#                     # pkt.show()
#                     continue
#
#                 if 'TCP' in pkt:
#                     transport_layer = 'TCP'
#                 elif 'UDP' in pkt:
#                     transport_layer = 'UDP'
#                 else:
#                     print("Warning: no TCP or UDP layer in this pkt")
#                     # pkt.show()
#                     continue
#
#                 src_port = pkt[transport_layer].sport
#                 dst_port = pkt[transport_layer].sport
#                 src_ip = pkt[network_layer].src
#                 dst_ip = pkt[network_layer].dst
#                 # print(src_ip, src_port, dst_ip, dst_port)
#             except IndexError as e:
#                 print(e)
#                 # pkt.show()
#                 continue
#
#             flow_id = src_ip + src_port + dst_ip + dst_port
#
#             feature = {}
#             # time
#             if flow_id not in self.data:
#                 self.data[flow_id] = []
#                 feature["time"] = 0
#                 feature["start_time"] = int(pkt.time)
#             else:
#                 feature["time"] = int(pkt.time) - self.data[flow_id][0]["start_time"]


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
        self.bias = {"Normal": 0,
                     "Attack": 0}
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
            src_port = tcp.sport
            dst_port = tcp.dport
            # print(src_ip, dst_ip, dst_port, length, eth.type, ip.get_proto(ip.p).__name__)
            # print(src_ip, dst_ip, dst_port, len(ip.data), len(buf))
            print(src_ip, dst_ip, src_port, dst_port)

    def load(self, with_label=True):
        # load flow label from xml file
        xml_label = ISCXIDS_2012_XML_Reader(self.__xml_label_file)
        self.label = xml_label.get_flow()

        time_start = time.time()
        for index, (ts, buf) in enumerate(self.packet):
            if index % 1000000 == 0:
                print(".", end="")
                # print(
                #     ">total:", index, "\t",
                #     "bias:", self.bias, "\t",
                #     "time cost:", time.time() - time_start, "s\t",
                #     "no match flow:", self.no_match_flow, "\t",
                #     "not ip(v6):", self.no_ip, "\t",
                #     "not tcp/udp:", self.no_tcp_udp, "\t",
                #     "duplicated:", self.duplicated, "\t",
                #     "accept:", self.accepted, "\t",
                # )
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
                    if ts - self.data[flow_id][0]["start_time"] > CHECK_INTERVAL:
                        # move to another key, and remove odl one
                        self.data[flow_id + "start_time"] = self.data[flow_id]
                        self.data[flow_id] = []

                        feature["start_time"] = ts
                        feature["time"] = 0
                    else:
                        self.duplicated += 1
                        continue
                else:
                    feature["time"] = ts - self.data[flow_id][0]["start_time"]

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
            if with_label:
                try:
                    feature["label"] = self.label[flow_id]
                except KeyError:
                    # print(flow_id)
                    self.no_match_flow += 1
                    continue

            if flow_id not in self.data:
                self.data[flow_id] = []
                self.bias[feature["label"]] += 1
            self.data[flow_id].append(feature)
            self.accepted += 1

        print("\nbias:", self.bias, "\t",
              "time cost:", time.time() - time_start, "s\t",
              "no match flow:", self.no_match_flow, "\t",
              "not ip(v6):", self.no_ip, "\t",
              "not tcp/udp:", self.no_tcp_udp, "\t",
              "duplicated:", self.duplicated, "\t",
              "accept:", self.accepted, "\t",
              )
        return self.bias

    def cache_save(self, json_file_path):
        with open(json_file_path, "w") as f:
            json.dump(self.data, f)

    def cache_load(self, json_file_path):
        with open(json_file_path, "r") as f:
            self.data = json.load(f)

    def save_to_csv(self, train_file_path, valid_normal_file_path, valid_attack_file_path, valid_amount):
        f_train = open(train_file_path, "w", encoding='utf-8', newline='')
        f_valid_normal = open(valid_normal_file_path, "w", encoding='utf-8', newline='')
        f_valid_attack = open(valid_attack_file_path, "w", encoding='utf-8', newline='')
        normal_in_valid = attack_in_valid = 0  # counter
        for flow_id, flow in self.data.items():
            if normal_in_valid < valid_amount and flow[0]["label"] == "Normal":
                f_valid_normal.writelines(json.dumps(flow) + "\n")
                normal_in_valid += 1
            elif attack_in_valid < valid_amount and flow[0]["label"] == "Attack":
                f_valid_attack.writelines(json.dumps(flow) + "\n")
                attack_in_valid += 1
            else:
                f_train.writelines(json.dumps(flow) + "\n")

        assert valid_amount == normal_in_valid == attack_in_valid

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

    reader = ISCXIDS2012PcapDataPreprocess("dataset/ISCXIDS2012/testbed-15jun.pcap",
                                           file_list,
                                           100)

    print("Loading form original data...")
    start_time = time.time()
    reader.load()
    print("time cost:", time.time() - start_time, "s")

    print("Making cache...", end="")
    start_time = time.time()
    reader.cache_save("dataset/ISCXIDS2012/cache.json")
    print("time cost:", time.time() - start_time, "s")

    print("Loading from cache...", end="")
    start_time = time.time()
    reader.cache_load("dataset/ISCXIDS2012/cache.json")
    print("time cost:", time.time() - start_time, "s")

    print("Doing statistic...", end="")
    start_time = time.time()
    print(reader.get_statistic(), end="")
    print("time cost:", time.time() - start_time, "s")

    print("Saving to csv...", end="")
    start_time = time.time()
    reader.save_to_csv(train_file_path="../../train.csv",
                       valid_normal_file_path="../../valid_normal.csv",
                       valid_attack_file_path="../../valid_attack.csv",
                       valid_amount=1000)
    print("time cost:", time.time() - start_time, "s")
