import scapy

from scapy.all import rdpcap


class PcapDataList:
    def __init__(self, pcap_file_path):
        self._file = pcap_file_path
        self.packets = rdpcap(self._file)

    def view_data(self):
        for index, pkt in enumerate(self.packets):
            if 'TCP' in pkt and pkt['TCP'].sport == 80:
                print("-----\n",
                      "#:", index, '\n',
                      "time:", pkt['TCP'].time, "\n",
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


if __name__ == "__main__":
    reader = PcapDataList("./dataset/test.pcap")
    reader.view_data()
