import dpkt
from .get_label_from_csv import load_label

class PcapPreprocess:
    def __init__(self, pcap_file_list, csv_data, max_flow_sample):
        self.__MAX_FLOW_SAMPLE = max_flow_sample

        self.__opened_pcap_file_list = [dpkt.pcap.Reader(open(file, "rb")) for file in pcap_file_list]

        self.data = {}
