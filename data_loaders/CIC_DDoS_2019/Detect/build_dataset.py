__package__ = "data_loaders.CIC_DDoS_2019.Detect"

from templates import DataLoaderTemplate, ConfigTemplate
from .get_feature_from_pcap import PcapPreprocess, list_file
from utils.normalization.number import *
from utils.normalization.net import *

from data_loaders.utils.load_pcap import get_label
import numpy as np


class CICDDoS2019DataLoader(DataLoaderTemplate):
    def load(self, show_statistic=True):
        self.config: CICDDoS2019DataLoaderConfig

        preprocessor = PcapPreprocess(pcap_file_list=self.config.PCAP_FILE_LIST,
                                      csv_data=self.config.CSV_FILE,
                                      max_flow_sample=self.config.FLOW_PKT_LIMIT,
                                      check_interval=self.config.CHECK_INTERVAL,
                                      label_cache_file=self.config.LABEL_CACHE_FILE)

        try:
            print("Loading feature cache... ", end="")
            preprocessor.cache_load(self.config.FEATURE_CACHE_FILE)
        except FileNotFoundError:
            print("No cache, loading from pcap file... ", end="")
            preprocessor.load(number_limit=self.config.FLOW_LIMIT)
            preprocessor.cache_dump(self.config.FEATURE_CACHE_FILE)
        print("Done")
        print(preprocessor.get_statistic())
        data_dict = preprocessor.get_dataset()

        self.dataset = tf.data.Dataset.from_generator(lambda: self.__data_generator(data_dict),
                                                      output_types=(tf.float32, tf.float32),
                                                      output_shapes=((self.config.FLOW_PKT_LIMIT,
                                                                      self.config.FEATURE_LEN),
                                                                     (1,)
                                                                     )
                                                      ).shuffle(self.config.SHUFFLE_BUF).batch(self.config.BATCH_SIZE)

    def __data_generator(self, data_dict):
        data_dict: dict
        for flow_id, flow_feature in data_dict.items():
            yield self.__parsing_packet(flow_feature, with_label=True)

    def __parsing_packet(self, flow, with_label):
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
            if flow_num >= self.config.FLOW_PKT_LIMIT:
                break

        # zero padding for missing packet
        pkt_list = np.pad(pkt_list,
                          ((0, self.config.FLOW_PKT_LIMIT - flow_num), (0, 0)),
                          mode="constant",
                          constant_values=(0.0, 0.0))
        try:
            assert np.shape(pkt_list) == (self.config.FLOW_PKT_LIMIT, len(feature))
        except AssertionError:
            print(np.shape(pkt_list))
            print(self.config.FLOW_PKT_LIMIT, len(feature))
            raise AssertionError
        if with_label:
            return pkt_list, label
        else:
            return pkt_list


class CICDDoS2019DataLoaderConfig(ConfigTemplate):
    def __init__(self,
                 pcap_file_list,
                 csv_file,
                 flow_limit,
                 flow_pkt_limit,
                 feature_len,
                 shuffle_buf_size,
                 batch_size=1,
                 check_interval=10,
                 label_cache_file="cache/label_cache",
                 feature_cache_file="cache/feature_cache",
                 ):
        """

        :param pcap_file_list:
        :param csv_file:
        :param flow_limit: sample limit of each label
        :param flow_pkt_limit:  packet limit of each flow
        """
        self.PCAP_FILE_LIST = pcap_file_list
        self.CSV_FILE = csv_file
        self.FLOW_LIMIT = flow_limit
        # shape of sample
        self.FLOW_PKT_LIMIT = flow_pkt_limit
        self.FEATURE_LEN = feature_len

        self.CHECK_INTERVAL = check_interval
        # cache
        self.LABEL_CACHE_FILE = label_cache_file
        self.FEATURE_CACHE_FILE = feature_cache_file
        self.SHUFFLE_BUF = shuffle_buf_size
        self.BATCH_SIZE = batch_size


if __name__ == '__main__':
    pcap_file_directory = "dataset/CIC_DDoS_2019/PCAP/3-11"
    files = list_file(pcap_file_directory)
    files = [pcap_file_directory + "/" + f for f in files]
    files = [x for x in files if int(x.split("_")[-1]) > 136]

    config = CICDDoS2019DataLoaderConfig(pcap_file_list=files,
                                         csv_file="dataset/CIC_DDoS_2019/CSV/03-11/Syn.csv",
                                         flow_limit=35000,
                                         flow_pkt_limit=20,
                                         feature_len=160,
                                         shuffle_buf_size=60000)
    flow_set = CICDDoS2019DataLoader(config)

    import cv2

    for feature, label in flow_set.get_dataset():
        print(label)
        cv2.imshow("test", feature[0].numpy())
        cv2.waitKey(1)
