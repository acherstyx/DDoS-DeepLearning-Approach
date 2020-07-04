__package__ = "data_loaders.ISCXIDS_2012"

import tensorflow as tf
import numpy as np

from templates.data_loader_template import DataLoaderTemplate
from .unpack_pcap import ISCXIDS2012PcapDataPreprocess

from utils.normalization.number import *
from utils.normalization.net import *
import cv2


def get_label(label_str):
    if label_str == "Normal":
        return 0.0
    else:
        return 1.0


class ISCXIDS2012DataLoader(DataLoaderTemplate):
    def data_generator(self):
        self.config: ISCXIDS2012DataLoaderConfig
        preprocessor = ISCXIDS2012PcapDataPreprocess(self.config.PCAP_FILE,
                                                     self.config.XML_FILE_LIST,
                                                     self.config.MAX_FLOW_SAMPLE)
        try:
            # trying to load cache file
            preprocessor.load_from_cache(self.config.CACHE_FILE)
        except Exception:
            preprocessor.load()
            preprocessor.cache(self.config.CACHE_FILE)

        init_dataset = preprocessor.get_data()

        # normalize features
        for flow_id, flow in init_dataset.items():
            pkt_list = []
            label = None
            feature = None
            flow_num = 0
            for pkt in flow:
                time = norm_number_clipped(int(pkt["time"] * 1000000000), 32)
                pkt_len = norm_number_clipped(pkt["pkt_len"], 16)
                ip_flags = norm_number(pkt["ip_flags"], 16)
                protocols = norm_protocol_str(pkt["protocols"])
                tcp_len = norm_number(pkt["tcp_len"], 16)
                tcp_ack = norm_number(pkt["tcp_ack"], 32)
                tcp_flags = norm_number(pkt["tcp_flags"], 8)
                tcp_win_size = norm_number(pkt["tcp_win_size"], 16)
                udp_len = norm_number(pkt["udp_len"], 16)

                feature = time + pkt_len + ip_flags + protocols + tcp_len + tcp_ack + tcp_flags + tcp_win_size + udp_len
                label = get_label(pkt["label"])
                flow_num += 1
                if flow_num >= self.config.PKT_EACH_FLOW:
                    break

                pkt_list.append(feature)
            # zero padding for missing packet
            pkt_list = np.pad(pkt_list, ((0, self.config.PKT_EACH_FLOW - flow_num), (0, 0)))
            assert np.shape(pkt_list) == (self.config.PKT_EACH_FLOW, len(feature))

            yield pkt_list, label

    def load(self):
        self.config: ISCXIDS2012DataLoaderConfig
        dataset = tf.data.Dataset.from_generator(generator=self.data_generator,
                                                 output_types=(tf.float32, tf.float32),
                                                 output_shapes=((self.config.PKT_EACH_FLOW, self.config.FEATURE_LEN),
                                                                ()),
                                                 ).batch(self.config.BATCH_SIZE, drop_remainder=True)
        self.dataset = dataset


class ISCXIDS2012DataLoaderConfig:
    def __init__(self,
                 pcap_file,
                 xml_file_list,
                 cache_file,
                 batch_size,
                 pkt_each_flow,
                 feature_len,
                 ):
        self.PCAP_FILE = pcap_file
        self.XML_FILE_LIST = xml_file_list
        self.BATCH_SIZE = batch_size
        self.CACHE_FILE = cache_file
        self.PKT_EACH_FLOW = pkt_each_flow
        self.FEATURE_LEN = feature_len
        self.MAX_FLOW_SAMPLE = pkt_each_flow  # same to pkt_each_flow


if __name__ == '__main__':
    config = ISCXIDS2012DataLoaderConfig(
        pcap_file="dataset/ISCXIDS2012/testbed-15jun.pcap",
        xml_file_list=[
            "dataset/ISCXIDS2012/labeled_flows_xml/TestbedMonJun14Flows.xml",
            "dataset/ISCXIDS2012/labeled_flows_xml/TestbedTueJun15-1Flows.xml",
            "dataset/ISCXIDS2012/labeled_flows_xml/TestbedTueJun15-2Flows.xml",
            "dataset/ISCXIDS2012/labeled_flows_xml/TestbedTueJun15-3Flows.xml"
        ],
        cache_file="dataset/ISCXIDS2012/cache.json",
        batch_size=10,
        pkt_each_flow=100,
        feature_len=155,
    )
    data_loader = ISCXIDS2012DataLoader(config)

    for flow_feature, label in data_loader.get_dataset():
        # print(flow_feature)
        # print(label)
        cv2.imshow("sample", flow_feature[0].numpy())
        cv2.waitKey(1)
    cv2.waitKey()
