__package__ = "data_loaders.ISCXIDS_2012"

import tensorflow as tf
import numpy as np

from templates.data_loader_template import DataLoaderTemplate
from .unpack_pcap import ISCXIDS2012PcapDataPreprocess

from utils.normalization.number import *
from utils.normalization.net import *
import cv2
import json
import random


def get_label(label_str):
    if label_str == "Normal":
        return 0.0
    else:
        return 1.0


class ISCXIDS2012DataLoader(DataLoaderTemplate):
    def __init__(self, config):
        super(ISCXIDS2012DataLoader, self).__init__(config)
        self.statistic = {"Normal": 1, "Attack": 1}
        self.validation = None

    def rand_abort(self, flow_type):
        """
        adjust flow bias
        :param flow_type:
        :return: if return True, you should throw away that flow
        """
        if flow_type == "Normal":
            if random.random() > self.statistic["Normal"] / (self.statistic["Normal"] + self.statistic["Attack"]):
                return False
            else:
                return True
        elif flow_type == "Attack":
            if random.random() > self.statistic["Attack"] / (self.statistic["Normal"] + self.statistic["Attack"]):
                return False
            else:
                return True

    def data_generator(self, opened_csv_file):
        self.config: ISCXIDS2012DataLoaderConfig

        # normalize features
        for line in opened_csv_file:
            flow = json.loads(line)
            pkt_list = []
            label = None
            feature = None
            flow_num = 0

            if self.rand_abort(flow[0]["label"]):
                continue

            self.statistic[flow[0]["label"]] += 1

            for pkt in flow:
                time = norm_number_clipped(int(pkt["time"] * 1000000), 32)
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
                pkt_list.append(feature)
                if flow_num >= self.config.PKT_EACH_FLOW:
                    break

            # zero padding for missing packet
            pkt_list = np.pad(pkt_list,
                              ((0, self.config.PKT_EACH_FLOW - flow_num), (0, 0)),
                              mode="constant",
                              constant_values=(0.0, 0.0))
            try:
                assert np.shape(pkt_list) == (self.config.PKT_EACH_FLOW, len(feature))
            except AssertionError:
                print(np.shape(pkt_list))
                print(self.config.PKT_EACH_FLOW, len(feature))
                raise AssertionError

            yield pkt_list, label

    def load(self):
        self.config: ISCXIDS2012DataLoaderConfig
        # doing preprocess
        preprocessor = ISCXIDS2012PcapDataPreprocess(self.config.PCAP_FILE,
                                                     self.config.XML_FILE_LIST,
                                                     self.config.MAX_FLOW_SAMPLE)

        try:
            # trying to open csv file
            csv_train = open(self.config.CSV_TRAIN_FILE)
            csv_valid_normal = open(self.config.CSV_VALID_NORMAL_FILE)
            csv_valid_attack = open(self.config.CSV_VALID_ATTACK_FILE)
            print("Loaded.")
        except Exception:
            print("Can't open csv file, loading from cache...")
            try:
                preprocessor.cache_load(self.config.CACHE_FILE)
                preprocessor.save_to_csv(self.config.CSV_TRAIN_FILE)
            except Exception:
                print("No cache for dataset, loading from original data...")
                preprocessor.load()
                preprocessor.cache_save(self.config.CACHE_FILE)
                preprocessor.save_to_csv(train_file_path=self.config.CSV_TRAIN_FILE,
                                         valid_normal_file_path=self.config.CSV_VALID_NORMAL_FILE,
                                         valid_attack_file_path=self.config.CSV_VALID_ATTACK_FILE,
                                         valid_amount=self.config.VALID_AMOUNT)
                print("Loaded.")
            csv_train = open(self.config.CSV_TRAIN_FILE)
            csv_valid_normal = open(self.config.CSV_VALID_NORMAL_FILE)
            csv_valid_attack = open(self.config.CSV_VALID_ATTACK_FILE)

        dataset_train = tf.data.Dataset.from_generator(generator=lambda: self.data_generator(csv_train),
                                                       output_types=(tf.float32, tf.float32),
                                                       output_shapes=(
                                                           (self.config.PKT_EACH_FLOW, self.config.FEATURE_LEN),
                                                           ()),
                                                       ) \
            .shuffle(self.config.SHUFFLE_BUFFER) \
            .batch(self.config.BATCH_SIZE, drop_remainder=True)
        dataset_valid_normal = tf.data.Dataset.from_generator(generator=lambda: self.data_generator(csv_valid_normal),
                                                              output_types=(tf.float32, tf.float32),
                                                              output_shapes=(
                                                                  (self.config.PKT_EACH_FLOW, self.config.FEATURE_LEN),
                                                                  ()),
                                                              ).batch(10)
        dataset_valid_attack = tf.data.Dataset.from_generator(generator=lambda: self.data_generator(csv_valid_attack),
                                                              output_types=(tf.float32, tf.float32),
                                                              output_shapes=(
                                                                  (self.config.PKT_EACH_FLOW, self.config.FEATURE_LEN),
                                                                  ()),
                                                              ).batch(10)
        self.dataset = (dataset_train, dataset_valid_normal, dataset_valid_attack)


class ISCXIDS2012DataLoaderConfig:
    def __init__(self,
                 pcap_file,
                 xml_file_list,
                 batch_size,
                 pkt_each_flow,
                 feature_len,
                 shuffle_buffer_size,
                 valid_amount,
                 csv_train_file="train.csv",
                 csv_valid_normal_file="valid_normal.csv",
                 csv_valid_attack_file="valid_attack.csv",
                 cache_file="cache.json"
                 ):
        self.PCAP_FILE = pcap_file
        self.XML_FILE_LIST = xml_file_list
        self.BATCH_SIZE = batch_size
        self.CACHE_FILE = cache_file
        self.PKT_EACH_FLOW = pkt_each_flow
        self.FEATURE_LEN = feature_len  # match the length of feature list
        self.MAX_FLOW_SAMPLE = pkt_each_flow  # same to pkt_each_flow
        self.CSV_TRAIN_FILE = csv_train_file
        self.SHUFFLE_BUFFER = shuffle_buffer_size
        self.CSV_VALID_NORMAL_FILE = csv_valid_normal_file
        self.CSV_VALID_ATTACK_FILE = csv_valid_attack_file
        self.VALID_AMOUNT = valid_amount


if __name__ == '__main__':
    config = ISCXIDS2012DataLoaderConfig(
        pcap_file="dataset/ISCXIDS2012/testbed-15jun.pcap",
        xml_file_list=[
            "dataset/ISCXIDS2012/labeled_flows_xml/TestbedMonJun14Flows.xml",
            "dataset/ISCXIDS2012/labeled_flows_xml/TestbedTueJun15-1Flows.xml",
            "dataset/ISCXIDS2012/labeled_flows_xml/TestbedTueJun15-2Flows.xml",
            "dataset/ISCXIDS2012/labeled_flows_xml/TestbedTueJun15-3Flows.xml"
        ],
        batch_size=10,
        pkt_each_flow=100,
        feature_len=155,
        shuffle_buffer_size=300,
        valid_amount=1000
    )
    data_loader = ISCXIDS2012DataLoader(config)

    # test the bias of normal and attack flow get from the dataset
    flow_sample_statistic = {"Normal": 1, "Attack": 1}
    counter = 0

    train, valid_normal, valid_attack = data_loader.get_dataset()
    for flow_feature, flow_label in train:
        for sample in flow_label:
            if sample == 1:
                flow_sample_statistic["Attack"] += 1
            elif sample == 0:
                flow_sample_statistic["Normal"] += 1
            else:
                raise ValueError

            counter += 1
            if counter % 10000 == 0:
                print(flow_sample_statistic)
