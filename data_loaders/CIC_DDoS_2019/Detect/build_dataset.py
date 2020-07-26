__package__ = "data_loaders.CIC_DDoS_2019.Detect"

import numpy as np
import logging
from templates import DataLoaderTemplate, ConfigTemplate
from .preprocess import PcapPreprocess, list_file
from utils.normalization.net import *

from data_loaders.utils.load_pcap import parsing_packet

logger = logging.getLogger(__name__)


class CICDDoS2019DataLoader(DataLoaderTemplate):
    def load(self, show_statistic=True):
        self.config: CICDDoS2019DataLoaderConfig

        preprocessor = PcapPreprocess(pcap_file_list=self.config.PCAP_FILE_LIST,
                                      csv_file=self.config.CSV_FILE,
                                      max_flow_sample=self.config.FLOW_PKT_LIMIT,
                                      check_interval=self.config.CHECK_INTERVAL,
                                      flow_limit=self.config.FLOW_LIMIT
                                      )

        preprocessor.load()

        logger.info("Flow label bias: %s", preprocessor.get_statistic())
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
            sample = parsing_packet(flow_feature, with_label=True, packet_limit=self.config.FLOW_PKT_LIMIT)
            try:
                assert np.shape(sample[0]) == (self.config.FLOW_PKT_LIMIT, self.config.FEATURE_LEN)
            except AssertionError:
                logger.error("Shape of data mismatch: expect %s, get %s",
                             (self.config.FLOW_PKT_LIMIT, self.config.FEATURE_LEN),
                             np.shape(sample[0]))
                raise AssertionError
            yield sample


class CICDDoS2019DataLoaderConfig(ConfigTemplate):
    def __init__(self,
                 pcap_file_list,
                 csv_file,
                 flow_limit,
                 flow_pkt_limit,
                 feature_len,
                 shuffle_buf_size,
                 batch_size=1,
                 check_interval=10
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

    for sample_feature, sample_label in flow_set.get_dataset():
        print(sample_label)
        cv2.imshow("test", sample_feature[0].numpy())
        cv2.waitKey(1)
