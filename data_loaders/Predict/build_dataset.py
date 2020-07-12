import tensorflow as tf
import dpkt
from templates import DataLoaderTemplate, ConfigTemplate


class PredictDataLoader(DataLoaderTemplate):
    def __init__(self, config):
        super(PredictDataLoader, self).__init__(config)

    def load(self):
        self.config: PredictDataLoaderConfig
        self.dataset = tf.data.Dataset.from_generator(self.__predict_data_generator,
                                                      output_types=(tf.float32, tf.float32),
                                                      output_shapes=((self.config.FLOW_PKT_LIMIT,
                                                                      self.config.FEATURE_LEN),
                                                                     (1,))
                                                      ).batch(self.config.BATCH_SIZE)

    def __predict_data_generator(self):
        self.config: PredictDataLoaderConfig

        for feature in self.config.FEATURE_EXTRACTOR(self.config.PCAP_FILE_LIST,
                                                     self.config.FLOW_PKT_LIMIT,
                                                     self.config.CACHE_FILE):
            yield feature, self.config.LABEL


class PredictDataLoaderConfig(ConfigTemplate):
    def __init__(self,
                 pcap_file_list,
                 feature_extract_function,
                 default_label,
                 feature_len,
                 flow_pkt_limit,
                 batch_size=10,
                 cache_file="cache/predict_cache"):
        """

        :param default_label:
        :param pcap_file_list:
        :param feature_extract_function: a function receive ts and buf from a pcap file, return feature vector
        """
        self.PCAP_FILE_LIST = pcap_file_list
        self.FEATURE_EXTRACTOR = feature_extract_function

        self.LABEL = default_label
        # shape
        self.FLOW_PKT_LIMIT = flow_pkt_limit
        self.FEATURE_LEN = feature_len
        self.BATCH_SIZE = batch_size
        self.CACHE_FILE = cache_file
