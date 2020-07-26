import tensorflow as tf
import dpkt
from templates import DataLoaderTemplate, ConfigTemplate


class PredictDataLoader(DataLoaderTemplate):
    def __init__(self, config):
        super(PredictDataLoader, self).__init__(config)

    def load(self):
        self.config: PredictDataLoaderConfig
        if self.config.WITH_FLOW_ID:
            self.dataset = tf.data.Dataset.from_generator(self.__predict_data_generator,
                                                          output_types=(tf.string, tf.float32, tf.float32),
                                                          output_shapes=((),
                                                                         (self.config.FLOW_PKT_LIMIT,
                                                                          self.config.FEATURE_LEN),
                                                                         (1,))
                                                          ).batch(self.config.BATCH_SIZE)
        else:
            self.dataset = tf.data.Dataset.from_generator(self.__predict_data_generator,
                                                          output_types=(tf.float32, tf.float32),
                                                          output_shapes=((self.config.FLOW_PKT_LIMIT,
                                                                          self.config.FEATURE_LEN),
                                                                         (1,))
                                                          ).batch(self.config.BATCH_SIZE)

    def __predict_data_generator(self):
        self.config: PredictDataLoaderConfig

        if not self.config.WITH_FLOW_ID:
            for feature in self.config.FEATURE_EXTRACTOR(self.config.PCAP_FILE_LIST,
                                                         self.config.FLOW_PKT_LIMIT,
                                                         self.config.CACHE_FILE,
                                                         self.config.WITH_FLOW_ID):
                yield feature, self.config.LABEL
        else:
            for flow_id, feature in self.config.FEATURE_EXTRACTOR(self.config.PCAP_FILE_LIST,
                                                                  self.config.FLOW_PKT_LIMIT,
                                                                  self.config.CACHE_FILE,
                                                                  self.config.WITH_FLOW_ID):
                yield flow_id, feature, self.config.LABEL


class PredictDataLoaderConfig(ConfigTemplate):
    def __init__(self,
                 pcap_file_list,
                 feature_extract_function,
                 default_label,
                 feature_len,
                 flow_pkt_limit,
                 batch_size=10,
                 with_flow_id=False,
                 cache_file="cache/predict_cache"):
        """

        :param feature_len:
        :param flow_pkt_limit:
        :param batch_size:  default is 10
        :param with_flow_id: if true, dataset will return the flow id of each sample
        :param cache_file: if a file name is given, cache will be enabled
        :param default_label: which label to return with feature
        :param pcap_file_list:  python list of *.pcap file
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
        self.WITH_FLOW_ID = with_flow_id


if __name__ == '__main__':
    from data_loaders.utils.load_pcap import feature_extractor

    predict_data_config = PredictDataLoaderConfig(pcap_file_list=["dataset/DDoSTestSample/SYN_Flooding.pcap"],
                                                  feature_extract_function=feature_extractor,
                                                  default_label=[1.0, ],
                                                  feature_len=160,
                                                  flow_pkt_limit=20)

    predict_set = PredictDataLoader(predict_data_config).get_dataset()

    for key, val in predict_set:
        print(key, val)
