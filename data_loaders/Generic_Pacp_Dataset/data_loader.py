import tensorflow as tf
import numpy as np
from templates import DataLoaderTemplate, ConfigTemplate


class GenericPcapDataLoader(DataLoaderTemplate):
    def load(self, *args):
        self.config: GenericPcapDataLoaderConfig

        if self.config.RETURN_FLOW_ID:
            self.dataset = tf.data.Dataset.from_generator(
                self.generator,
                output_types=(tf.string, tf.float32, tf.float32),
                output_shapes=(
                    (),
                    self.config.FEATURE_SHAPE,
                    (2,)
                )
            ).shuffle(self.config.SHUFFLE_BUFFER).batch(self.config.BATCH_SIZE, drop_remainder=False)
        else:
            self.dataset = tf.data.Dataset.from_generator(
                self.generator,
                output_types=(tf.float32, tf.float32),
                output_shapes=(
                    self.config.FEATURE_SHAPE,
                    (2,)
                )
            ).shuffle(self.config.SHUFFLE_BUFFER).batch(self.config.BATCH_SIZE, drop_remainder=False)

    def generator(self):
        self.config: GenericPcapDataLoaderConfig

        data_dict = self.cache_load(self.config.PICKLE_DUMPED_DATASET_PATH)

        for flow_id, (feature, label) in data_dict.items():
            # zero padding
            feature_shape = np.shape(feature)
            feature = np.pad(feature,
                             ((0, self.config.FEATURE_SHAPE[0] - feature_shape[0]), (0, 0)),
                             mode="constant",
                             constant_values=(0.0, 0.0))
            assert self.config.FEATURE_SHAPE == np.shape(feature)

            if self.config.RETURN_FLOW_ID:
                yield flow_id, feature, label
            else:
                yield feature, label


class GenericPcapDataLoaderConfig(ConfigTemplate):
    def __init__(self,
                 preprocessor_dump_path,
                 feature_shape,
                 batch_size,
                 shuffle_buffer_size,
                 return_flow_id):
        self.PICKLE_DUMPED_DATASET_PATH = preprocessor_dump_path
        self.FEATURE_SHAPE = feature_shape
        self.RETURN_FLOW_ID = return_flow_id
        self.SHUFFLE_BUFFER = shuffle_buffer_size
        self.BATCH_SIZE = batch_size


if __name__ == '__main__':
    from data_loaders.Generic_Pacp_Dataset.pcap_preprocessor import PcapPreprocessor, PcapPreprocessorConfig
    from data_loaders.CIC_DDoS_2019.preprocess_loader import load_label, load_feature, parsing_label

    my_label_dict = load_label("dataset/CIC_DDoS_2019/CSV/03-11/UDP.csv", "cache-label")
    my_feature_list = load_feature(["dataset/CIC_DDoS_2019/PCAP/3-11/SAT-03-11-2018_0107", ],
                                   pkt_in_each_flow_limit=100,
                                   label_dict=my_label_dict,
                                   sample_limit_dict={"BENIGN": 10, "MSSQL": 0, "UDP": 10})
    my_label_dict = parsing_label(my_label_dict)

    my_preprocessor_config = PcapPreprocessorConfig("cache-combine_data", 100)
    my_preprocessor = PcapPreprocessor(my_preprocessor_config, my_label_dict, my_feature_list)

    my_data_loader_config = GenericPcapDataLoaderConfig(preprocessor_dump_path="cache-combine_data",
                                                        feature_shape=(100, 160),
                                                        return_flow_id=True,
                                                        shuffle_buffer_size=20000,
                                                        batch_size=10)
    my_data_loader = GenericPcapDataLoader(my_data_loader_config)

    for my_flow_id, my_feature, my_label in my_data_loader.get_dataset():
        print(my_flow_id, my_feature, my_label)
