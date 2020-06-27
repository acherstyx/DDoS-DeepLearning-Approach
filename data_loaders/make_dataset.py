import tensorflow as tf
from collections import OrderedDict

from data_loaders.csv_reader import flow_data_generator
from templates.data_loader_template import DataLoaderTemplate

from utils.normalization import *


class FlowData(DataLoaderTemplate):
    def load(self):
        self.config: FlowDataConfig

        gen = flow_data_generator(self.config.CSV_DATA_FILE)

        normed_data = tf.data.Dataset.from_generator(generator=lambda: gen,
                                                     output_types=(tf.float32, tf.float32),
                                                     output_shapes=((self.config.FEATURES_LEN,), ()),
                                                     )

        self.dataset = normed_data


class FlowDataConfig:
    def __init__(self,
                 csv_data_file,
                 features_len):
        self.CSV_DATA_FILE = csv_data_file
        self.FEATURES_LEN = features_len


if __name__ == "__main__":
    config = FlowDataConfig("../dataset/sample/pickup.csv", 104)
    FlowData = FlowData(config)
    dataset = FlowData.get_dataset()

    for feature, label in dataset:
        print(feature, label)
