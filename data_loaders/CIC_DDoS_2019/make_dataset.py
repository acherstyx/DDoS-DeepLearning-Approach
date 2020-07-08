import tensorflow as tf

from .csv_reader import flow_data_generator
from templates.data_loader_template import DataLoaderTemplate


class FlowData(DataLoaderTemplate):
    def load(self):
        self.config: FlowDataConfig

        normed_data = tf.data.Dataset.from_generator(generator=lambda: flow_data_generator(self.config.CSV_DATA_FILE),
                                                     output_types=(tf.float32, tf.float32),
                                                     output_shapes=(self.config.FEATURES_LEN, ()),
                                                     ).batch(self.config.BATCH_SIZE, drop_remainder=True)

        self.dataset = normed_data


class FlowDataConfig:
    def __init__(self,
                 csv_data_file,
                 features_len,
                 batch_size):
        self.CSV_DATA_FILE = csv_data_file
        self.FEATURES_LEN = features_len
        self.BATCH_SIZE = batch_size


if __name__ == "__main__":
    config = FlowDataConfig("../dataset/sample/pickup.csv", 104, 2)
    FlowData = FlowData(config)
    dataset = FlowData.get_dataset()

    for feature, label in dataset:
        print(feature, label)
