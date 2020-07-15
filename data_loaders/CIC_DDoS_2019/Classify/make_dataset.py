import tensorflow as tf

from collections import OrderedDict
from data_loaders.CIC_DDoS_2019.csv_reader import select_column_from_csv
from templates.data_loader_template import DataLoaderTemplate

from utils.normalization.net import *


def flow_data_generator(csv_data_file):
    label_name = "Label"
    select_columns = ["Label",
                      "Source IP", "Source Port",
                      "Destination IP", "Destination Port",
                      "Protocol",
                      "Timestamp",
                      "Flow Duration",
                      ]

    csv_dataset = select_column_from_csv(csv_data_file, label_name, select_columns)

    label_dict = {"BENIGN": 0.0, "Portmap": 1.0}

    for features, label in csv_dataset:
        features: OrderedDict
        # tf.print(label, list(features.values()))

        # feature
        features: list = [x[0] for x in list(features.values())]

        src_ip = norm_ip(features[0].numpy().decode('utf-8'))
        src_port = norm_port(features[1].numpy())
        dest_ip = norm_ip(features[2].numpy().decode('utf-8'))
        dest_port = norm_port(features[3].numpy())
        protocol = norm_protocol(features[4].numpy())


        # label
        label = label_dict[label.numpy()[0].decode('utf-8')]

        yield src_ip + src_port + dest_ip + dest_port + protocol, label


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
    config = FlowDataConfig("dataset/sample/pickup.csv", 104, 2)
    FlowData = FlowData(config)
    dataset = FlowData.get_dataset()

    for feature, label in dataset:
        print(feature, label)
