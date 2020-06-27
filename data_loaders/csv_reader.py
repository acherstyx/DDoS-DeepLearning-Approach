import tensorflow as tf
from collections import OrderedDict
from utils.normalization.ip import *

LABEL_NAME = "Label"
SELECT_COLUMNS = ["Label",
                  "Source IP", "Source Port",
                  "Destination IP", "Destination Port",
                  "Protocol",
                  "Timestamp",
                  "Flow Duration",
                  ]
COLUMN_DICT = dict(zip(SELECT_COLUMNS, list(range(len(SELECT_COLUMNS)))))


def __load_flow_data(csv_data_file, label_name, select_columns):
    return tf.data.experimental.make_csv_dataset(file_pattern=csv_data_file,
                                                 batch_size=1,
                                                 label_name=label_name,
                                                 select_columns=select_columns,
                                                 num_epochs=1,
                                                 shuffle=True,
                                                 shuffle_buffer_size=1000)


def flow_data_generator(csv_data_file):
    csv_dataset = __load_flow_data(csv_data_file, LABEL_NAME, SELECT_COLUMNS)

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



if __name__ == "__main__":
    for a_feature_list, a_label in flow_data_generator("../dataset/sample/pickup.csv"):
        print(len(a_feature_list), a_label, a_feature_list)
