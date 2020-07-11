__package__ = "data_loaders.CIC_DDoS_2019_Detect"

import tensorflow as tf

from ..CIC_DDoS_2019.csv_reader import load_flow


def load_label(csv_file):
    data = load_flow(csv_file)

    for key, val in data.items():
        print(key)


if __name__ == '__main__':
    load_label("dataset/CIC_DDoS_2019/CSV/03-11/Syn.csv")
