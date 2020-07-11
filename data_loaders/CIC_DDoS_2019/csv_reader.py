import tensorflow as tf
import pandas as pd


def select_column_from_csv(csv_data_file, label_name, select_columns):
    return tf.data.experimental.make_csv_dataset(file_pattern=csv_data_file,
                                                 batch_size=1,
                                                 label_name=label_name,
                                                 select_columns=select_columns,
                                                 num_epochs=1)


def load_flow(csv_data_file):
    csv_file = pd.read_csv(csv_data_file)

    return dict(zip(csv_file["Flow ID"], csv_file[" Label"]))


