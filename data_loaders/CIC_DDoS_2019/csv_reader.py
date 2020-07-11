import tensorflow as tf


def select_column_from_csv(csv_data_file, label_name, select_columns):
    return tf.data.experimental.make_csv_dataset(file_pattern=csv_data_file,
                                                 batch_size=1,
                                                 label_name=label_name,
                                                 select_columns=select_columns,
                                                 num_epochs=1)
