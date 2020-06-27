import tensorflow as tf


class DataLoaderTemplate:
    def __init__(self, config):
        """
        init the data loader
        :param config: configs you want to use in `load` method
        """
        self.config = config
        self.dataset = None
        # the data will be load automatically
        self.load()

    def load(self):
        """
        load data here
        """
        raise NotImplementedError

    def get_dataset(self) -> tf.data.Dataset:
        """
        return the dataset
        :return: dataset
        """
        if self.dataset is None:
            raise Exception("[Error] Load data first.")

        return self.dataset
