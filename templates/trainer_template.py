import os
import tensorflow as tf

from datetime import datetime


class TrainerTemplate:
    def __init__(self, model, data, config):
        """
        init the trainer
        :param model:
        :param data: data loader
        :param config: config you want to use
        """
        self.model = model
        self.data = data
        self.config = config

        self.callbacks = []
        self.metrics = []

        # timestamp for log file
        self.timestamp = "{0:%Y-%m-%dT%H-%M-%SW}".format(datetime.now())
        self.checkpoint = None

    def train(self, *args):
        """
        train your model here
        """
        raise NotImplementedError

    def save(self, path: str, *args):
        self.model: tf.keras.Model
        try:
            self.model.save_weights(path)
        except OSError:
            os.makedirs(os.path.join(*os.path.split(path)[:-1]))
            self.model.save_weights(path)

    def load(self, path, *args):
        self.model: tf.keras.Model
        self.model.load_weights(path)

    def predict(self, *args):
        pass
