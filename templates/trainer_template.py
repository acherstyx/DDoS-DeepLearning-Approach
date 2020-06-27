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
        self.timestamp = "{0:%Y-%m-%dT%H-%M-%S/}".format(datetime.now())
        self.checkpoint = None

    def train(self, *args):
        """
        train your model here
        """
        raise NotImplementedError

    def save(self, *args):
        pass

    def predict(self, *args):
        pass
