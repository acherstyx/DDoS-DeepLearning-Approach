import tensorflow as tf

from templates.trainer_template import TrainerTemplate


class UniversalTrainer(TrainerTemplate):
    def train(self, *args):
        self.model: tf.keras.Model
        self.data: tf.data.Dataset
        self.config: UniversalTrainerConfig

        self.model.compile("Adam",
                           loss=tf.keras.losses.BinaryCrossentropy(),
                           metrics=[tf.keras.metrics.BinaryCrossentropy()])

        self.model.fit(x=self.data,
                       epochs=5)


class UniversalTrainerConfig:
    def __init__(self):
        pass
