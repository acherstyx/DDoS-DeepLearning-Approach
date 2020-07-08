import tensorflow as tf

from templates.trainer_template import TrainerTemplate


class UniversalTrainer(TrainerTemplate):
    def train(self, *args):
        self.model: tf.keras.Model
        self.data: tf.data.Dataset
        self.config: UniversalTrainerConfig

        self.model.compile(tf.keras.optimizers.Adam(self.config.LEARNING_RATE),
                           loss=tf.keras.losses.BinaryCrossentropy(),
                           metrics=[tf.keras.metrics.BinaryAccuracy(),
                                    tf.keras.metrics.BinaryCrossentropy()])

        self.model.fit(x=self.data,
                       epochs=self.config.EPOCH)

    def evaluate(self, eval_set):
        self.model: tf.keras.Model

        self.model.compile(tf.keras.optimizers.Adam(self.config.LEARNING_RATE),
                           loss=tf.keras.losses.BinaryCrossentropy(),
                           metrics=[tf.keras.metrics.BinaryAccuracy(),
                                    tf.keras.metrics.BinaryCrossentropy()])

        return self.model.evaluate(eval_set)


class UniversalTrainerConfig:
    def __init__(self,
                 epoch,
                 learning_rate):
        self.EPOCH = epoch
        self.LEARNING_RATE = learning_rate
