import tensorflow as tf
from tensorflow.keras import Model, layers

from templates.model_template import ModelTemplate


class DCNNModel(ModelTemplate):

    def build(self, *args):
        self.config: DCNNModelConfig
        inputs = layers.Input(shape=(self.config.PKT_EACH_FLOW, self.config.FEATURE_SIZE),
                              dtype=tf.float32)

        hidden_layer = layers.Reshape((self.config.PKT_EACH_FLOW, self.config.FEATURE_SIZE, 1))(inputs)

        hidden_layer = layers.Conv2D(8,
                                     kernel_size=(8, 8),
                                     strides=(2, 2),
                                     padding="SAME",
                                     activation="relu")(hidden_layer)
        hidden_layer = layers.BatchNormalization()(hidden_layer)
        hidden_layer = layers.Conv2D(16,
                                     kernel_size=(8, 8),
                                     strides=(2, 2),
                                     padding="SAME",
                                     activation="relu")(hidden_layer)
        hidden_layer = layers.BatchNormalization()(hidden_layer)
        hidden_layer = layers.MaxPool2D(pool_size=(4, 2),
                                        padding="SAME")(hidden_layer)

        hidden_layer = layers.Flatten()(hidden_layer)
        hidden_layer = layers.Dense(32,
                                    activation="relu")(hidden_layer)
        hidden_layer = layers.Dense(16,
                                    activation="relu")(hidden_layer)
        hidden_layer = layers.Dense(2,
                                    activation='relu')(hidden_layer)
        hidden_layer = layers.Softmax()(hidden_layer)

        outputs = hidden_layer
        self.model = Model(inputs=inputs,
                           outputs=outputs)

        self.model.compile(tf.keras.optimizers.Adam(self.config.LEARNING_RATE),
                           loss=tf.keras.losses.CategoricalCrossentropy(),
                           metrics=[tf.keras.metrics.CategoricalAccuracy(),
                                    tf.keras.metrics.CategoricalCrossentropy()])


class DCNNModelConfig:

    def __init__(self,
                 feature_size,
                 pkt_each_flow,
                 learning_rate
                 ):
        self.FEATURE_SIZE = feature_size
        self.PKT_EACH_FLOW = pkt_each_flow
        self.LEARNING_RATE = learning_rate


if __name__ == '__main__':
    config = DCNNModelConfig(
        155,
        100,
        0.0001
    )

    model = DCNNModel(config)
    model.show_summary(with_plot=True, dpi=150)
