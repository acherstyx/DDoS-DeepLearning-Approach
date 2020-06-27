import tensorflow as tf
from tensorflow.keras.layers import Input, Dense, BatchNormalization
from tensorflow.keras import Model

from templates.model_template import ModelTemplate


class DNNModel(ModelTemplate):
    def build(self, *args):
        self.config: DNNModelConfig

        features = Input(shape=(self.config.FEATURES_LEN,), name="input")

        hidden_layer = features

        for units in self.config.UNITS_LIST:
            hidden_layer = Dense(units, activation='relu')(hidden_layer)
            hidden_layer = BatchNormalization()(hidden_layer)

        predict = Dense(1, activation='sigmoid')(hidden_layer)

        self.model = Model(inputs=features,
                           outputs=predict)


class DNNModelConfig:
    def __init__(self,
                 features_len,
                 units_list):
        self.FEATURES_LEN = features_len
        self.UNITS_LIST = units_list


if __name__ == "__main__":
    config = DNNModelConfig(features_len=104,
                            units_list=[200, 100, 10])
    network = DNNModel(config)
    model = network.get_model()
    model: Model
    model.summary()
