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


if __name__ == "__main__":
    from models.dnn import DNNModel, DNNModelConfig
    from data_loaders.make_dataset import FlowData, FlowDataConfig

    dataset_config = FlowDataConfig(csv_data_file="../dataset/sample/pickup.csv",
                                    features_len=104,
                                    batch_size=10)
    model_config = DNNModelConfig(features_len=104,
                                  units_list=[200, 100, 10])
    dataset = FlowData(dataset_config).get_dataset()
    model = DNNModel(model_config).get_model()

    trainer = UniversalTrainer(model, dataset, None)
    trainer.train()
