from models.dnn import DNNModel, DNNModelConfig
from data_loaders.CIC_DDoS_2019.make_dataset import FlowData, FlowDataConfig
from trainers.universal_trainer import UniversalTrainer

dataset_config = FlowDataConfig(csv_data_file="../dataset/sample/pickup.csv",
                                features_len=104,
                                batch_size=10)
model_config = DNNModelConfig(features_len=104,
                              units_list=[200, 100, 10])

if __name__ == "__main__":
    dataset = FlowData(dataset_config).get_dataset()
    model = DNNModel(model_config).get_model()

    trainer = UniversalTrainer(model, dataset, None)
    trainer.train()
