from data_loaders.ISCXIDS_2012.make_dataset import ISCXIDS2012DataLoader, ISCXIDS2012DataLoaderConfig
from models.dcnn import DCNNModel, DCNNModelConfig
from trainers.universal_trainer import UniversalTrainer, UniversalTrainerConfig

data_loader_config = ISCXIDS2012DataLoaderConfig(
    "dataset/ISCXIDS2012/testbed-15jun.pcap",
    ["dataset/ISCXIDS2012/labeled_flows_xml/TestbedThuJun17-3Flows.xsd",
     "dataset/ISCXIDS2012/labeled_flows_xml/TestbedTueJun15-1Flows.xml",
     "dataset/ISCXIDS2012/labeled_flows_xml/TestbedTueJun15-2Flows.xml",
     "dataset/ISCXIDS2012/labeled_flows_xml/TestbedTueJun15-3Flows.xml"],
    "dataset/ISCXIDS2012/cache.json",
    100,
    100,
    155
)

model_config = DCNNModelConfig(
    data_loader_config.FEATURE_LEN,
    data_loader_config.PKT_EACH_FLOW
)

if __name__ == '__main__':
    dataset = ISCXIDS2012DataLoader(data_loader_config).get_dataset()
    model = DCNNModel(model_config).get_model()

    trainer = UniversalTrainer(model, dataset, None)
    trainer.train()
