import os

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
from data_loaders.ISCXIDS_2012.make_dataset import ISCXIDS2012DataLoader, ISCXIDS2012DataLoaderConfig
from models.dcnn import DCNNModel, DCNNModelConfig
from trainers.universal_trainer import UniversalTrainer, UniversalTrainerConfig

data_loader_config = ISCXIDS2012DataLoaderConfig(
    pcap_file="dataset/ISCXIDS2012/testbed-15jun.pcap",
    xml_file_list=["dataset/ISCXIDS2012/labeled_flows_xml/TestbedMonJun14Flows.xml",
                   "dataset/ISCXIDS2012/labeled_flows_xml/TestbedTueJun15-1Flows.xml",
                   "dataset/ISCXIDS2012/labeled_flows_xml/TestbedTueJun15-2Flows.xml",
                   "dataset/ISCXIDS2012/labeled_flows_xml/TestbedTueJun15-3Flows.xml"],
    batch_size=50,
    pkt_each_flow=100,
    feature_len=155,
    shuffle_buffer_size=10000,
    valid_amount=1000
)

model_config = DCNNModelConfig(
    data_loader_config.FEATURE_LEN,
    data_loader_config.PKT_EACH_FLOW
)

trainer_config = UniversalTrainerConfig(
    epoch=5,
    learning_rate=0.001
)

if __name__ == '__main__':
    train_set, valid_normal_set, valid_attack_set = ISCXIDS2012DataLoader(data_loader_config).get_dataset()
    model = DCNNModel(model_config).get_model()

    trainer = UniversalTrainer(model, train_set, trainer_config)
    trainer.train()

    trainer.save("./logs/ISCXIDS2012/" + trainer.timestamp + ".h5")

    print("\n=====Test attack flow=====")
    trainer.evaluate(valid_attack_set)
    print("\n=====Test normal flow=====")
    trainer.evaluate(valid_normal_set)

    print("On train.")
    counter = 0
    for test_sample_feature, test_sample_label in train_set:
        # print(test_sample_feature)
        test_sample_predict = model.predict(test_sample_feature)
        for a, b in zip(test_sample_label, test_sample_predict):
            print(a.numpy(), b)
        counter += 1
        if counter > 2:
            break
