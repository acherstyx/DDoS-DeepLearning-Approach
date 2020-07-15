from data_loaders.CIC_DDoS_2019.Detect import CICDDoS2019DataLoader, CICDDoS2019DataLoaderConfig
from data_loaders.Predict import PredictDataLoader, PredictDataLoaderConfig
from data_loaders.utils.load_pcap import feature_extractor
from trainers import UniversalTrainerConfig, UniversalTrainer
from models import DCNNModelConfig, DCNNModel
from utils.file_io import list_file
import pickle
import cv2

pcap_file_directory = "dataset/CIC_DDoS_2019/PCAP/3-11"
files = list_file(pcap_file_directory)
files = [pcap_file_directory + "/" + f for f in files]
files = [x for x in files if int(x.split("_")[-1]) > 60]
# valid_files = [x for x in files if int(x.split("_")[-1]) > 60]

data_loader_config = CICDDoS2019DataLoaderConfig(pcap_file_list=files,
                                                 csv_file="dataset/CIC_DDoS_2019/CSV/03-11/UDP.csv",
                                                 flow_limit=35000,
                                                 flow_pkt_limit=20,
                                                 feature_len=160,
                                                 shuffle_buf_size=30000,
                                                 batch_size=100)

predict_data_config = PredictDataLoaderConfig(pcap_file_list=["dataset/DDoSTestSample/UDP_Flooding.pcap"],
                                              feature_extract_function=feature_extractor,
                                              default_label=[1.0, ],
                                              feature_len=data_loader_config.FEATURE_LEN,
                                              flow_pkt_limit=data_loader_config.FLOW_PKT_LIMIT)

model_config = DCNNModelConfig(feature_size=data_loader_config.FEATURE_LEN,
                               pkt_each_flow=data_loader_config.FLOW_PKT_LIMIT)

trainer_config = UniversalTrainerConfig(epoch=1,
                                        learning_rate=0.0001)

if __name__ == '__main__':
    flow_set = CICDDoS2019DataLoader(data_loader_config)

    # try:
    #     for flow, label in flow_set.get_dataset():
    #         print(label[0])
    #         cv2.imshow("test", flow[0].numpy())
    #         cv2.waitKey()
    # except KeyboardInterrupt:
    #     pass

    model = DCNNModel(model_config)
    trainer = UniversalTrainer(model.get_model(), flow_set.get_dataset(), trainer_config)
    trainer.train()
    trainer.save("logs/CIC_DDoS_2019/" + trainer.timestamp + ".h5")
    # trainer.load("logs/CIC_DDoS_2019/2020-07-12T17-07-38W.h5")

    predict_set = PredictDataLoader(predict_data_config)

    trainer.evaluate(predict_set.get_dataset())

    for flow, label in flow_set.get_dataset():
        predict_label = model.get_model().predict(flow)
        print(label[:3].numpy(), predict_label[:3])
        cv2.imshow("test", flow[0].numpy())
        cv2.waitKey()
