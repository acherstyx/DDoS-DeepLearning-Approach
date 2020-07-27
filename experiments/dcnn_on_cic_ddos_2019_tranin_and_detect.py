from data_loaders.CIC_DDoS_2019.Detect import CICDDoS2019DataLoader, CICDDoS2019DataLoaderConfig
from data_loaders.Predict import PredictDataLoader, PredictDataLoaderConfig, capture_pcap
from data_loaders.utils.load_pcap import feature_extractor
from trainers import UniversalTrainerConfig, UniversalTrainer
from models import DCNNModelConfig, DCNNModel
from utils.file_io import list_file
import pickle
import cv2

pcap_file_directory = "dataset/CIC_DDoS_2019/PCAP/3-11"
files = list_file(pcap_file_directory)
files = [pcap_file_directory + "/" + f for f in files]
files = [x for x in files if 136 >= int(x.split("_")[-1]) >= 105]
# valid_files = [x for x in files if int(x.split("_")[-1]) > 60]

data_loader_config = CICDDoS2019DataLoaderConfig(pcap_file_list=files,
                                                 csv_file="dataset/CIC_DDoS_2019/CSV/03-11/UDP.csv",
                                                 flow_limit=1800,
                                                 flow_pkt_limit=20,
                                                 feature_len=160,
                                                 shuffle_buf_size=3000,
                                                 batch_size=10)

# capture config
CAPTURE_FILE = "logs/CIC_DDoS_2019_Release/capture/current_cap.pcap"
INTERFACE = "Intel(R) Wireless-AC 9462"
COUNT = 10000
TIMEOUT = 10

predict_data_config = PredictDataLoaderConfig(pcap_file_list=[CAPTURE_FILE],
                                              feature_extract_function=feature_extractor,
                                              default_label=[1.0, ],
                                              feature_len=data_loader_config.FEATURE_LEN,
                                              flow_pkt_limit=data_loader_config.FLOW_PKT_LIMIT,
                                              with_flow_id=False)

model_config = DCNNModelConfig(feature_size=data_loader_config.FEATURE_LEN,
                               pkt_each_flow=data_loader_config.FLOW_PKT_LIMIT)

trainer_config = UniversalTrainerConfig(epoch=5,
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
    # trainer.train()
    # trainer.save("logs/CIC_DDoS_2019_Release/model.h5")
    trainer.load("logs/CIC_DDoS_2019_Release/model.h5")

    # capture and predict
    while True:
        capture_pcap(CAPTURE_FILE, INTERFACE, TIMEOUT, COUNT)

        predict_set = PredictDataLoader(predict_data_config)

        trainer.evaluate(predict_set.get_dataset())

        # for flow_id, flow, label in predict_set.get_dataset():
        #     model.get_model().evaluate(flow, label)
