from templates import PreprocessorTemplate, ConfigTemplate
from tqdm import tqdm


class PcapPreprocessor(PreprocessorTemplate):
    def __init__(self, config, label, feature):
        super(PcapPreprocessor, self).__init__(config)
        self.config: PcapPreprocessorConfig

        # python dict with format: {"<flow_id>", "<label>"}
        self.label = label
        # iterable object, return format: ["<flow-id", <feature>]
        self.feature = feature

        # store data in python dict
        # {"<flow_id>": [[<feature>], <label>]}

        if not self.config.REWRITE:
            self.data_dict = self.cache_try_load(self.config.COMBINED_DATASET_SAVE_PATH, self.combine)
        else:
            self.data_dict = self.combine()
            self.cache_save(self.data_dict, self.config.COMBINED_DATASET_SAVE_PATH)

    def combine(self):
        self.config: PcapPreprocessorConfig
        data_dict = {}
        for flow_id, feature in tqdm(self.feature, ncols=100):
            if flow_id in data_dict:
                if len(data_dict[flow_id][0]) > self.config.PKT_IN_EACH_FLOW_LIMIT:
                    continue
                data_dict[flow_id][0].append(feature)
            else:
                if flow_id in self.label:
                    data_dict[flow_id] = [[feature], self.label[flow_id]]
                else:
                    continue
        # print("Combine_dict is:", data_dict)
        return data_dict

    def get_data_dict(self):
        return self.data_dict


class PcapPreprocessorConfig(ConfigTemplate):
    def __init__(self,
                 data_dump_path,
                 pkt_in_each_flow_limit,
                 rewrite=True):
        self.COMBINED_DATASET_SAVE_PATH = data_dump_path
        self.PKT_IN_EACH_FLOW_LIMIT = pkt_in_each_flow_limit
        self.REWRITE = rewrite


if __name__ == '__main__':
    from data_loaders.CIC_DDoS_2019.preprocess_loader import load_label, load_feature, parsing_label
    import numpy as np

    my_label_dict = load_label("dataset/CIC_DDoS_2019/CSV/03-11/UDP.csv", "cache-label")
    my_feature_list = load_feature(["dataset/CIC_DDoS_2019/PCAP/3-11/SAT-03-11-2018_0107", ],
                                   pkt_in_each_flow_limit=100,
                                   label_dict=my_label_dict,
                                   sample_limit_dict={"BENIGN": 10, "MSSQL": 0, "UDP": 10})
    my_label_dict = parsing_label(my_label_dict)

    my_preprocessor_config = PcapPreprocessorConfig("cache-combine_data", 100)
    my_preprocessor = PcapPreprocessor(my_preprocessor_config, my_label_dict, my_feature_list)

    my_data_dict = my_preprocessor.get_data_dict()

    for k, v in my_data_dict.items():
        print(k, np.shape(v[0]), v[1])
