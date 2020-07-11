__package__ = "data_loaders.CIC_DDoS_2019_Detect"

import dpkt
from ..CIC_DDoS_2019.csv_reader import load_flow
from ..utils.load_pcap import get_flow_id
from ..utils.load_pcap import unpack_feature
import os
import json
from tqdm import tqdm


class PcapPreprocess:
    def __init__(self,
                 pcap_file_list,
                 csv_data,
                 max_flow_sample,
                 check_interval,
                 cache_file_path="label_cache.json"):
        # get label from csv

        try:
            print("Loading label cache...")
            with open(cache_file_path, "r") as cache_file:
                self.label_dict = json.load(cache_file)
        except FileNotFoundError:
            print("No cache, loading label from csv file...")
            self.label_dict = load_flow(csv_data)
            print("Making label cache...")
            with open(cache_file_path, "w") as cache_file:
                json.dump(self.label_dict, cache_file)
            print("Cache done.")

        self.__opened_pcap_file_list = [dpkt.pcap.Reader(open(file, "rb")) for file in pcap_file_list]

        self.data = {}

        self.MAX_FLOW_SAMPLE = max_flow_sample
        self.CHECK_INTERVAL = check_interval

        # statistic
        self.no_match_label = 0
        self.no_layer = 0
        self.duplicate = 0
        self.bias = {}

    def load(self, with_label=True):
        counter = 0
        for pcap_file in tqdm(self.__opened_pcap_file_list):
            print(self.bias)
            for ts, buf in pcap_file:
                # print(ts, buf)
                flow_id = get_flow_id(buf)

                if flow_id is None:
                    self.no_layer += 1
                    continue

                feature = {}

                if with_label:
                    try:
                        feature["label"] = self.label_dict[flow_id]
                        # print(flow_id)
                    except Exception:
                        self.no_match_label += 1
                        continue

                if flow_id not in self.data:
                    feature["time"] = 0
                    feature["start_time"] = ts
                else:
                    if len(self.data[flow_id]) > self.MAX_FLOW_SAMPLE:
                        if ts - self.data[flow_id][0]["start_time"] > self.CHECK_INTERVAL:
                            assert flow_id + str(self.data[flow_id][0]["start_time"]) not in self.data
                            self.data[flow_id + str(self.data[flow_id][0]["start_time"])] = self.data[flow_id]
                            self.data[flow_id] = []

                            feature["time"] = 0
                            feature["start_time"] = ts
                        else:
                            self.duplicate += 1
                            continue
                    else:
                        feature["time"] = ts - self.data[flow_id][0]["start_time"]

                feature.update(unpack_feature(ts, buf))

                if flow_id not in self.data:
                    self.data[flow_id] = []
                    try:
                        self.bias[feature["label"]] += 1
                    except Exception:
                        self.bias[feature["label"]] = 0
                        self.bias[feature["label"]] += 1

                self.data[flow_id].append(feature)

        return self.bias

    def get_statistic(self):
        return {
            "bias": self.bias,
            "no match label": self.no_match_label,
            "no layer": self.no_layer,
            "duplicate": self.duplicate
        }

    def dump_json(self, json_file):
        with open(json_file, "w") as f:
            json.dump(self.data, f)

    def load_json(self, json_file):
        with open(json_file, "r") as f:
            self.data = json.load(f)

    def __try_cache(self):
        pass




def list_file(directory):
    file_list = []
    for filename in os.listdir(directory):
        file_list.append(filename)
    return file_list


if __name__ == '__main__':
    pcap_file_directory = "dataset/CIC_DDoS_2019/PCAP/3-11"
    files = list_file(pcap_file_directory)
    print(files)
    print(len(files))

    files = [pcap_file_directory + "/" + f for f in files]
    # files = [x for x in files if int(x.split("_")[-1]) > 136]
    files = [x for x in files if int(x.split("_")[-1]) > 141]
    print(files)

    # print(files)

    preprocessor = PcapPreprocess(files,
                                  "dataset/CIC_DDoS_2019/CSV/03-11/Syn.csv",
                                  20,
                                  10)
    preprocessor.load()
    print(preprocessor.get_statistic())
    preprocessor.dump_json("dataset_cache.json")
