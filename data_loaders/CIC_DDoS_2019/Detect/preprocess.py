__package__ = "data_loaders.CIC_DDoS_2019.Detect"
__all__ = ["PcapPreprocess", "list_file"]

import dpkt

import os
import pickle
import logging
import pandas as pd

from tqdm import tqdm
from utils.file_io import list_file
from data_loaders.utils.load_pcap import get_flow_id, unpack_feature

"""
Do some preprocess to help make tensorflow dataset from CIC DDoS 2019 dataset
"""

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_label(csv_data_file):
    """
    Load flow and its label from the label file from CIC DDoS 2019 dataset
    :param csv_data_file:   CIC DDoS 2019 dataset label file
    :return: dict with `Flow ID` as key and `Label` as value
    """
    csv_file = pd.read_csv(csv_data_file)

    return dict(zip(csv_file["Flow ID"], csv_file[" Label"]))


class PcapPreprocess:
    def __init__(self,
                 pcap_file_list,
                 csv_file,
                 max_flow_sample,
                 check_interval):
        self.csv_file = csv_file

        # save cache to the same directory, use hash value of `self` to identify change

        self.__opened_pcap_file_list = [dpkt.pcap.Reader(open(file, "rb")) for file in pcap_file_list]

        self.label_dict = None
        self.data = {}

        self.MAX_FLOW_SAMPLE = max_flow_sample
        self.CHECK_INTERVAL = check_interval

        # statistic
        self.no_match_label = 0
        self.no_layer = 0
        self.duplicate = 0
        self.bias = {}

        # cache
        # TODO: change cache file name based on the change in python file
        self.csv_cache_file = "cache/preprocess-csv_cache"
        self.pcap_cache_file = "cache/preprocess-pcap_cache"

    def load(self, with_label=True, number_limit=0):
        """
        load feature from pcap file and get label

        :param with_label:
        :param number_limit: limit the sample of each type of label, 0 is unlimited
        :return:
        """

        # try to load cache first

        if self.csv_cache_file is not None:
            try:
                logger.info("Loading label cache... ")
                with open(self.csv_cache_file, "rb") as cache_file:
                    self.label_dict = pickle.load(cache_file)
            except FileNotFoundError:
                logger.info("No cache, loading label from csv file... ")
                self.label_dict = load_label(self.csv_file)
                logger.info("Making label cache... ")
                with open(self.csv_cache_file, "wb") as cache_file:
                    pickle.dump(self.label_dict, cache_file)
            logger.info("Done.")

        if self.pcap_cache_file is not None:
            try:
                logger.info("Loading pcap cache... ")
                self.__cache_load(self.pcap_cache_file)
                return self.get_statistic()
            except FileNotFoundError:
                logger.info("No cache, loading from raw data... ")
            logger.info("Done.")

        self.bias = {}
        process_bar = tqdm(self.__opened_pcap_file_list)

        for pcap_file in process_bar:
            process_bar.set_postfix(**self.bias)
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
                    except KeyError:
                        self.no_match_label += 1
                        continue
                try:
                    if number_limit != 0 and self.bias[feature["label"]] >= number_limit:
                        continue
                except KeyError:
                    self.bias[feature["label"]] = 0

                if flow_id not in self.data:
                    feature["time"] = 0
                    feature["start_time"] = ts
                else:
                    if len(self.data[flow_id]) > self.MAX_FLOW_SAMPLE:
                        if ts - self.data[flow_id][0]["start_time"] > self.CHECK_INTERVAL:
                            assert flow_id + str(self.data[flow_id][0]["start_time"]) not in self.data
                            self.data[flow_id + str(self.data[flow_id][0]["start_time"])] = self.data[flow_id]
                            self.data.pop(flow_id)

                            feature["time"] = 0
                            feature["start_time"] = ts
                        else:
                            self.duplicate += 1
                            continue
                    elif ts - self.data[flow_id][0]["start_time"] > self.CHECK_INTERVAL:
                        assert flow_id + str(self.data[flow_id][0]["start_time"]) not in self.data
                        self.data[flow_id + str(self.data[flow_id][0]["start_time"])] = self.data[flow_id]
                        self.data.pop(flow_id)

                        feature["time"] = 0
                        feature["start_time"] = ts
                    else:
                        feature["time"] = ts - self.data[flow_id][0]["start_time"]

                feature.update(unpack_feature(ts, buf))

                if flow_id not in self.data:
                    self.data[flow_id] = []
                    try:
                        self.bias[feature["label"]] += 1
                    except KeyError:
                        self.bias[feature["label"]] = 0
                        self.bias[feature["label"]] += 1

                self.data[flow_id].append(feature)

        if self.pcap_cache_file is not None:
            self.__cache_dump(self.pcap_cache_file)

        return self.bias

    def get_statistic(self):
        label_bias = {}
        for key, feature in self.data.items():
            feature = feature[0]
            try:
                label_bias[feature["label"]] += 1
            except KeyError:
                label_bias[feature["label"]] = 1
        return label_bias

    def __cache_dump(self, json_file):
        with open(json_file, "wb") as f:
            pickle.dump(self.data, f)

    def __cache_load(self, json_file):
        with open(json_file, "rb") as f:
            self.data = pickle.load(f)

    def get_dataset(self):
        return self.data


if __name__ == '__main__':
    pcap_file_directory = "dataset/CIC_DDoS_2019/PCAP/3-11"
    files = list_file(pcap_file_directory)
    print(files)
    print(len(files))

    files = [pcap_file_directory + "/" + f for f in files]
    files = [x for x in files if int(x.split("_")[-1]) > 136]
    print(files)

    # print(files)

    preprocessor = PcapPreprocess(files,
                                  "dataset/CIC_DDoS_2019/CSV/03-11/Syn.csv",
                                  20,
                                  10)
    print(preprocessor.load(number_limit=14000))

    # for sample in preprocessor.get_dataset().items():
    #     print(sample)
