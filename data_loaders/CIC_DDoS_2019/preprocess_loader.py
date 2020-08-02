import dpkt
import logging
import pandas as pd
from tqdm import tqdm
from templates.utils import cache_try_load
from data_loaders.utils.load_pcap import get_flow_id, unpack_feature, parsing_packet

logger = logging.getLogger(__name__)


def load_label(csv_data_file, cache_file=None):
    """
    Load flow and its label from the label file from CIC DDoS 2019 dataset

    :param csv_data_file:   CIC DDoS 2019 dataset label file
    :return: dict with `Flow ID` as key and `Label` as value
    :param cache_file:
    """

    def __load():
        logger.info("Loading label of CIC DDoS 2019 from %s", csv_data_file)
        csv_file = pd.read_csv(csv_data_file)
        return dict(zip(csv_file["Flow ID"], csv_file[" Label"]))

    if cache_file is not None:
        return cache_try_load(cache_file, __load)
    else:
        return __load()


def load_feature(pcap_file_list, pkt_in_each_flow_limit=None, label_dict=None, sample_limit_dict=None):
    """
    load feature from pcap file.
    accelerate by remove flow without label in `label_dict` and reach `sample_limit`

    :param pcap_file_list: [ <1.pcap>, <2.pcap>, ...]
    :param pkt_in_each_flow_limit: limit the pkt number in each flow
    :param label_dict: {"<flow_id>": <label>, ...}
    :param sample_limit_dict: {"<label>":<number_limit>, ...}
    """
    opened_pcap_file_list = [dpkt.pcap.Reader(open(file, "rb")) for file in pcap_file_list]

    sample_statistic = None
    if sample_limit_dict is not None:
        sample_statistic = {k: 0 for k, _ in sample_limit_dict.items()}

    time_dict = {}
    flow_appear_count = {}

    process_bar = tqdm(opened_pcap_file_list, ncols=100, leave=True)
    for pcap_file in process_bar:
        for ts, buf in pcap_file:

            flow_id = get_flow_id(buf)

            if flow_id is None:
                continue

            feature = {}

            # skip if no label
            if label_dict is not None:
                try:
                    feature["label"] = label_dict[flow_id]
                except KeyError:
                    # TODO: No match label
                    continue
            # skip if reach length
            if pkt_in_each_flow_limit is not None:
                if flow_id in flow_appear_count and flow_appear_count[flow_id] >= pkt_in_each_flow_limit:
                    continue
                else:
                    try:
                        flow_appear_count[flow_id] += 1
                    except KeyError:
                        flow_appear_count[flow_id] = 1
            # skip if reach limited number
            if sample_limit_dict is not None:
                if sample_limit_dict[feature["label"]] <= sample_statistic[feature["label"]]:
                    all_reach_limit = True
                    # print(sample_limit_dict, sample_statistic)
                    for k, v in sample_limit_dict.items():
                        # print(k, v)
                        if sample_statistic[k] < v:
                            all_reach_limit = False

                    if all_reach_limit:
                        break
                    else:
                        continue
            # get time
            if flow_id not in time_dict:
                feature["time"] = 0
                time_dict[flow_id] = ts
                sample_statistic[feature["label"]] += 1
            else:
                feature["time"] = ts - time_dict[flow_id]

            feature.update(unpack_feature(ts, buf))

            process_bar.set_postfix(**sample_statistic)
            yield flow_id, parsing_packet(feature)


def get_label(label_str: str):
    normal_list = ["benign", "normal"]
    attack_list = ["attack", "syn", "udp", "mssql"]
    if label_str.lower() in normal_list:
        return [1.0, 0.0]
    elif label_str.lower() in attack_list:
        return [0.0, 1.0]
    else:
        logger.error(f"ERROR: Label {label_str} not in label list.")
        raise ValueError


def parsing_label(label_dict):
    return {k: get_label(v) for k, v in label_dict.items()}


# test case
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    my_label_dict = load_label("dataset/CIC_DDoS_2019/CSV/03-11/UDP.csv")
    gen = load_feature(["dataset/CIC_DDoS_2019/PCAP/3-11/SAT-03-11-2018_0117", ], 100, label_dict=my_label_dict,
                       sample_limit_dict={"UDP": 100, "BENIGN": 100, "MSSQL": 0})

    for my_flow_id, my_pkt in gen:
        logger.debug("Flow ID: %s, feature: %s", my_flow_id, my_pkt)
        break
    for my_flow_id, my_label in my_label_dict.items():
        logger.debug("Flow ID: %s, label: %s", my_flow_id, my_label)
        break
