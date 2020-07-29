import dpkt
from tqdm import tqdm
from data_loaders.utils.load_pcap import get_flow_id, unpack_feature, parsing_packet


def load_feature(pcap_file_list, pkt_in_each_flow_limit=None, sample_limit=None):
    """
    load feature from pcap file without label file

    :param pkt_in_each_flow_limit:
    :param pcap_file_list: [ <1.pcap>, <2.pcap>, ...]
    :param sample_limit: {"<label>":<number_limit>, ...}
    """
    opened_pcap_file_list = [dpkt.pcap.Reader(open(file, "rb")) for file in pcap_file_list]

    time_dict = {}
    flow_appear_count = {}
    sample_statistic = 0

    process_bar = tqdm(opened_pcap_file_list, ncols=100, leave=True)
    for pcap_file in process_bar:
        for ts, buf in pcap_file:

            flow_id = get_flow_id(buf)

            if flow_id is None:
                continue

            feature = {}

            # skip if reach length
            if flow_id in flow_appear_count and flow_appear_count[flow_id] >= pkt_in_each_flow_limit:
                continue
            else:
                try:
                    flow_appear_count[flow_id] += 1
                except KeyError:
                    flow_appear_count[flow_id] = 1
            # skip if reach limited number
            if sample_limit is not None:
                if sample_limit <= sample_statistic:
                    break

            # get time
            if flow_id not in time_dict:
                feature["time"] = 0
                time_dict[flow_id] = ts
                sample_statistic += 1
            else:
                feature["time"] = ts - time_dict[flow_id]

            feature.update(unpack_feature(ts, buf))

            process_bar.set_postfix({"Loaded flow number": sample_statistic})

            yield flow_id, parsing_packet(feature)


def generate_default_label_dict(feature_list, default_label):
    label_dict = {}
    for flow_id, _ in feature_list:
        label_dict[flow_id] = default_label
    return label_dict
