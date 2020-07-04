try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET


class ISCXIDS_2012_XML_Reader:
    def __init__(self, file_list):
        self.count = {}
        self.flow = {}

        for xml_file in file_list:
            tree = ET.parse(xml_file)  # load to memory (make sure you have enough memory)
            root = tree.getroot()
            self.load_flow_label(xml_root=root)
        print(self.count)

    def load_flow_label(self, xml_root: ET.Element):
        for elem in xml_root:
            # get flow id
            src_ip = elem.find("source").text
            src_port = elem.find("sourcePort").text
            dst_ip = elem.find("destination").text
            dst_port = elem.find("destinationPort").text
            flow_id = src_ip + "-" + src_port + "-" + dst_ip + "-" + dst_port
            # flow_id_reverse = dst_ip + "-" + dst_port + "-" + src_ip + "-" + src_port

            tag = elem.find("Tag").text
            self.flow[flow_id] = tag
            # self.flow[flow_id_reverse] = tag
            # print(flow_id)
            try:
                self.count[tag] += 1
            except KeyError:
                self.count[tag] = 1

    def get_flow(self):
        return self.flow


if __name__ == '__main__':
    file_list = ["dataset/ISCXIDS2012/labeled_flows_xml/TestbedThuJun17-3Flows.xsd",
                 "dataset/ISCXIDS2012/labeled_flows_xml/TestbedTueJun15-1Flows.xml",
                 "dataset/ISCXIDS2012/labeled_flows_xml/TestbedTueJun15-2Flows.xml",
                 "dataset/ISCXIDS2012/labeled_flows_xml/TestbedTueJun15-3Flows.xml"]
    reader = ISCXIDS_2012_XML_Reader(file_list)
