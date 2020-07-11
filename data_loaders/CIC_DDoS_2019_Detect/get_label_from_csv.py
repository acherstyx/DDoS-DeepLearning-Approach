__package__ = "data_loaders.CIC_DDoS_2019_Detect"

from ..CIC_DDoS_2019.csv_reader import select_column_from_csv


def load_label(csv_file):
    csv_set = select_column_from_csv(csv_data_file=csv_file,
                                     label_name="Label",
                                     select_columns=["Flow ID"]
                                     )
    for data in csv_set:
        print(data)


if __name__ == '__main__':
    load_label("dataset/CIC_DDoS_2019/CSV/01-12/Syn.csv")
