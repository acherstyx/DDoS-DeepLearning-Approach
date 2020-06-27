from utils.normalization.number import norm_number


def norm_time_h_m_s(time_str: str):
    """

    :param time_str: time in format like: 3:43.23
    """
    time_split = time_str.split(":")
    assert len(time_split) == 2
    time_split = [time_split[0], ] + time_split[1].split(".")
    assert len(time_split) == 3
    print(time_split)

    time_bin = norm_number(int(time_split[0]), 6)
    time_bin += norm_number(int(time_split[1]), 6)
    time_bin += norm_number(int(time_split[2]), 4)

    return time_bin


if __name__ == "__main__":
    sample_time = "0:18.1"
    print(norm_time_h_m_s(sample_time))
