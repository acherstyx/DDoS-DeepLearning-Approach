import tensorflow as tf

from utils.normalization.number import norm_number


def norm_ip(ip_str: str):
    split = ip_str.split(".")

    assert len(split) == 4

    ip_float = [str(bin(int(x)))[2:] for x in split]
    # print(ip_float)

    one_hot = ""
    for bin_format in ip_float:
        one_hot = one_hot + '0' * (8 - len(bin_format)) + bin_format
    # print(one_hot)

    return [float(x) for x in list(one_hot)]


def tf_norm_ip(ip_str: tf.Tensor):
    split = tf.strings.split(ip_str, ".")
    return tf.cast(split, dtype=tf.float32) / 255


def norm_port(port: int):
    return norm_number(port, 16)


def norm_protocol(protocol: int):
    return norm_number(protocol, 8)


if __name__ == "__main__":
    # test case
    ip_1 = "192.168.1.2"

    print(norm_ip(ip_1))
