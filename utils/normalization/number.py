def norm_number(number: int, bit: int):
    bin_format = str(bin(number))[2:]
    assert len(bin_format) <= bit
    # print(bin_format)
    return [float(x) for x in list('0' * (bit - len(bin_format)) + bin_format)]


def norm_number_clipped(number: int, bit: int):
    try:
        return norm_number(number, bit)
    except AssertionError:
        return [1.0 for _ in range(bit)]


if __name__ == "__main__":
    print(norm_number(11947408, 30))
    print(norm_number_clipped(1432443242, 10))
