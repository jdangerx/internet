import itertools


def bytes_to_ints(bs):
    """
    Convert a list of bytes to a list of integers.

    >>> bytes_to_ints([1, 0, 2, 1])
    [256, 513]
    >>> bytes_to_ints([1, 0, 1])
    Traceback (most recent call last):
        ...
    ValueError: Odd number of bytes.
    >>> bytes_to_ints([])
    []
    """
    if len(bs) % 2 != 0:
        raise ValueError("Odd number of bytes.")
    pairs = zip(bs[::2], bs[1::2])
    return [(a << 8) + b for a, b in pairs]


def short_to_chars(xs):
    """
    Convert a list of integers to a list of bytes.

    >>> short_to_chars([256, 513])
    [1, 0, 2, 1]
    >>> short_to_chars([])
    []
    """
    arr = itertools.chain.from_iterable((x >> 8, x & 255) for x in xs)
    return list(arr)


def ones_complement_addition(x, y, bitsize=16):
    """
    Add two numbers of any bitsize and carry the carry around.

    11 + 10 = 101 => 10:
    >>> ones_complement_addition(3, 2, 2)
    2

    11 + 11 = 110 => 11:
    >>> ones_complement_addition(3, 3, 2)
    3

    00 + 10 = 10 => 10:
    >>> ones_complement_addition(0, 2, 2)
    2
    """
    cap = 2 ** bitsize - 1
    total = x + y
    if total > cap:
        total -= cap
    return total


def ones_complement_sum(xs, bitsize=16):
    """
    Sum across a bunch of integers with one's complement.

    [11, 10, 10] -> [10, 10] -> [01]:
    >>> ones_complement_sum([3, 2, 2], 2)
    1

    [10, 10, 10] -> [01, 10] -> [11]:
    >>> ones_complement_sum([2, 2, 2], 2)
    3

    []:
    >>> ones_complement_sum([], 2)
    0
    """
    sum = 0
    for x in xs:
        sum = ones_complement_addition(sum, x, bitsize)
    return sum


def ones_complement(x, bitsize=16):
    """
    Swap all 1s and 0s.

    01 -> 10
    >>> ones_complement(1, bitsize=2)
    2

    >>> ones_complement(7, bitsize=3)
    0

    >>> ones_complement((ones_complement(15232)))
    15232
    """
    return ((1 << bitsize) - 1) ^ x


def checksum(bs):
    ints = bytes_to_ints(bs)
    ones_comp_sum = ones_complement_sum(ints)
    return ones_complement(ones_comp_sum)


if __name__ == "__main__":
    import doctest
    doctest.testmod()
