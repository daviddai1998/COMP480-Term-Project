import math
import random
import pandas as pd
from bitarray import bitarray
from sklearn.utils import murmurhash3_32


def generate_uid(url):
    digit = len(str(random.Random(url).random()))
    return int(random.Random(url).random() * 10 ** (digit - 2))


def hash_factory(m):

    def hash_func(x, y):
        return murmurhash3_32(x, y) % m

    return hash_func


class BloomFilterUrl:

    def __init__(self, n, r):
        self.n = n
        self.r = r
        self.k = math.ceil((r / n) * 0.7)

        self.bits = bitarray(self.r)
        self.bits.setall(0)

    def insert(self, key):
        for _ in range(self.k):
            val = hash_factory(self.r)(key, _)
            self.bits[val] = 1

    def test(self, key):
        for _ in range(self.k):
            val = hash_factory(self.r)(key, _)
            if not self.bits[val]:
                return False
        return True


class Server:

    def __init__(self, bloom_filter):
        self.bf = bloom_filter

    def check_malicious(self, uid):
        return self.bf.test(uid)


# data = pd.read_csv('user-ct-test-collection-01.txt', sep="\t")
# urllist = data.ClickURL.dropna().unique().tolist()


print(generate_uid("test"))
