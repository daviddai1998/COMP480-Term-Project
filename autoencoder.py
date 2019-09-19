# The char2vec library I use: https://github.com/aleju/CharVectorizer
import math
import random
import pandas as pd
import numpy as np
from bitarray import bitarray
from sklearn.utils import murmurhash3_32
import matplotlib.pyplot as plt


def generate_uid(url):
    digit = len(str(random.Random(url).random()))
    return int(random.Random(url).random() * 10 ** (digit - 2) % 1111111139)


def hash_factory(m):

    def hash_func(x, y):
        if y == 0:
            return (43278 * x + 712894) % 2147483647 % m
        elif y == 1:
            return (327 * x + 23427) % 10001 % m
        elif y == 2:
            return (12 * x + 4334) % 1043001 % m
        else:
            return (x + 1435) % 1111111139 % m

    return hash_func


def url_transformation(url, encrpt):
    new_str = ""
    for ch in url:
        if ch in encrpt:
            new_str += random.choice(encrpt[ch])
        else:
            new_str += ch
    return new_str


def compute_collision_rate(lst, server):
    count = 0
    for ele in lst:
        uid = generate_uid(ele)
        if server.check_malicious(uid):
            count += 1
    print(count)
    return float(count) / float(len(lst))


class BloomFilterUrl:

    def __init__(self, n, r):
        self.n = n
        self.r = r
        self.k = 4

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

    def check_malicious(self, url_id):
        return self.bf.test(url_id)

    def generate_latency(self):
        ans = random.random()
        if ans > 0.7 or ans < 0.3:
            return self.generate_latency()
        return ans

    def generate_base_time(self):
        ans = random.random()
        if ans > 0.3:
            return self.generate_base_time()
        return ans

    def compute_time(self, url_id):
        t = 0
        t += self.generate_base_time()
        if self.check_malicious(url_id):
            t += self.generate_latency()
        return t


# data = pd.read_csv('user-ct-test-collection-01.txt', sep="\t")
# urllist = data.ClickURL.dropna().unique().tolist()
#
# mal_urls = np.random.choice(urllist, 1000, replace=False)
# np.save("mal_urls.npy", mal_urls)
# mal_urls = np.load("mal_urls.npy")
#
# k = [1, 2, 3, 5, 10]


def run():
    for num in k:
        bf = BloomFilterUrl(1000, num * 1000)
        for dt in mal_urls:
            uid = generate_uid(dt)
            bf.insert(uid)

        sv = Server(bf)

        # outF = open("mal_urls.txt", "w")
        # for url in mal_urls:
        #     outF.write(url)
        #     outF.write("\n")
        # outF.close()

        conversion = {'0': ['g', 'z'], '1': ['6', 'a'], '2': ['4', '_'], '3': ['f', '7'], '4': ['2', 'x'], '5': ['0', 'g'],
                      '6': ['1', '8'], '7': ['l', '8'], '8': ['7', 'n'], '9': ['a', '1'], 'a': ['1', '9'], 'b': ['s', 'v'],
                      'c': ['m', 's'], 'd': ['o', 'v'], 'e': ['u', 'k'], 'f': ['3', 'o'], 'g': ['0', '5'], 'h': ['5', '0'],
                      'i': ['y', 'l'], 'j': ['u', 'k'], 'k': ['u', 'j'], 'l': ['7', 'n'], 'm': ['9', 'a'], 'n': ['7', 'l'],
                      'o': ['d', 'f'], 'p': ['r', 'e'], 'q': ['z', '0'], 'r': ['6', 'k'], 's': ['v', 'b'], 't': ['m', '9'],
                      'u': ['j', 'k'], 'v': ['s', 'd'], 'w': ['/', 'h'], 'x': ['4', '2'], 'y': ['i', 'l'], 'z': ['q', '0'],
                      '_': ['2', 'g'], ':': ['x', 'j'], '/': ['w', '4']}

        converted = []
        for s in mal_urls:
            converted.append(url_transformation(s, conversion))

        # print(converted)
        random_urls = np.random.choice(urllist, 1000, replace=False)
        # print(random_urls)

        print(compute_collision_rate(random_urls, sv))
        print(compute_collision_rate(converted, sv))

# run()


k = [1, 2, 3, 5, 10]
random_2 = [0.762, 0.408, 0.235, 0.096, 0.046]
auto_2 = [0.765, 0.409, 0.253, 0.123, 0.042]

random_4 = [0.938, 0.552, 0.313, 0.077, 0.011]
auto_4 = [0.939, 0.587, 0.297, 0.109, 0.012]

random_rate_mur = [0.613, 0.405, 0.222, 0.093, 0.07]
auto_rate_mur = [0.617, 0.388, 0.257, 0.096, 0.006]

df = pd.DataFrame({'k': np.array(k),
                   'auto_mur': np.array(auto_rate_mur),
                   'random_mur': np.array(random_rate_mur),
                   'auto_2': np.array(auto_2),
                   'random_2': np.array(random_2),
                   'auto_4': np.array(auto_4),
                   'random_4': np.array(random_4)
                   })
plt.plot('k', 'auto_mur', data=df, marker='.', color='red', linewidth=1)
# plt.plot('k', 'random_mur', data=df, marker='.', color='blue', linewidth=1)
plt.plot('k', 'auto_2', data=df, marker='.', color='blue', linewidth=1)
# plt.plot('k', 'random_2', data=df, marker='.', color='green', linewidth=1)
plt.plot('k', 'auto_4', data=df, marker='.', color='black', linewidth=1)
# plt.plot('k', 'random_4', data=df, marker='.', color='cyan', linewidth=1)
plt.title("collision rate comparison of auto encoding")
plt.xlabel("k: bucket size of bloom filter")
plt.ylabel('collision rate')
plt.legend()
plt.show()
