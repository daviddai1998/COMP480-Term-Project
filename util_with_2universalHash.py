import math
import random
import pandas as pd
import numpy as np
from bitarray import bitarray
from sklearn.utils import murmurhash3_32
from sklearn.linear_model import LogisticRegression


def generate_uid(url):
    digit = len(str(random.Random(url).random()))
    return int(random.Random(url).random() * 10 ** (digit - 2) % 1111111139)


def hash_factory(m):

    def hash_func(x, y):
        return (34142 * x + 324213) % 1111111139 % m, (5325 * x + 54323) % 1111111139 % m, (524634 * x + 3543) % 1111111139 % m, (65787 * x + 5435) % 1111111139 % m

    return hash_func


class BloomFilterUrl:

    def __init__(self, n, r):
        self.n = n
        self.r = r
        self.k = int(math.ceil((r / n) * 0.7))

        self.bits = bitarray(self.r)
        self.bits.setall(0)

    def insert(self, key):
        for _ in range(self.k):
            val1, val2, val3, val4 = hash_factory(self.r)(key, 4)
            self.bits[val1] = 1
            self.bits[val2] = 1
            self.bits[val3] = 1
            self.bits[val4] = 1

    def test(self, key):
        for _ in range(self.k):
            val1, val2, val3, val4 = hash_factory(self.r)(key, 4)
            if not self.bits[val1] or not self.bits[val2] or not self.bits[val3] or not self.bits[val4]:
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


data = pd.read_csv('C:/Users/zichu/Documents/Rice Course/COMP 480/data1.txt', sep="\t")
urllist = data.ClickURL.dropna().unique().tolist()
uid = list(map(lambda x: generate_uid(x), urllist))

# mal_data = np.random.choice(uid, 1000, replace=False)
# np.save("mal_data2.npy", mal_data)

# maldata = np.load("mal_data.npy")

maldata = np.random.choice(uid, 1000, replace=False)

bf = BloomFilterUrl(1000, 8000)
for dt in maldata:
    bf.insert(dt)

sv = Server(bf)

latency_list = []
normal_list = []
count = 0

print('cp1')

for i in range(20000):
    print(uid[i])
    if sv.compute_time(uid[i]) >= 0.3:
        latency_list.append(uid[i])
        count += 1
    else:
        normal_list.append(uid[i])


print(len(latency_list))
print(len(normal_list))
print(count)
# normal_list = normal_list[:len(latency_list)]


totallst = latency_list + normal_list
totalidx = [0 for _ in range(len(latency_list))] + [1 for _ in range(len(normal_list))]
totallst = [[itm1] for itm1 in totallst]
# totalidx = [[itm2] for itm2 in totalidx]

print(len(totallst))
print(len(totalidx))

print("finish")

clf = LogisticRegression(random_state=0, solver='lbfgs',multi_class='multinomial').fit(totallst, totalidx)
predictlst = [[random.choice(uid)] for _ in range(10000)]
r = clf.predict(predictlst)

print(len(r))


finallst = []
for idx in range(len(r)):
    if r[idx] == 1:
        finallst.append(predictlst[idx][0])

print(len(finallst))

randlst = [random.choice(uid) for _ in range(len(finallst))]

print(len(randlst))


count1 = 0
for i in finallst:
    if sv.compute_time(i) >= 0.3:
        count1 += 1

count2 = 0
for i in randlst:
    if sv.compute_time(i) >= 0.3:
        count2 += 1


print(count1)
print(count2)



# 76 109

