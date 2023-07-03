import glob
import os.path

import matplotlib.pyplot as plt
import pandas as pd

csv_folder_path = '../data/pcap_2_csv/'
csv_file_path = glob.glob(os.path.join(csv_folder_path, "*.csv"))

dic_0_sum = {}  # 正常
dic_1_sum = {}  # 恶意
for file in csv_file_path:
    print(file)
    df = pd.read_csv(file, index_col=0)
    cert_length = df['Cert_pbk_size_list']             # 修改这里，统计不同特征
    Label = df['Label']

    value_count = cert_length.value_counts()    # 统计索引
    print(type(value_count))
    print(value_count)
    max_count_5 = value_count.index[:3]        # 最大的五个
    dic_0 = {max_count_5[0]: 0, max_count_5[1]: 0, max_count_5[2]: 0}#, max_count_5[3]: 0, max_count_5[4]: 0,
            # max_count_5[5]: 0, max_count_5[6]: 0} # 正常
    dic_1 = {max_count_5[0]: 0, max_count_5[1]: 0, max_count_5[2]: 0}#, max_count_5[3]: 0, max_count_5[4]: 0,
             #max_count_5[5]: 0, max_count_5[6]: 0} # 恶意
    for i in range(len(cert_length)):
        if cert_length[i] in dic_0:
            if Label[i] == 0:
                dic_0[cert_length[i]] += 1
            else:
                dic_1[cert_length[i]] += 1
        elif cert_length[i] in dic_1:
            if Label[i] == 0:
                dic_0[cert_length[i]] += 1
            else:
                dic_1[cert_length[i]] += 1


    for x in dic_0.keys():
        # print(x)
        # print(dic_0_sum)
        if x in dic_0_sum:
            dic_0_sum[x] += dic_0[x]
        else:
            dic_0_sum[x] = dic_0[x]

    for x in dic_1.keys():
        if x in dic_1_sum:
            dic_1_sum[x] += dic_1[x]
        else:
            dic_1_sum[x] = dic_1[x]

print(dic_0_sum)
print(dic_1_sum)
print('正常流量', sorted(dic_0_sum.items(), key=lambda x: x[0]))
print('恶意流量', sorted(dic_1_sum.items(), key=lambda x: x[0]))
# print(dic_0_sum_sort)
# print(dic_1_sum_sort)
    # for x in value_count.index[:4]:
    #     print(x)
    #     print(value_count[x])
# plt.rcParams["font.sans-serif"] = ['SimHei']
# plt.rcParams["axes.unicode_minus"] = False
#
# x1 = [0, 2, 3]
# x2 = [x + 0.05 for x in x1]
#
# y1 = [4, 5, 6]
# y2 = [9, 5, 1]
#
# plt.bar(x1, y1, lw=0.3, fc='b', width=0.05, label="正常流量")
# plt.bar(x2, y2, lw=0.3, fc='r', width=0.05, label="正常流量")
#
# plt.title('公钥长度相关性')
# plt.xlabel("公钥长度")
# plt.ylabel("流量数目")
#
# plt.legend()
# plt.show()
