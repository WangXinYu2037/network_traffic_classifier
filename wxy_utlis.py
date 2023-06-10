import numpy as np
import pandas as pd
from utlis.config import dtype
import glob
import os


# 将最后一列量化，其它列量化

def harmonize_data(df):
    max_min_scaler = lambda x: (x - np.min(x)) / (np.max(x) - np.min(x))
    col_name = [x for x in df.columns[:-1]]

    for col_ in col_name:
        # print(col_)
        df[col_] = df[[col_]].apply(max_min_scaler)  # 为啥多了一个[]

    # df[' Label'] = 1                                  # Label为1代表恶意流量，先将该列全部设为1
    # df = df.replace({" Label": {"BENIGN": 0}})    # 好巧妙的赋值，将所有BENIGN设为0,(看来是先找列，再找行）
    # df_result = df.replace({" Label": r'((?!BENIGN).)*'}, {" Label": 1}, regex=True)
    # df_result = df.replace(regex={})             # 有问题，只能执行一次？

    # inplace写入源数据，regex打开正则表达式
    df[' Label'].replace(['BENIGN', r'((?!BENIGN).)*'], [0, 1], regex=True, inplace=True)
    # print(df)
    # print(df[" Label"])
    # print(df.iloc[-1])

    return df


# 输入df， 列名，将其转为float和str

def Ob2Float(df, col_name):

    str_feature = ["Flow ID", " Source IP", " Destination IP", " Timestamp", " Label"]
    col_name_l = [x for x in col_name if x not in str_feature]

    # 转为str的列
    df[str_feature] = df[str_feature].astype(str)
    # 转为float的列
    df[col_name_l] = df[col_name_l].astype(float)

    return df


if __name__ == "__main__":
    # 测试一下,排查bug

    df = pd.read_csv('data/08_04_2017-be-2015-OK-1-com.callpod.android_apps.keeper.pcap_ISCX.csv', dtype=dtype)
    # csv_path = './data/'
    # csv_file_path = glob.glob(os.path.join(csv_path, '*.csv'))
    #
    # frames = []
    #
    # for file_ in csv_file_path:
    #     print(file_)
    #     df = pd.read_csv(file_, dtype=dtype)
    #     frames.append(df)
    # df = pd.concat(frames)

    # print(df.dtypes)

    useless_feature = ["Flow ID", " Source IP", " Destination IP", " Timestamp", " Bwd PSH Flags", " Fwd URG Flags",
                       " Bwd URG Flags", " RST Flag Count", " CWE Flag Count", " ECE Flag Count", "Fwd Avg Bytes/Bulk",
                       " Fwd Avg Packets/Bulk", " Fwd Avg Bulk Rate", " Bwd Avg Bytes/Bulk", " Bwd Avg Packets/Bulk",
                       "Bwd Avg Bulk Rate"]

    df = df.drop(columns=useless_feature)  # 要赋值

    df = harmonize_data(df)

    print(df.head())

