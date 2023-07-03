import joblib
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


# --------------------------------------保存模型，可以直接调用，目前不是很需要
def save_model(model, model_path):
    joblib.dump(model, model_path)


def load_model(model_path):
    model = joblib.load(model_path)
    return model


# 分离加密流量和未加密流量
def data_split():
    csv_folder_path = './data/'
    csv_file_path = glob.glob(os.path.join(csv_folder_path, "*.csv"))

    out_folder_443 = './data_split/ciphertext'
    out_folder = './data_split/message'

    # file[7:-14]是为了删掉data/和后面的.pcap_ISCX.csv，看来后续还得修改，才能更完善
    # 主要是前面那个7，要对应路径名的长度
    for file in csv_file_path:
        print(file)
        df = pd.read_csv(file)
        # 源端口或者目的端口是443的数据包
        df_443 = df[(df[' Source Port'] == 443) | (df[' Destination Port'] == 443)]
        # 源端口和目的端口都不是443的数据包
        df_other = df[(df[' Source Port'] != 443) & (df[' Destination Port'] != 443)]
        df_443.to_csv(os.path.join(out_folder_443, file[7:-14] + '_443.csv'))
        df_other.to_csv(os.path.join(out_folder, file[7:-14] + '_m.csv'))


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

