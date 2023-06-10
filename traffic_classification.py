import glob
import os.path
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score
from wxy_utlis import harmonize_data, Ob2Float
from utlis.config import dtype, useless_feature


# ----------------------------------------------------读取多个CSV文件，并合并（要对列进行处理）
# 读入一个列表，将该列表所列文件路径下所有csv文件拼接成df
def load_csv_to_df(folder_path_l):
    csv_file_path = []
    for folder_path in folder_path_l:
        csv_file_path.extend(glob.glob(os.path.join(folder_path, '*.csv')))

    frames = []
    for file_ in csv_file_path:
        print(file_)
        df = pd.read_csv(file_, dtype=dtype)
        frames.append(df)
    df_result = pd.concat(frames)
    print("----------------------------------------读取完成")
    return df_result
# print(traffic.dtypes)

# print(traffic.head())
# print(traffic.iloc[0])
# print(traffic.iloc[1])

# ----------------------------------------------对数据进行清洗，量化， 归一化
# 清除无用数据，有些数据全是0，有些数据几乎是定值


def data_preprocess(traffic, useless_feature):
    traffic = traffic.drop(columns=useless_feature)
    # 量化，归一化
    traffic = harmonize_data(traffic)
    print(traffic.head())
    print(traffic.dtypes)
    # traffic.to_csv('./debug/traffic.csv')
    # print(traffic.head())
    Features = traffic.drop(columns=" Label")
    Label = traffic[" Label"]

    # print(np.isnan(Features))                      # 排查NaN
    # print(np.where(np.isnan(Features)))

    # F_columns = Features.columns
    # print(F_columns[16])
    # print(Features[F_columns[16]].dtype)
    # print(Features.iloc[65583])
    # # Features.iloc[65583].to_csv('65583.csv')
    # print(Features.iat[65583, 16])
    Features = Features.fillna(0)                    # 是数字太小了，所以变成NaN了吗
    print("----------------------------------------量化，清洗数据完成")
    return Features, Label


# ------------------------------------------------随机分配训练集和测试集
def random_split(Features, Label, test_size):
    x0, x1, y0, y1 = train_test_split(Features, Label, test_size=test_size)
    print("xtrain:", x0.shape, "ytrain:", y0.shape)
    print("xtest:", x1.shape, "xtest:", y1.shape)
    print("----------------------------------------训练集和测试集规模如上，训练中")
    return x0, x1, y0, y1


# ------------------------------------------------建立模型，并打印相关指标


def Random_Forest_Classifier(xtrain, xtest, ytrain, ytest):
    rfc = RandomForestClassifier()
    rfc.fit(xtrain, ytrain)
    # 查看效果
    y_pred = rfc.predict(xtest)
    print("准确率Accuracy：", accuracy_score(ytest, y_pred))
    P = precision_score(ytest, y_pred)
    print("精确率Precision：", P)
    R = recall_score(ytest, y_pred)
    print("召回率Recall：", R)
    F1 = 2 * P * R / (P + R)
    print("F1值：", F1)

    print("----------------------------------------采用随机森林算法，准确度相关指标如上")

def Decision_Tree_Classifier(xtrain, xtest, ytrain, ytest):
    dtc = DecisionTreeClassifier()
    dtc.fit(xtrain, ytrain)
    # 查看效果
    y_pred = dtc.predict(xtest)
    print("准确率Accuracy：", accuracy_score(ytest, y_pred))
    P = precision_score(ytest, y_pred)
    print("精确率Precision：", P)
    R = recall_score(ytest, y_pred)
    print("召回率Recall：", R)
    F1 = 2 * P * R / (P + R)
    print("F1值：", F1)

    print("----------------------------------------采用决策树算法，准确度相关指标如上")


if __name__ == "__main__":
    csv_path = ['./data/']
    network_traffic = load_csv_to_df(csv_path)  # csv -> df

    Features, Label = data_preprocess(network_traffic, useless_feature)  # 量化，清洗

    test_size = 0.8
    xtrain, xtest, ytrain, ytest = random_split(Features, Label, test_size)
    # np.isnan(xtrain).to_csv('nan.csv')

    Random_Forest_Classifier(xtrain, xtest, ytrain, ytest)
    Decision_Tree_Classifier(xtrain, xtest, ytrain, ytest)
