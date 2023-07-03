# ---------------------------------- 统计量性和恶性数据的数量
import glob
import os.path
import pandas as pd
from matplotlib import pyplot as plt

csv_folder_path = '../data/balance/'
csv_file_path = glob.glob(os.path.join(csv_folder_path, "*.csv"))

benign_sum = 0
other_sum = 0
for file in csv_file_path:
    df = pd.read_csv(file)
    print(file)
    # print(df[' Label'].value_counts())
    # print(df[' Label'].value_counts()['BENIGN'])
    try:
        benign_num = df[' Label'].value_counts()['BENIGN']
    except:
        benign_num = 0
    other = df.shape[0] - benign_num
    benign_sum += benign_num
    other_sum += other
    print(benign_sum, other_sum)

# ------------------------------------------做饼状图，还可以进一步分
# benign_sum = 329657
# other_sum = 611877

plt.rcParams['font.sans-serif' ]= ['SimHei']
plt.figure(figsize=(7.5, 5), dpi=80)  # 调节画布的大小
labels = ['BENIGN', 'OTHERS']  # 定义各个扇形的面积/标签
sizes = [benign_sum, other_sum]  # 各个值，影响各个扇形的面积
colors = ['lightblue', 'orange'] # 每块扇形的颜色
explode = (0.01, 0.01)
patches, text1, text2 = plt.pie(sizes,
                      explode=explode,
                      labels=labels,
                      colors=colors,
                      labeldistance = 1.2,#图例距圆心半径倍距离
                      autopct = '%3.2f%%', #数值保留固定小数位
                      shadow = False, #无阴影设置
                      startangle =90, #逆时针起始角度设置
                      pctdistance = 0.6) #数值距圆心半径倍数距离
#patches饼图的返回值，texts1为饼图外label的文本，texts2为饼图内部文本
plt.axis('equal')
plt.legend()
plt.show()



