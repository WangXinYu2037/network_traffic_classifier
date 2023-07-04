### Readme

下面是程序和文件清单及其功能：

```python
./
	traffic_classification_csv.py: 用提供的csv进行机器学习
	traffic_classification_pcap.py: 先从pcap中提取握手特征、流元特征和明文特征到csv，再进行机器学习
    traffic_classification_pcap.py: 从真实流量中提取握手特征、流元特征和明文特征到csv，再进行机器学习
    traffic_classification_pcap_select_feature.py: 根据随机森林给出的特征重要性排名，选取相关性教强的特征作为输入，进行机器学习
	wxy_utiliz.py: 存放了一些函数，比如归一化，csv读取时的处理
        
./Demo/
	存放了演示视频，包括pcap提取特征的演示，机器学习过程的演示，
    还有一些统计图表，特征重要性排名的csv文件

./utliz/
	draw_bar.py: 用于统计某个特征的不同分布与流量类型的关系，输入是csv文件，可以自己选择要统计的特征，最后输出两个字典，其中一个是正常流量在特征不同取值情况下的分布，另一个是恶意的。然后用该数据做柱状图。
	draw_pie.py: 统计恶意流量和正常流量数量，画饼状图
	config.py: 定义了读取csv时的一些参数
	pcap_flowcontainer.py: 用flowcontainer从pcap中提取握手特征
	pcap_pyshark.py: 用pyshark从pcap中提取明文特征和流元特征
	pcap_scapy.py: 用scapy尝试从pcap中提取特征
	get_property_from_pcap.py: 是上面工具的集合，从pcap中提取特征转为csv->输出csv
	
./data/
	*.csv/: 约30w条提供的csv数据，约70个特征
	pcap_2_csv/: 对提供的pcap提取特征，约20个特征
	pcap_w_csv_真实流量/: 对捕获并分类的的真实提取特征，输出的csv文件保存于此
	balance/: 30w条数据进行平衡，使恶意和正常流量1：1
	pcap_test/:调试用



./捕获的真实流量/
	由袁梦硕同学捕获的真实流量，分类命名方式与提供的pcap统一；
	其中的data_split是将包含多个会话的pcap包按照会话拆分的结果
    *.csv均为捕获真实流量pcap后，使用程序提取特征后得到的csv文件
	


python 3.7.16
```

github好难用，我尝试用这种方法修改代理，似乎挺有效。

https://zhuanlan.zhihu.com/p/636418854、

居然真的管用啊，家人们！！！

太好了，终于不用被github的断联折磨了，而且配合personal access token作为密码

终于github稍微能好用一点了

https://blog.csdn.net/qq_39218530/article/details/119809170

在push时需要输入token作为密码，之后应该就不用了。



--------------------------------------------------------分割线------------------------------------------









![img](https://img-blog.csdnimg.cn/img_convert/8639eb29331058cbde8e0b4d90eb715d.png)

![img](https://img-blog.csdnimg.cn/img_convert/eac00d3124b850cf7fbb2f9bd7f02614.png)

https://blog.csdn.net/qq_40877422/article/details/113617859

CICAndMal2017 数据集中包括广告软件（Adware）、勒索软件（Ransomware）、恐吓软件（Scareware）、短信恶意软件（SMS Malware）四类恶意软件流量、大量的良性流量（Benign）。提供的云盘链接中包含了各类流量拆分后的双向流以及CSV文件



```
x = data.drop(["quality"], axis=1)
y = data["quality"]
X_train, X_test, y_train, y_test = train_test_split(x, y, train_size=0.7, random_state=123)
print("数据集整体数量：{}".format(len(x)))
print("训练集集整体数量：{}".format(len(X_train)))
print("测试集整体数量：{}".format(len(X_test)))

```

https://blog.csdn.net/ww596520206/article/details/129138144



如何快速读入CSV文件

https://cloud.tencent.com/developer/ask/sof/65313

如何归一化

https://blog.csdn.net/qq_35069382/article/details/104226705

如何修改某datafram中某一列的类型

https://www.cnblogs.com/ivyJ/p/15693516.html



dtype没处理好，失误，把n给替换了



![image-20230606121002516](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20230606121002516.png)

读取失败

![image-20230606121023619](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20230606121023619.png)

空了一行



有些特征全是0，需要去除



正则表达式，将label量化

https://blog.csdn.net/atco/article/details/25100919

https://zhuanlan.zhihu.com/p/62398358

![img](https://upload-images.jianshu.io/upload_images/8612260-0e62070ce90a4bb2.png?imageMogr2/auto-orient/strip|imageView2/2/format/webp)



指标

https://zhuanlan.zhihu.com/p/93107394

https://blog.csdn.net/hfutdog/article/details/88085878

接下来采用不同的算法，调整选取的参数，提高相关性，计算不同的指标



撰写报告，北邮的兄弟

https://github.com/RaidriarB/PythonSparkMachineLearningTest-backend

按照这个来写

* 根据端口号区分加解密流量，将CSV文件进一步分开，文件处理好弄
* 列出特征
* 对比不同算法



* 加分项目
  * 首先得捕获真实流量
  * 排除干扰流量，打上标签
  * 特征选择（我感觉就是在80多个特征里面选相关性强的，问问助教除了这80个还能有别的？？）
  * 分类方法改进我觉得不大可能了，或许用三种分类器，最后三种再投票获得最后的结果？



昊哥推荐的，机器学习和深度学习都有

https://github.com/Colorado-Mesa-University-Cybersecurity/DeepLearning-AndroidMalware



模型导出，学习一下，很容易joblib库就行，暂时用不到

pip install flowcontainer -i http://pypi.douban.com/simple --trusted-host pypi.douban.com

对字符串编码





开始把加密流量和非加密流量分开



如何画饼状图

https://zhuanlan.zhihu.com/p/109566553

## 开坑——神经网络深度学习

https://blog.csdn.net/qq_45125356/article/details/126956497

https://github.com/lulu-cloud/Pytorch-Encrypted-Traffic-Classification-with-1D_CNN



看了一下lxf的ppt

（1）对训练数据的数量进行统计

（2）可视化某个特征在不同标签下的分布情况：固定标签和特征，做密度和取值的图



陈应君采用pyshark方式





### 最后的文档

（1）模拟器，恶意apk，流量截取

（2）数据处理

（3）机器学习

（4）深度学习





协议密码组件，量化的方法，编码的方法，可以参照数据包的01bit流

提取三种特征：流元，协议，明文

https://blog.csdn.net/m0_46281300/article/details/119192409

pyshark：（1）修改Tshark路径（2）环境问题

scapy：感觉这个也挺好用，也有问题，有些提取不了

https://blog.csdn.net/Ineedapassward/article/details/117149639



![image-20230622193838813](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20230622193838813.png)



https://zhuanlan.zhihu.com/p/395907216

tls各个字段查询

Ciphersuite：提供可选项，进行选择
