from flowcontainer.extractor import extract
import glob
import os
import pandas as pd
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import pyshark
from libnum import s2n
'''
提取握手特征
特征有：密码套件，证书长度，证书数量，证书签发者和所有者，是否自签名，失效时间，公钥长度，签名长度
'''
def bytes_to_string(bytes):
    return str(bytes, 'utf-8')


def x509name_to_json(x509_name):
    json = {}
    for attribute in x509_name:
        name = attribute.oid._name
        value = attribute.value
        json[name] = value
    return json


def x509_parser(cert_hex):
    print(cert_hex[2962:2965])
    cert = bytes.fromhex(cert_hex.replace(':', ''))
    cert = x509.load_der_x509_certificate(cert, default_backend())
    rst = {
        'issuer': x509name_to_json(cert.issuer),
        'subject': x509name_to_json(cert.subject),
        'extensions': x509name_to_json(cert.extensions),
        'not_valid_before': cert.not_valid_before,
        'not_valid_after': cert.not_valid_after,
        'public_key_size': cert.public_key().key_size,
        'signature_len': len(cert.signature)
    }
    return rst


def datatime2int(current_date):
    r = current_date.year * 10000 + current_date.month * 100 + current_date.day
    return r


def get_Cert(cert_info):

    flag = 0
    for y in cert_info:
        if y[0] != '':
            cert_hex = y[0].split(',')[0]
            flag = 1
            break
    if flag == 0:
        Cert_issuer_list.append(0)
        Cert_subject_list.append(0)
        # Cert_extension_list.append(0)
        Cert_not_valid_before_list.append(0)
        Cert_not_valid_after_list.append(0)
        Cert_self_sign.append(0)
        Cert_pbk_size_list.append(0)
        Cert_sign_len_list.append(0)
        return
    rst = x509_parser(cert_hex)
    Cert_issuer_list.append(rst['issuer'])
    Cert_subject_list.append(rst['subject'])
    # Cert_extension_list.append(rst['extensions'])
    Cert_self_sign.append(int(rst['subject'] == rst['subject']))
    Cert_not_valid_before_list.append(datatime2int(rst['not_valid_before']))
    Cert_not_valid_after_list.append(datatime2int(rst['not_valid_after']))
    Cert_pbk_size_list.append(rst['public_key_size'])
    Cert_sign_len_list.append(rst['signature_len'])
    return


def get_Cipher_suite(Cipher_suite):
    if Cipher_suite != '':  # 有套件选项
        flag = 0  # 没有选取密码套件
        print(flag)
        for x in Cipher_suite:

            if ',' not in x[0] and x[0] != '':  # 没有分割，且不是空，所以此处进行了选择
                Cipher_suite_list.append(int(x[0]))
                flag = 1  # 选取了密码套件
                break
        if flag == 0:
            Cipher_suite_list.append(0)
    else:  # 无密码套件选项
        Cipher_suite_list.append(0)


def get_Cert_length(Cert_length):
    if Cert_length != '':
        flag = 0
        for x in Cert_length:
            if x[0] != '':
                y = x[0].split(',')
                Cert_length_list.append(int(y[0]))    # 选择一个不为空的作为该pcap的证书长度
                Cert_num_list.append(len(y))          # 记录证书数量
                flag = 1
                break
        if flag == 0:
            Cert_length_list.append(0)
            Cert_num_list.append(0)
    else:
        Cert_length_list.append(0)
        Cert_num_list.append(0)


pcap_path = ['.././data/pcap_test/']
pcap_file_path = []
for folder_path in pcap_path:
    pcap_file_path.extend(glob.glob(os.path.join(folder_path, '*.pcap')))

# ------------------------------给出了文件夹下的csv文件个数
# --------------------------特征有：密码套件，证书长度，证书数量，证书签发者和所有者，是否自签名，失效时间，公钥长度，签名长度
M = len(pcap_path)
Cipher_suite_list = []
Cert_length_list = []
Cert_num_list = []
Cert_issuer_list = []
Cert_subject_list = []
Cert_self_sign = []
# Cert_extension_list = []
Cert_not_valid_before_list = []
Cert_not_valid_after_list = []
Cert_pbk_size_list = []
Cert_sign_len_list = []


extensions = ["tls.handshake.ciphersuite", 'tls.handshake.certificate_length',
              "tls.handshake.certificate"]

for file in pcap_file_path:
    result = extract(file, filter='tcp', extension=extensions)
    print(result)
    if result == {}:
        Cipher_suite_list.append(0)                       # 从这里开始，就已经没有内容了，置为0
        Cert_length_list.append(0)
        Cert_num_list.append(0)
        Cert_issuer_list.append(0)
        Cert_subject_list.append(0)
        Cert_self_sign.append(0)
        # Cert_extension_list.append(0)
        Cert_not_valid_before_list.append(0)
        Cert_not_valid_after_list.append(0)
        Cert_pbk_size_list.append(0)
        Cert_sign_len_list.append(0)
        continue                                          # 下一个pcap
    for key in result:
        value = result[key]
        Cipher_suite = value.extension['tls.handshake.ciphersuite']
        Cert_length = value.extension['tls.handshake.certificate_length']
        Cert_info = value.extension['tls.handshake.certificate']
        print('handshake.ciphersuite：', Cipher_suite)
        print('Cert_length：', Cert_length)
        print("Cert_info：", Cert_info)

        get_Cipher_suite(Cipher_suite)
        get_Cert_length(Cert_length)
        get_Cert(Cert_info)

    print('Cipher_suite_list：', Cipher_suite_list, len(Cipher_suite_list))
    print('Cert_length_list：', Cert_length_list, len(Cert_length_list))
    print('Cert_num_list：', Cert_num_list, len(Cert_num_list))
    print('Cert_issuer_list：', Cert_issuer_list, len(Cert_issuer_list))
    print('Cert_subject_list：', Cert_subject_list, len(Cert_subject_list))
    print('Cert_self_sign：', Cert_self_sign, len(Cert_self_sign))
    # print('Cert_extension_list：', Cert_extension_list, len(Cert_extension_list))
    print('Cert_not_valid_before_list：', Cert_not_valid_before_list, len(Cert_not_valid_before_list))
    print('Cert_not_valid_after_list：', Cert_not_valid_after_list, len(Cert_not_valid_after_list))
    print('pbk_size：', Cert_pbk_size_list, len(Cert_pbk_size_list))
    print('sign_len：', Cert_sign_len_list, len(Cert_sign_len_list))



'''
提取流元特征
流元数据特征包括：pcap包长、包平均达到时间、packet包数、packet平均字节数
'''


pcap_file_path = []
for folder_path in pcap_path:
    pcap_file_path.extend(glob.glob(os.path.join(folder_path, '*.pcap')))

# ---------------------------------- 流元数据特征包括：pcap包长、包平均达到时间、packet包数、packet平均字节数
Pcap_len_list = []
Arrival_time_ave_list = []
Packet_num_list = []
Packet_len_ave_list = []
for file in pcap_file_path:
    print(file)
    pcap = pyshark.FileCapture(file, display_filter="")  # 过滤出所有的TLS流量

    Arrival_time_ave = 0
    Pcap_len = 0
    N = 0
    for packet in pcap:
        # print(packet)
        Arrival_time_ave += eval(packet.tcp.get_field_by_showname('Time since first frame in this TCP stream'))
        Pcap_len += len(packet)
        N += 1
        # print(packet.tcp.get_field_by_showname('Time since first frame in this TCP stream'))
        # print(packet.tls.get_field_by_showname('handshake'))
    pcap.close()
    Arrival_time_ave_list.append(eval(format(Arrival_time_ave / N, '.4f')))
    Packet_num_list.append(N)
    Pcap_len_list.append(Pcap_len)
    Packet_len_ave_list.append(eval(format(Pcap_len / N, '.4f')))

    print('packet平均到达时间：', Arrival_time_ave_list, len(Arrival_time_ave_list))
    print('packet平均长度', Packet_len_ave_list, len(Packet_len_ave_list))
    print('Packet数量：', Packet_num_list, len(Packet_num_list))
    print('Pcap总长度：', Pcap_len_list, len(Pcap_len_list))

    pcap.close()

'''
提取明文特征
特征有：http内容长度， 距第一次请求的时间， 请求帧数， 接受编码， 会话状态，提交数据方式，用户代理
'''

Content_length_list = []
Time_since_request_list = []
Request_frame_list = []
Accept_encoding_list = []
Connection_list = []
Request_method_list = []
User_agent_list = []


for file in pcap_file_path:
    print(file)
    pcap = pyshark.FileCapture(file, display_filter='http')

    flag = 0
    for packet in pcap:
        flag = 1
    pcap.close()

    if flag == 0:                         # 说明pcap里没有http报文
        Content_length_list.append(0)
        Time_since_request_list.append(0)
        Request_frame_list.append(0)
        Accept_encoding_list.append(0)
        Connection_list.append(0)
        Request_method_list.append(2)
        User_agent_list.append(0)
        continue

    pcap = pyshark.FileCapture(file, display_filter='http')
    for packet in pcap:
        print(packet)
        Content_length = packet.http.get_field_by_showname('Content length')
        if Content_length is None:
            Content_length_list.append(0)
        else:
            Content_length_list.append(int(Content_length))

        Time_since_request = packet.http.get_field_by_showname('Time since request')
        print(Time_since_request)
        if Time_since_request is None:
            Time_since_request_list.append(0)
        else:
            Time_since_request_list.append(eval(format(eval(Time_since_request.split(' ')[0]), '.4f')))

        Request_in_frame = packet.http.get_field_by_showname('Request in frame')
        if Request_in_frame is None:
            Request_frame_list.append(0)
        else:
            Request_frame_list.append(eval(Request_in_frame))

        Accept_encoding = packet.http.get_field_by_showname('Accept-Encoding')
        if Accept_encoding is None:
            Accept_encoding_list.append(0)
        else:
            Accept_encoding_list.append(s2n(Accept_encoding) & 0xffff)

        Connection = packet.http.get_field_by_showname('Connection')
        if Connection is None:
            Connection_list.append(0)
        else:
            Connection_list.append(s2n(Connection) & 0xffff)

        Request_method = packet.http.get_field_by_showname('Request Method')
        if Request_method is None:
            Request_method_list.append(2)
        else:
            Request_method_list.append(int(packet.http.get_field_by_showname('Request Method') == "POST"))

        User_agent = packet.http.get_field_by_showname('User-Agent')
        if User_agent is None:
            User_agent_list.append(0)
        else:
            User_agent_list.append(s2n(User_agent) & 0xffff)

        print('Content_length', Content_length_list, len(Content_length_list))
        print('Time_since_request', Time_since_request_list, len(Time_since_request_list))
        print('Request_frame', Request_frame_list, len(Request_frame_list))
        print('Accept_encoding', Accept_encoding_list, len(Accept_encoding_list))
        print('Connection', Connection_list, len(Connection_list))
        print('Request_method', Request_method_list, len(Request_method_list))
        print('User_agent', User_agent_list, len(User_agent_list))
        break

    pcap.close()

'''
开始写入csv文件
'''
# -----------------------------开始写入CSV
label = [1] * len(pcap_file_path)
print(len(pcap_file_path))
dic = {'Cipher_suite': Cipher_suite_list, 'Cert_length': Cert_length_list, 'Cert_num': Cert_num_list,
       'Cert_self_sign': Cert_self_sign, 'Cert_not_valid_before': Cert_not_valid_before_list,
       'Cert_not_valid_after': Cert_not_valid_after_list, 'Cert_pbk_size_list': Cert_pbk_size_list,
       'Cert_sign_len': Cert_sign_len_list, 'Arrival_time_ave：': Arrival_time_ave_list,
       'Packet_len_ave': Packet_len_ave_list, 'Packet_num': Packet_num_list, 'Pcap_len': Pcap_len_list,
        'Content_length': Content_length_list, 'Time_since_request': Time_since_request_list,
       'Request_frame': Request_frame_list, 'Accept_encoding': Accept_encoding_list, 'Connection': Connection_list,
       'Request_method': Request_method_list, 'User_agent': User_agent_list, 'Label': label}
for value in dic.values():
    print(len(value))

df = pd.DataFrame(dic)


df.to_csv("握手特征+流元特征+明文特征.csv")

