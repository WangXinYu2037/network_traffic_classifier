from flowcontainer.extractor import extract
import glob
import os
import pandas as pd
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# ----------------------------------------------------握手特征
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
    # print(cert_hex[2962:2965])
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


pcap_path = ['../data/pcap_test/']
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

label = ['1'] * len(Cipher_suite_list)                    # 最后的特征，1是恶意，0是善意

# -----------------------------开始写入CSV
df = pd.DataFrame({'Cipher_suite': Cipher_suite_list, 'Cert_length': Cert_length_list, 'Cert_num': Cert_num_list,
                   'Cert_self_sign': Cert_self_sign, 'Cert_not_valid_before': Cert_not_valid_before_list,
                   'Cert_not_valid_after': Cert_not_valid_after_list, 'Cert_pbk_size_list': Cert_pbk_size_list,
                   'Cert_sign_len': Cert_sign_len_list})


df.to_csv(pcap_path[0] + "握手特征.csv")

