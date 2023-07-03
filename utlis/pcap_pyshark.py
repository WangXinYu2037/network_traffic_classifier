import asyncio
import glob
import os.path

import pyshark
from libnum import s2n

# def packet2CSV(packet):
#

pcap_path = ['.././data/pcap_test/']
pcap_file_path = []
for folder_path in pcap_path:
    pcap_file_path.extend(glob.glob(os.path.join(folder_path, '*.pcap')))

# ---------------------------------- 流元数据特征包括：pcap包长、包平均达到时间、packet包数、packet平均字节数

Pcap_len_list = []
Arrival_time_ave_list = []
Packet_num_list = []
Packet_len_ave_list = []

# ---------------------------------- 明文特征，http头部字段特征：内容长度，请求后时间，帧数量，接受的编码，链接状态
# -----------------------------------       数据提交方式POST是1，get是0
Content_length_list = []
Time_since_request_list = []
Request_frame_list = []
Accept_encoding_list = []
Connection_list = []
Request_method_list = []
User_agent_list = []
for file in pcap_file_path:
    print(file)
    pcap = pyshark.FileCapture(file, display_filter='tls')

    flag = 0
    for packet in pcap:
        print(packet)
        flag = 1
    pcap.close()

    if flag == 0:                         # 说明pcap里没有
        Content_length_list.append(0)
        Time_since_request_list.append(0)
        Request_frame_list.append(0)
        Accept_encoding_list.append(0)
        Connection_list.append(0)
        Request_method_list.append(2)
        User_agent_list.append(0)
        continue
    # if len(pcap) == 0:                                     # 没有http报文
    #     Content_length_list.append(0)
    #     Time_since_request_list.append(0)
    #     Request_frame_list.append(0)
    #     Accept_encoding_list.append(0)
    #     Connection_list.append(0)
    #     Request_method_list.append(2)
    #     User_agent_list.append(0)
    #     continue
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

    pcap.close()
    print('Content_length', Content_length_list, len(Content_length_list))
    print('Time_since_request', Time_since_request_list, len(Time_since_request_list))
    print('Request_frame', Request_frame_list, len(Request_frame_list))
    print('Accept_encoding', Accept_encoding_list, len(Accept_encoding_list))
    print('Connection', Connection_list, len(Connection_list))
    print('Request_method', Request_method_list, len(Request_method_list))
    print('User_agent', User_agent_list, len(User_agent_list))
# for file in pcap_file_path:
#     print(file)
#     pcap = pyshark.FileCapture(file, display_filter="")  # 过滤出所有的TLS流量
#
#     Arrival_time_ave = 0
#     Pcap_len = 0
#     N = 0
#     for packet in pcap:
#         print(packet)
#         Arrival_time_ave += eval(packet.tcp.get_field_by_showname('Time since first frame in this TCP stream'))
#         Pcap_len += len(packet)
#         N += 1
#         # print(packet.tcp.get_field_by_showname('Time since first frame in this TCP stream'))
#         # print(packet.tls.get_field_by_showname('handshake'))
#     pcap.close()
#     Arrival_time_ave_list.append(format(Arrival_time_ave / N, '.4f'))
#     Packet_num_list.append(N)
#     Pcap_len_list.append(Pcap_len)
#     Packet_len_ave_list.append(format(Pcap_len / N, '.4f'))
#
#     print('packet平均到达时间：', Arrival_time_ave_list)
#     print('packet平均长度', Packet_len_ave_list)
#     print('Packet数量：', Packet_num_list)
#     print('Pcap总长度：', Pcap_len_list)
#
#     pcap.close()

# file = pcap_file_path[0]
# file = "1.pcap"
# print(file)
# pcap = pyshark.FileCapture(file)
#
# for packet in pcap:
#     print(packet)
# print(pcap[0])

