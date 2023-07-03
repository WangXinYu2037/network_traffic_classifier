from scapy.all import *
import glob
import os

pcap_path = ['.././data/pcap_test/']
pcap_file_path = []
for folder_path in pcap_path:
    pcap_file_path.extend(glob.glob(os.path.join(folder_path, '*.pcap')))

load_layer("tls")
for file in pcap_file_path:
    print(file)
    pcap = rdpcap(file)
    for x in pcap:
        x.show()






