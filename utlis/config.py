# 存储一些基本配置
# ID, IP, Timestamps要设为str，无法量化，这几个特征直觉上与恶意流量关联性较低
# 先尝试以数据包的其它特征来看看

dtype = {'Flow ID': str,  ' Source IP': str,  ' Source Port': float,  ' Destination IP': str,
         ' Destination Port': float,  ' Protocol': float,  ' Timestamp': str,  ' Flow Duration': float,
         ' Total Fwd Packets': float,  ' Total Backward Packets': float,
         'Total Length of Fwd Packets': float,  ' Total Length of Bwd Packets': float,
         ' Fwd Packet Length Max': float,  ' Fwd Packet Length Min': float,
         ' Fwd Packet Length Mean': float,  ' Fwd Packet Length Std': float,
         'Bwd Packet Length Max': float,  ' Bwd Packet Length Min': float,
         ' Bwd Packet Length Mean': float,  ' Bwd Packet Length Std': float,  'Flow Bytes/s': float,
         ' Flow Packets/s': float,  ' Flow IAT Mean': float,  ' Flow IAT Std': float,  ' Flow IAT Max': float,
         ' Flow IAT Min': float,  'Fwd IAT Total': float,  ' Fwd IAT Mean': float,  ' Fwd IAT Std': float,
         ' Fwd IAT Max': float,  ' Fwd IAT Min': float,  'Bwd IAT Total': float,  ' Bwd IAT Mean': float,
         ' Bwd IAT Std': float,  ' Bwd IAT Max': float,  ' Bwd IAT Min': float,  'Fwd PSH Flags': float,
         ' Bwd PSH Flags': float,  ' Fwd URG Flags': float,  ' Bwd URG Flags': float,
         ' Fwd Header Length': float,  ' Bwd Header Length': float,  'Fwd Packets/s': float,
         ' Bwd Packets/s': float,  ' Min Packet Length': float,  ' Max Packet Length': float,
         ' Packet Length Mean': float,  ' Packet Length Std': float,  ' Packet Length Variance': float,
         'FIN Flag Count': float,  ' SYN Flag Count': float,  ' RST Flag Count': float,
         ' PSH Flag Count': float,  ' ACK Flag Count': float,  ' URG Flag Count': float,
         ' CWE Flag Count': float,  ' ECE Flag Count': float,  ' Down/Up Ratio': float,
         ' Average Packet Size': float,  ' Avg Fwd Segment Size': float,
         ' Avg Bwd Segment Size': float,  ' Fwd Header Length.1': float,  'Fwd Avg Bytes/Bulk': float,
         ' Fwd Avg Packets/Bulk': float,  ' Fwd Avg Bulk Rate': float,  ' Bwd Avg Bytes/Bulk': float,
         ' Bwd Avg Packets/Bulk': float,  'Bwd Avg Bulk Rate': float,  'Subflow Fwd Packets': float,
         ' Subflow Fwd Bytes': float,  ' Subflow Bwd Packets': float,  ' Subflow Bwd Bytes': float,
         'Iit_Wi_bytes_forward': float,  ' Iit_Wi_bytes_backward': float,
         ' act_data_pkt_fwd': float,  ' Min_seg_size_forward': float,  'Active Mean': float,
         ' Active Std': float,  ' Active Max': float,  ' Active Min': float,  'Idle Mean': float,  ' Idle Std': float,
         ' Idle Max': float,  ' Idle Min': float,  ' Label': str}

useless_feature = ["Flow ID", " Source IP", " Destination IP", " Timestamp", " Bwd PSH Flags", " Fwd URG Flags",
                   " Bwd URG Flags", " RST Flag Count", " CWE Flag Count", " ECE Flag Count", "Fwd Avg Bytes/Bulk",
                   " Fwd Avg Packets/Bulk", " Fwd Avg Bulk Rate", " Bwd Avg Bytes/Bulk", " Bwd Avg Packets/Bulk",
                   "Bwd Avg Bulk Rate", " min_seg_size_forward"]

