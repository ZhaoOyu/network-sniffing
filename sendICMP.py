from scapy.all import *

# 定义回调函数处理接收到的数据包
def packet_callback(packet):
    if packet.haslayer(IP) and packet[IP].dst == "1.2.3.4" and packet.haslayer(TCP):
        # 过滤目标地址为1.2.3.4且为TCP协议的数据包

        # 打印接收到的请求报文信息
        print("Received packet:")
        print(packet.summary())
        print(packet.show())

        # 构造伪造的响应数据包
        response = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                   TCP(dport=packet[TCP].sport, sport=packet[TCP].dport, flags="A", ack=packet[TCP].seq + 1)

        # 发送伪造的响应数据包
        send(response, verbose=0)

# 开始嗅探网络流量
sniff(filter="host 1.2.3.4", prn=packet_callback, store=0)

