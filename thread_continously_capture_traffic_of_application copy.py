import wmi
# http://timgolden.me.uk/python/wmi/tutorial.html
# https://learn.microsoft.com/en-us/previous-versions/windows/desktop/nettcpipprov/msft-nettcpconnection

import pyshark
from pyshark import ek_field_mapping
import pandas as pd
# import pyperfmon

# Config:
READER_PORT = 4000
SERVER_PORT = 4001
SHOW_PORT = 4002

from time import sleep
from threading import Thread

import socket
global list_of_prot_ip_port
list_of_prot_ip_port=[]

def get_socket_data():
    global list_of_prot_ip_port
    while True:
        ip = socket.gethostbyname(socket.gethostname())
        Socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        Socket.bind((ip, SHOW_PORT))
        Socket.sendto(bytes("get_new_df", "utf-8"), (ip, SERVER_PORT))
        Socket.settimeout(1.0)
        try:
            data = Socket.recv(65536)
            #print('data received')
        except:
            data = b''
            print('receiving data failed')
        data = data.decode()      
        Socket.close()
        it = [iter(data.split())] * 3
        item=list(zip(*it))
        # temp = data.split(sep=" ")
        # item = list(zip(temp[::1], temp[1::2], temp[2::3]))    
        item=list(set(item))
        #print(item)
        if item != [] and len(item) > 1:
            list_of_prot_ip_port = item
            print(list_of_prot_ip_port)
            #sleep(0.1)
        
            # item=data.split(sep=";")     
        #return item



def packet_callback(packet):
    global list_of_prot_ip_port
    try:        
        '''Geht das asyncron, so dass die Liste nur ein update erhält, wenn sie sich verändert hat.'''
        #print(list_of_prot_ip_port)
        #print(packet.highest_layer)
        #print(packet.ip)
        #print(packet.tcp)

        #print(packet.highest_layer, '   ', packet.transport_layer)
        if packet.transport_layer == "UDP":
            prot_ip_port_src=('UDP', packet.ip.src.value, str(packet.udp.srcport))
            prot_ip_port_dst=('UDP', packet.ip.dst.value, str(packet.udp.dstport))
            if (prot_ip_port_src in list_of_prot_ip_port) or (prot_ip_port_dst in list_of_prot_ip_port):        
                print('MATCH!!!')
                print(f'protocol: {packet.transport_layer} src: {packet.ip.src.value} dst: {packet.ip.dst.value}')
       # print(prot_ip_port_dst, prot_ip_port_src)            
        if packet.transport_layer == "TCP":
            prot_ip_port_src=('TCP', packet.ip.src.value, str(packet.tcp.srcport))
            prot_ip_port_dst=('TCP', packet.ip.dst.value, str(packet.tcp.dstport))
            if (prot_ip_port_src in list_of_prot_ip_port) or (prot_ip_port_dst in list_of_prot_ip_port):        
                print('MATCH!!!')
                print(f'protocol: {packet.transport_layer} src: {packet.ip.src.value} dst: {packet.ip.dst.value} RTT: {packet.tcp.analysis_ack_rtt}')
       # print(prot_ip_port_dst, prot_ip_port_src)
       # print(list_of_prot_ip_port)
            

            
              #, RTT: {packet.tcp.analysis_ack_rtt}, iRTT: {packet.tcp.analysis.initial_rtt}')
        #print("RTT", packet.tcp.analysis_ack_rtt)
        #print("iRTT", packet.tcp.analysis.initial_rtt)
        
    except:        
        pass
    

# define the global variable
list_of_prot_ip_port = None
# create a new thread
thread = Thread(target=get_socket_data)
# start the thread
thread.start()

capture = pyshark.LiveCapture(interface='ethernet 3',  use_ek=True)
for packet in capture.sniff_continuously():
    capture.apply_on_packets(packet_callback)
       
