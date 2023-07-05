import wmi
# http://timgolden.me.uk/python/wmi/tutorial.html
# https://learn.microsoft.com/en-us/previous-versions/windows/desktop/nettcpipprov/msft-nettcpconnection

import pyshark
from pyshark import ek_field_mapping
import pandas as pd
import os
import socket
import time
from threading import Thread
import json

#from sys import exit
# CAPTUREINTERFACE = "WLAN"
CAPTUREINTERFACE = "ethernet"
app='-outlook'
data_path=r"C:\Users\bodensohn\git\poc_app_traffic_monitor\data"
file_name=time.strftime("%m%d%H%M%S", time.localtime())+app
data_path=data_path+ "\\" + file_name

# Config:
READER_PORT = 4000
SERVER_PORT = 4001
SHOW_PORT = 4002

global list_of_prot_ip_port
list_of_prot_ip_port = None
global write2ndjson


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
           # print('data received')
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
        if item != [] and item != None and len(item) > 1:
          #  print(item)
            list_of_prot_ip_port = item

class Write2ndjson:
    def check_working_dir(self, working_dir):
        if not os.path.exists(working_dir):          
            os.makedirs(working_dir)  

    def __init__(self, name, working_dir, NMAX = 100):
        self.name = name
        self.NMAX = NMAX
        self.counter = 0
        self.working_dir=working_dir
        self.check_working_dir(self.working_dir)   
        
    def increment_counter(self):
        self.counter += 1

    def get_file_name(self):
        file=str(int(self.counter/self.NMAX)) + "_"+ self.name + ".ndjson"
        return os.path.join(self.working_dir, file)
        #return self.working_dir+"/"+str(int(self.counter/self.NMAX)) + "_"+ self.name + ".ndjson"

    def writeline2ndjson(self, line):
        filename = self.get_file_name()
        self.increment_counter()
        file = open(filename, "a", encoding="utf-8")
        json.dump(line, file)
        #file.write(line)
        file.write('\n')
        file.close()

def get_data_from_ip(packet):
    line={}
    basic_keys = ['time', 'len', 'protocol', 'src', 'dst', 'dscp', 'srcport', 'dstport']
    if packet.transport_layer == "UDP":        
        prot_ip_port_src=('UDP', packet.ip.src.value, str(packet.udp.srcport))
        prot_ip_port_dst=('UDP', packet.ip.dst.value, str(packet.udp.dstport))
        if (prot_ip_port_src in list_of_prot_ip_port) or (prot_ip_port_dst in list_of_prot_ip_port):        
            print('MATCH UDP v4!!!')                
            values=[packet.sniff_timestamp, packet.ip.len, packet.transport_layer, packet.ip.src.value, packet.ip.dst.value,packet.ip.dsfield.dscp, packet.udp.srcport, packet.udp.dstport] 
            for key, value in zip(basic_keys, values):
                line[key] = value
            print(line)  
                                                   
    # print(prot_ip_port_dst, prot_ip_port_src)            
    if packet.transport_layer == "TCP":           
        prot_ip_port_src=('TCP', packet.ip.src.value, str(packet.tcp.srcport))
        prot_ip_port_dst=('TCP', packet.ip.dst.value, str(packet.tcp.dstport))
        #print(packet.transport_layer, '  ', prot_ip_port_src, ' ', prot_ip_port_dst, ' ', list_of_prot_ip_port )
        if (prot_ip_port_src in list_of_prot_ip_port) or (prot_ip_port_dst in list_of_prot_ip_port):        
            print('MATCH TCP v4!!!')

            # Loop Over Two Lists to Create a Dictionary using Zip
            
            values=[packet.sniff_timestamp, packet.ip.len, packet.transport_layer, packet.ip.src.value, packet.ip.dst.value,packet.ip.dsfield.dscp, packet.tcp.srcport, packet.tcp.dstport] 
            for key, value in zip(basic_keys, values):
                line[key] = value                           
            if hasattr(packet.tcp, "analysis_ack_rtt"):
                line['rtt'] = packet.tcp.analysis_ack_rtt
            else:
                line['rtt'] = " "        
            print(line)   
    return line

def get_data_from_ipv6(packet):
    line={}
    basic_keys = ['time', 'len', 'protocol', 'src', 'dst', 'dscp', 'srcport', 'dstport']
    if packet.transport_layer == "UDP":        
        prot_ip_port_src=('UDP', packet.ipv6.src.value, str(packet.udp.srcport))
        prot_ip_port_dst=('UDP', packet.ipv6.dst.value, str(packet.udp.dstport))
        if (prot_ip_port_src in list_of_prot_ip_port) or (prot_ip_port_dst in list_of_prot_ip_port):        
            print('MATCH UDP v6!!!')                
            values=[packet.sniff_timestamp, packet.ip.len, packet.transport_layer, packet.ip.src.value, packet.ip.dst.value,packet.ip.dsfield.dscp, packet.tcp.srcport, packet.tcp.dstport] 
            for key, value in zip(basic_keys, values):
                line[key] = value
                                                   
    # print(prot_ip_port_dst, prot_ip_port_src)            
    if packet.transport_layer == "TCP":           
        prot_ip_port_src=('TCP', packet.ipv6.src.value, str(packet.tcp.srcport))
        prot_ip_port_dst=('TCP', packet.ipv6.dst.value, str(packet.tcp.dstport))
        #print(prot_ip_port_src, '  ', prot_ip_port_dst)

        if (prot_ip_port_src in list_of_prot_ip_port) or (prot_ip_port_dst in list_of_prot_ip_port):        
            print('MATCH TCP v6!!!')

            # Loop Over Two Lists to Create a Dictionary using Zip                
            values=[packet.sniff_timestamp, packet.ipv6.plen, packet.transport_layer, packet.ipv6.src.value, packet.ipv6.dst.value,packet.ipv6.tclass.dscp, packet.tcp.srcport, packet.tcp.dstport] 
            for key, value in zip(basic_keys, values):
                line[key] = value                           
            if hasattr(packet.tcp, "analysis_ack_rtt"):
                line['rtt'] = packet.tcp.analysis_ack_rtt
            else:
                line['rtt'] = " "        
            print(line)   
    return line

def packet_callback(packet):
    global write2ndjson     
    global list_of_prot_ip_port

    try:
        
        '''Geht das asyncron, so dass die Liste nur ein update erhält, wenn sie sich verändert hat.'''
        line=[]
        if hasattr(packet, 'ip'):
            line=get_data_from_ip(packet)
        elif hasattr(packet, 'ipv6'):
            line=get_data_from_ipv6(packet)
        #print('line:', line)        
        if len(line) > 4:                
            write2ndjson.writeline2ndjson(line)          
    except:        
        pass
    


write2ndjson= Write2ndjson(file_name, data_path, 1000)

# create a new thread to fetch list of protocolip and port
thread_fetch_list_of_protcol_ip_port = Thread(target=get_socket_data)
# start the thread
thread_fetch_list_of_protcol_ip_port.start()

'''Main process to capture packet from interface and add packet to pdeque'''
capture = pyshark.LiveCapture(interface=CAPTUREINTERFACE, bpf_filter='ip or ip6', use_ek=True)
for packet in capture.sniff_continuously():
    capture.apply_on_packets(packet_callback)
       
