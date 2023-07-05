import wmi
import pyshark
from pyshark import ek_field_mapping
import pandas as pd



# http://timgolden.me.uk/python/wmi/tutorial.html

# https://learn.microsoft.com/en-us/previous-versions/windows/desktop/nettcpipprov/msft-nettcpconnection
#
#import pyperfmon

#---------------------------Einfaches Beispiel-------------------------------------------------------
#                   Get process IDs for specific application instances
c_default=wmi.WMI()
application="Teams.exe"
list_of_process_ids=[]
for process in c_default.Win32_Process(name=application):
   print(process.ProcessId, process.Name)
   list_of_process_ids.append(process.ProcessId)
for process in c_default.Win32_PerfRawData_PerfProc_Process():
    if process.IDProcess in list_of_process_ids:
        print(process.IDProcess)
#-----------------------Ende einfaches Beispiel-------------------------------------------------------
#-------------------------------------Change Namespace for MSFT_NetTCPConnection
c_cimv2 = wmi.WMI(namespace="StandardCimv2")
tcp_class=c_cimv2.MSFT_NetTCPConnection
#list_of_properties=['AggregationBehavior','AppliedSetting', 'AvailableRequestedStates', 'Caption', 'CommunicationStatus', 'CreationTime', 'Description', 'DetailedStatus', 'Directionality', 'ElementName', 'EnabledDefault', 'EnabledState', 'HealthState', 'InstallDate', 'InstanceID', 'LocalAddress', 'LocalPort', 'Name', 'OffloadState', 'OperatingStatus', 'OperationalStatus', 'OtherEnabledState', 'OwningProcess', 'PrimaryStatus', 'RemoteAddress', 'RemotePort', 'RequestedState', 'State', 'Status', 'StatusDescriptions', 'TimeOfLastStateChange', 'TransitioningToState']

list_of_ip_address=[]
#print(my_class.properties)
for item in tcp_class.instances():
        if item.OwningProcess in list_of_process_ids:
              #print(item.CreationTime,item.OwningProcess, item.LocalAddress, item.RemoteAddress, item.AppliedSetting,  item.Description)
              list_of_ip_address.append(item.RemoteAddress)
set_list_of_ip_address=set(list_of_ip_address)
set_list_of_ip_address.discard('0.0.0.0')
list_of_ip_address=list(set_list_of_ip_address)
print(list_of_ip_address)



'''Basic Info
https://www.wireshark.org/docs/dfref/t/tcp.html'''

'''print(dir(packet.tcp))
['__abstractmethods__', '__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattr__', '__getattribute__', '__getstate__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__setstate__', '__sizeof__', '__slots__', '__str__', '__subclasshook__', '__weakref__', '_abc_impl', '_field_has_subfields', '_fields_dict', '_get_field_value', '_get_nested_field', '_get_possible_layer_prefixes', '_layer_name', '_pretty_print_field', '_pretty_print_layer_fields', 'ack', 'all_field_names', 'analysis', 'checksum', 'completeness', 'dstport', 'field_names', 'flags', 'get', 'get_field', 'get_field_as_list', 'has_field', 'hdr', 'layer_name', 'len', 'nxtseq', 'port', 'pretty_print', 'seq', 'srcport', 'stream', 'time', 'urgent', 'window']'''

#tcp_capture = pyshark.LiveCapture(interface="Ethernet 3", use_ek=True)

if len(list_of_ip_address) > 0:
        #bpf_filter = "tcp and ("
        bpf_filter = "("
        for addr in list_of_ip_address[:-1]:
        
                bpf_filter = "%shost %s or " % (bpf_filter, addr)
        bpf_filter = "%shost %s)" % (bpf_filter, list_of_ip_address[-1])
print(bpf_filter)

#tcp_capture = pyshark.LiveCapture(interface='ethernet 3', bpf_filter=bpf_filter, use_ek=True)
tcp_capture = pyshark.LiveCapture(interface='ethernet',  use_ek=True)


df_rtcp=pd.DataFrame()

for packet in tcp_capture.sniff_continuously():    
    try:
        #print(dir(packet.tcp))
        #print(dir(packet.tcp.field_names))
        #print(packet.highest_layer)
        if (packet.ip.src.value in list_of_ip_address) or (packet.ip.dst in list_of_ip_address):
            print(f'protocol: {packet.transport_layer} src: {packet.ip.src.value} dst: {packet.ip.dst.value} RTT: {packet.tcp.analysis_ack_rtt}')
            
              #, RTT: {packet.tcp.analysis_ack_rtt}, iRTT: {packet.tcp.analysis.initial_rtt}')
        #print("RTT", packet.tcp.analysis_ack_rtt)
        #print("iRTT", packet.tcp.analysis.initial_rtt)

    except:
        pass