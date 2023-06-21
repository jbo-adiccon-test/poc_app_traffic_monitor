import wmi
# http://timgolden.me.uk/python/wmi/tutorial.html

# https://learn.microsoft.com/en-us/previous-versions/windows/desktop/nettcpipprov/msft-nettcpconnection
#
import pyperfmon
import pyshark

import socket

READER_PORT = 4000
SERVER_PORT = 4001
SHOW_PORT = 4002

def socket_send(string):
    ip = socket.gethostbyname(socket.gethostname())
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ip, READER_PORT))
    s.sendto(bytes(string, "utf-8"), (ip, SERVER_PORT))
    s.close()



#---------------------------Einfaches Beispiel-------------------------------------------------------
#                   Get process IDs for specific application instances
c_default=wmi.WMI()
c_cimv2 = wmi.WMI(namespace="StandardCimv2")
capture = pyshark.LiveCapture(interface='ethernet 3',  use_ek=True)
application="Teams.exe"
while True:
        list_of_process_ids=[]
        for process in c_default.Win32_Process(name=application):
                #print(process.ProcessId, process.Name)
                list_of_process_ids.append(process.ProcessId)
#         for process in c_default.Win32_PerfRawData_PerfProc_Process():
#                 if process.IDProcess in list_of_process_ids:
#                         print(process.IDProcess)
# 
#-----------------------Ende einfaches Beispiel-------------------------------------------------------
#-------------------------------------Change Namespace for MSFT_NetTCPConnection

        '''Here we get local and remote ip adresses as well as port numbers, for tcp endpoids for all process instances created for the given program'''

        tcp_class=c_cimv2.MSFT_NetTCPConnection
        #list_of_properties=['AggregationBehavior','AppliedSetting', 'AvailableRequestedStates', 'Caption', 'CommunicationStatus', 'CreationTime', 'Description', 'DetailedStatus', 'Directionality', 'ElementName', 'EnabledDefault', 'EnabledState', 'HealthState', 'InstallDate', 'InstanceID', 'LocalAddress', 'LocalPort', 'Name', 'OffloadState', 'OperatingStatus', 'OperationalStatus', 'OtherEnabledState', 'OwningProcess', 'PrimaryStatus', 'RemoteAddress', 'RemotePort', 'RequestedState', 'State', 'Status', 'StatusDescriptions', 'TimeOfLastStateChange', 'TransitioningToState']

        list_of_ip_address=[]        
        list_of_prot_address_port=[]
        #print(my_class.properties)
        for item in tcp_class.instances():
                
                if item.OwningProcess in list_of_process_ids:
                       #print(item)
                #print(item.CreationTime,item.OwningProcess, item.LocalAddress, item.RemoteAddress, item.AppliedSetting,  item.Description)
                        list_of_ip_address.append(item.RemoteAddress)
                        list_of_prot_address_port.append(('TCP', item.RemoteAddress, item.RemotePort))
                        list_of_prot_address_port.append(('TCP', item.LocalAddress, item.LocalPort))
        print(list_of_prot_address_port)       #list_of_address_port.append((item.LocalAddress, item.LocalPort))
        


        udp_class=c_cimv2.MSFT_NetUDPEndpoint
        #list_of_properties=['AggregationBehavior','AppliedSetting', 'AvailableRequestedStates', 'Caption', 'CommunicationStatus', 'CreationTime', 'Description', 'DetailedStatus', 'Directionality', 'ElementName', 'EnabledDefault', 'EnabledState', 'HealthState', 'InstallDate', 'InstanceID', 'LocalAddress', 'LocalPort', 'Name', 'OffloadState', 'OperatingStatus', 'OperationalStatus', 'OtherEnabledState', 'OwningProcess', 'PrimaryStatus', 'RemoteAddress', 'RemotePort', 'RequestedState', 'State', 'Status', 'StatusDescriptions', 'TimeOfLastStateChange', 'TransitioningToState']
        '''Here we get local ip adresses as well as port numbers, for udp endpoids for all process instances created for the given program. WE don't need remote adresses, since udp flows use same local endpoints'''
        for item in udp_class.instances():        
                if item.OwningProcess in list_of_process_ids:
                #print(item.CreationTime,item.OwningProcess, item.LocalAddress, item.RemoteAddress, item.AppliedSetting,  item.Description)
                        # list_of_ip_address.append(item.LocalAddress)
                        list_of_prot_address_port.append(('UDP', item.LocalAddress, item.LocalPort))
        
        # '''remove all duplicates and global defaults'''
        # set_list_of_ip_address=set(list_of_ip_address)
        # set_list_of_ip_address.discard('0.0.0.0')
        # set_list_of_ip_address.discard('::')
        # list_of_ip_address=list(set_list_of_ip_address)

        # string_of_ip_addresses = ' '.join([str(elem)+';' for elem in list_of_ip_address])
        #print(string_of_ip_addresses)
        
        # '''remove all duplicates and global defaults'''
        list_of_prot_address_port = list(set(list_of_prot_address_port))
        list_of_prot_address_port = [ (a,b,c) for a,b,c in list_of_prot_address_port if ( b != '::' ) ]
        list_of_prot_address_port = [ (a,b,c) for a,b,c in list_of_prot_address_port if ( b != '0.0.0.0' ) ]
        
        ''' serialization of tuples to be transmitted as string so that we can reconstruct tuples again'''
        string_of_prot_address_port=' '.join([str(elem[0])+" "+str(elem[1])+" "+str(elem[2]) for elem in list_of_prot_address_port])
        string_of_prot_address_port=string_of_prot_address_port+"\n"        
        print(string_of_prot_address_port)
               
        
        
        try:
                #socket_send(str(string_of_ip_addresses))
                socket_send(str(string_of_prot_address_port))
                print('send succeded')
        except:
                print("send failed")