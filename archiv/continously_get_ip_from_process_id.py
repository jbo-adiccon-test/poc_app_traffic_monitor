import wmi
import mi
# http://timgolden.me.uk/python/wmi/tutorial.html

# https://learn.microsoft.com/en-us/previous-versions/windows/desktop/nettcpipprov/msft-nettcpconnection

# without sub processes!
#
import pyshark
import socket
import time

READER_PORT = 4000
SERVER_PORT = 4001
SHOW_PORT = 4002

teams_filter=['teams.exe']
webex_filter=['webex', 'atmgr']
outlook_filter=['outlook.exe']
slack_filter=['slack']
#webex_filter=['webex']
my_filter_list=slack_filter



def socket_send(string):
    ip = socket.gethostbyname(socket.gethostname())
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ip, READER_PORT))
    s.sendto(bytes(string, "utf-8"), (ip, SERVER_PORT))
    s.close()

def get_list_of_process_ids():
        
        conn=wmi.WMI(moniker="root\\cimv2")        
        list_of_process_ids=[]
        
        for i in conn.win32_process():
                #print(i)
                for name in my_filter_list:
                        if name in i.name.lower():
                                list_of_process_ids.append(i.ProcessId)
        '''
        with mi.Application() as a:
                with a.create_session(protocol=mi.PROTOCOL_WMIDCOM) as s:
                        with s.exec_query(
                                u"root\\cimv2", u"select * from win32_process") as q:
                                i = q.get_next_instance()
                                while i is not None:
                                        s = i[u'name']
                                        p= i[u'ProcessId']

                                        if s.lower() in my_filter_list:
                                                list_of_process_ids.append(p)

                                        #print(i[u'ProcessId'])
                                        i = q.get_next_instance()

        # process_list=c_default.Win32_Process()

        # for process in process_list:
        #         if any(True for x in my_filter_list if x in str(process.Name.lower())):              
        #                 list_of_process_ids.append(process.ProcessId)

        '''
        print('list of process_id ', list_of_process_ids)
        return list_of_process_ids


def get_flows_of_applications(list_of_process_ids):
        list_of_prot_address_port=[]
        '''  
        with mi.Application() as a:
                with a.create_session(protocol=mi.PROTOCOL_WMIDCOM) as s:
                        with s.exec_query(
                                u"root\\standardcimv2", u"select * from * ") as q:
                               # print(len(q))
                                i=q.get_next_class()                          
                                while i is not None:
                                        
                                        print(i)
                                        i = q.get_next_instance()
        
        '''
       
        #----Change Namespace for MSFT_NetTCPConnection----
        c_cimv2 = wmi.WMI(moniker='root/standardcimv2')
        #c_cimv2=wmi.WMI()
        tcp_class=c_cimv2.MSFT_NetTCPConnection()         
        for item in tcp_class:
                
                if item.OwningProcess in list_of_process_ids:                        
                        list_of_prot_address_port.append(('TCP', item.RemoteAddress, item.RemotePort))
                        list_of_prot_address_port.append(('TCP', item.LocalAddress, item.LocalPort))    
        
        udp_class=c_cimv2.MSFT_NetUDPEndpoint()      
                
        # Here we get local ip adresses as well as port numbers, for udp endpoids for all process instances created for the given program. WE don't need remote adresses, since udp flows use same local endpoints'''
        for item in udp_class:        
                if item.OwningProcess in list_of_process_ids:
                       #print(item) 
                        list_of_prot_address_port.append(('UDP', item.LocalAddress, item.LocalPort))                       
        # # '''remove all duplicates and global defaults'''
        list_of_prot_address_port = list(set(list_of_prot_address_port))       
        list_of_prot_address_port = [ (a,b,c) for a,b,c in list_of_prot_address_port if ( b not in [ '127.0.0.1', '::', '0.0.0.0'  ] ) ]
        
        # ''' serialization of tuples to be transmitted as string so that we can reconstruct tuples again'''
        string_of_prot_address_port=' '.join([str(elem[0])+" "+str(elem[1])+" "+str(elem[2]) for elem in list_of_prot_address_port])
        string_of_prot_address_port=string_of_prot_address_port+"\n"        
        #print(string_of_prot_address_port)
        return string_of_prot_address_port        




#                   Get process IDs for specific application instances
while True:
        start = time.time()
        list_of_process_ids=get_list_of_process_ids()
        #print(list_of_process_ids)
               
        string_of_prot_address_port=get_flows_of_applications(list_of_process_ids)
        #end =time.time()
        print(time.time() - start,'\n') 
        print(string_of_prot_address_port) 
        
        try:
                #socket_send(str(string_of_ip_addresses))
                socket_send(str(string_of_prot_address_port))
                print('send succeded')
        except:
                print("send failed")
