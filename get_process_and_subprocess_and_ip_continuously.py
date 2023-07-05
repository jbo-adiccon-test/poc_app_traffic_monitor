import functools
import wmi
import time

import socket


READER_PORT = 4000
SERVER_PORT = 4001
SHOW_PORT = 4002

teams='teams'
webex='webex'
outlook='outlook'
slack='slack'
#webex_filter=['webex']
app=slack



def socket_send(string):
    ip = socket.gethostbyname(socket.gethostname())
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ip, READER_PORT))
    s.sendto(bytes(string, "utf-8"), (ip, SERVER_PORT))
    s.close()




c = wmi.WMI(moniker="root\\cimv2")
c_cimv2 = wmi.WMI(moniker='root/standardcimv2')


def find_process_ids_by_name(process_name):
    #c = wmi.WMI(moniker="root\\cimv2") 
    process_ids = []
    for process in c.win32_process():
        if process_name.lower() in process.Name.lower():
            process_ids.append(process.ProcessId)
    return process_ids

def get_process_name_by_pid(pid):    
    process_name = ""
    for process in c.Win32_Process(ProcessId=pid):
        process_name = process.Name
        break
    return process_name

#cache pids found
@functools.lru_cache()
def find_subprocess_ids(parent_pid):
    #c = wmi.WMI(moniker="root\\cimv2") 
    subprocess_ids = []
    for process in c.win32_process(ParentProcessId=parent_pid):
        subprocess_ids.append(process.ProcessId)
        subprocess_ids.extend(find_subprocess_ids(process.ProcessId))
    return subprocess_ids



def get_flows_of_applications(list_of_process_ids):
        list_of_prot_address_port=[]
        if list_of_process_ids != []:
            set_of_pids=set(list_of_process_ids)
            tcp_class=c_cimv2.MSFT_NetTCPConnection()         
            for item in tcp_class:
                    
                    if item.OwningProcess in set_of_pids:                        
                            list_of_prot_address_port.append(('TCP', item.RemoteAddress, item.RemotePort))
                            list_of_prot_address_port.append(('TCP', item.LocalAddress, item.LocalPort))    
            
            udp_class=c_cimv2.MSFT_NetUDPEndpoint()      
                    
            # Here we get local ip adresses as well as port numbers, for udp endpoids for all process instances created for the given program. WE don't need remote adresses, since udp flows use same local endpoints'''
            for item in udp_class:        
                    if item.OwningProcess in set_of_pids:
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

def get_list_of_process_ids(target_app_name):
    target_pids = find_process_ids_by_name(target_app_name)
    
    if not target_pids:
        list_of_process_ids=[]
        print(f"No process found for '{target_app_name}'.")
    else:
        list_of_process_ids = [ x for x in target_pids ]
        print(f"Process ID(s) for '{target_app_name}': {target_pids}")
        for pid in target_pids:
            subprocess_ids = find_subprocess_ids(pid)
            #subprocess_name = get_process_name_by_pid(pid)
            #print(f"Subprocess ID(s) for '{target_app_name}' (PID {pid}, subprocess_name {subprocess_name}): {subprocess_ids}" )
            list_of_process_ids += subprocess_ids
    return list_of_process_ids




def main():
         #                   Get process IDs for specific application instances
    while True:
        start = time.time()            
        target_app_name = app  # Replace with the application name you want to find (e.g., "chrome.exe", "notepad.exe")
        list_of_process_ids=get_list_of_process_ids(target_app_name)
        string_of_prot_address_port=get_flows_of_applications(list_of_process_ids)
        try:
            #socket_send(str(string_of_ip_addresses))
            socket_send(str(string_of_prot_address_port))
            print('send succeded')
        except:
            print("send failed")
        print(time.time() - start,'\n') 
        #print(string_of_prot_address_port) 


if __name__ == "__main__":
     main()     
