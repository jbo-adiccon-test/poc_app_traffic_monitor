import wmi
# http://timgolden.me.uk/python/wmi/tutorial.html

# https://learn.microsoft.com/en-us/previous-versions/windows/desktop/nettcpipprov/msft-nettcpconnection
#
import pyperfmon

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
print(len(list_of_ip_address))


udp_class=c_cimv2.MSFT_NetUDPEndpoint
#list_of_properties=['AggregationBehavior','AppliedSetting', 'AvailableRequestedStates', 'Caption', 'CommunicationStatus', 'CreationTime', 'Description', 'DetailedStatus', 'Directionality', 'ElementName', 'EnabledDefault', 'EnabledState', 'HealthState', 'InstallDate', 'InstanceID', 'LocalAddress', 'LocalPort', 'Name', 'OffloadState', 'OperatingStatus', 'OperationalStatus', 'OtherEnabledState', 'OwningProcess', 'PrimaryStatus', 'RemoteAddress', 'RemotePort', 'RequestedState', 'State', 'Status', 'StatusDescriptions', 'TimeOfLastStateChange', 'TransitioningToState']

list_of_ip_address=[]
#print(my_class.properties)
for item in udp_class.instances():        
        if item.OwningProcess in list_of_process_ids:
              #print(item.CreationTime,item.OwningProcess, item.LocalAddress, item.RemoteAddress, item.AppliedSetting,  item.Description)
              list_of_ip_address.append(item.LocalAddress)
set_list_of_ip_address=set(list_of_ip_address)
#set_list_of_ip_address.discard('0.0.0.0')
list_of_ip_address=list(set_list_of_ip_address)
print(f'UDP {list_of_ip_address}')
# udp_class=c_cimv2.MSFT_NetUDPEndpoint
# for item in udp_class.instances():  
#         print(item.CreationTime,item.OwningProcess, item.LocalAddress )



'''instance of Win32_PerfRawData_PerfProc_Process
{
        CreatingProcessID = 612;
        ElapsedTime = "133311294184509113";
        Frequency_Object = "10000000";
        Frequency_PerfTime = "10000000";
        Frequency_Sys100NS = "10000000";
        HandleCount = 240;
        IDProcess = 10068;
        IODataBytesPersec = "1641456";
        IODataOperationsPersec = "4";
        IOOtherBytesPersec = "1518";
        IOOtherOperationsPersec = "5018";
        IOReadBytesPersec = "1641456";
        IOReadOperationsPersec = "4";
        IOWriteBytesPersec = "0";
        IOWriteOperationsPersec = "0";
        Name = "WmiPrvSE#2";
        PageFaultsPersec = 20290;
        PageFileBytes = "8622080";
        PageFileBytesPeak = "9748480";
        PercentPrivilegedTime = "1093750";
        PercentProcessorTime = "1562500";
        PercentUserTime = "468750";
        PoolNonpagedBytes = 11416;
        PoolPagedBytes = 78192;
        PriorityBase = 8;
        PrivateBytes = "8622080";
        ThreadCount = 9;
        Timestamp_Object = "133311294186072846";
        Timestamp_PerfTime = "87144277764";
        Timestamp_Sys100NS = "133311294186072846";
        VirtualBytes = "2203406774272";
        VirtualBytesPeak = "2203418243072";
        WorkingSet = "15478784";
        WorkingSetPeak = "16445440";
        WorkingSetPrivate = "7479296";
};


def print_classes(filter):
        c_classes=c.classes
        list_of_classes=[]
        for c_class in c_classes:
                if c_class.find(filter) > 0:
                        print(c_class)

print_classes('')

print(dir(c))
['__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattr__', '__getattribute__', '__gt__', '__hash__', 
'__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', '_cached_classes', '_classes', '_classes_map', '_getAttributeNames', '_get_classes', '_namespace', '_raw_query', 'classes', 'fetch_as_classes', 'fetch_as_lists', 'get', 'handle', 'instances', 'new', 'new_instance_of', 'query', 'subclasses_of', 'watch_for', 'wmi']


# Retrieve Objects
HAT FUNKTONIERT
my_class=c.Win32_PerfRawData_TCPIPCounters_TCPIPPerformanceDiagnosticsPerCPU
print(my_class(Name="CPU0"))
for x in my_class(Name='CPU0'):
        print(x)
[<_wmi_object: b'\\\\HV3-JBO\\root\\cimv2:Win32_PerfRawData_TCPIPCounters_TCPIPPerformanceDiagnosticsPerCPU.Name="CPU0"'>]

instance of Win32_PerfRawData_TCPIPCounters_TCPIPPerformanceDiagnosticsPerCPU
{
        Frequency_Object = "0";
        Frequency_PerfTime = "0";
        Frequency_Sys100NS = "10000000";
        Name = "CPU0";
        TCPcurrentconnections = 2;
        Timestamp_Object = "0";
        Timestamp_PerfTime = "0";
        Timestamp_Sys100NS = "133311551789185226";
};
'''





#-------------------------------------Change Namespace for MSFT_NetTCPConnection


#my_class=c.MSFT_NetTransportConnection
'''{
  string   Caption;
  string   Description;
  string   ElementName;
  datetime InstallDate;
  string   Name;
  uint16   OperationalStatus[];
  string   StatusDescriptions[];
  string   Status;
  uint16   HealthState;
  uint16   CommunicationStatus;
  uint16   DetailedStatus;
  uint16   OperatingStatus;
  uint16   PrimaryStatus;
  string   OtherEnabledState;
  uint16   EnabledDefault = 2;
  datetime TimeOfLastStateChange;
  uint16   TransitioningToState = 12;
  uint16   AvailableRequestedStates[];
  string   InstanceID;
  uint16   EnabledState;
  uint16   RequestedState = 5;
  uint16   Directionality;
  uint16   AggregationBehavior;
  string   LocalAddress;
  uint16   LocalPort;
  string   RemoteAddress;
  uint16   RemotePort;
  uint8    State;
  uint8    AppliedSetting;
  uint32   OwningProcess;
  datetime CreationTime;
  uint8    OffloadState;
};
'''
    