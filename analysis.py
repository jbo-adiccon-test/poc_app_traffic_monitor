import os
import pandas as pd
import time

from dash import Dash, dcc, html, Input, Output, callback
import plotly.express as px

global df_group
df_group = pd.DataFrame()

working_dir=r'C:\Users\bodensohn\git\poc_app_traffic_monitor\data\163732-slack'
name_it='slack.ndjson'
time_interval='10s'
period=400

#name_it='4_225857-outlook.ndjson'
def read_list_of_files(working_dir): 
    read_path=working_dir
    file_list=os.listdir(path=read_path)
    file_list=pd.Series(file_list)
    return file_list

def read_list_of_files_within_time(working_dir, period):   
    # First we retreive creation time of latest file
    # Get a list of all files in the directory
    new_file_list=[]
    files = os.listdir(working_dir)
    # Initialize variables to track the latest creation time and the corresponding file
    latest_creation_time = 0
    latest_file = None
    # Loop through the files and find the latest creation time
    for file in files:
        file_path = os.path.join(working_dir, file)
        if os.path.isfile(file_path):
            creation_time = os.path.getctime(file_path)
            if creation_time > latest_creation_time:
                latest_creation_time = creation_time
                # latest_file = file_path

    #os.listdir(path=read_path)
    #file_list = os.listdir(path=read_path)

    try:
        for file in files:
            file_path = os.path.join(working_dir, file)
            # if os.path.isfile(path) and (os.stat(path).st_ctime > time.time() - 1200):
            #     old_files.append(filename)

            if os.path.isfile(file_path) and (os.stat(file_path).st_ctime > latest_creation_time - period):
                new_file_list.append(file)            
    except:
        pass   
    return set(new_file_list)


def create_basic_dataframe(working_dir, period):
    '''Returns data frame created from file in working_dir'''
    df_file=pd.DataFrame()
        #read all data from filelist which have outlook.ndjson
    #file_list=read_list_of_files(working_dir, period)  
    file_list=read_list_of_files_within_time(working_dir, period)  
    for filename in file_list:
        if (filename.find(name_it)!=-1):
            try:
                file_path = os.path.join(working_dir, filename)
                # df_read=pd.read_json(file_path, lines=True)
                # df_read['time']=df_read['time'].astype('string')
                # df_read['timestamp']=pd.to_datetime(df_read['time'], origin='unix', unit='s')
                # df_read['interval']=pd.DatetimeIndex(df_read['timestamp']).ceil(time_interval)
                # df_read['flow_info'] = list(zip(df_read.protocol,df_read.src, df_read.srcport, df_read.dst, df_read.dstport))                
                # # df_file=pd.concat([df_file, df_read])
                df_file = pd.concat([df_file, pd.read_json(file_path, lines=True)])                  
            except Exception as ex:  # pylint: disable=broad-except
                print('error in create_basic_dataframe')
                continue
    print(df_file.columns)         
    df_file['time']=df_file['time'].astype('string')
    df_file['timestamp']=pd.to_datetime(df_file['time'], origin='unix', unit='s')
    df_file['interval']=pd.DatetimeIndex(df_file['timestamp']).ceil(time_interval)
    df_file['flow_info'] = list(zip(df_file.protocol,df_file.src, df_file.srcport, df_file.dst, df_file.dstport))

    return df_file 

def create_df_group(df_file, time_interval):
    df_group = pd.DataFrame({'counts': df_file.groupby('interval')[['flow_info', 'len','dscp']].value_counts()})
    df_group = df_group.reset_index()
    df_group.to_csv('analysis.txt', sep='\t', header=True, index=False)
    return df_group




def main():
    global df_group
    df_file=pd.DataFrame()
    df_file=create_basic_dataframe(working_dir, period)
    start_time=time.time()     
    df_group = create_df_group(df_file, time_interval)
    print(time.time()-start_time)  
    
    app1 = Dash(__name__)
    app1.layout = html.Div([
        dcc.Graph(
            id='graph1', figure={}         
        ),
        dcc.Interval(
                    id='interval-component',
                    interval=2*1000,
                    n_intervals=0)
    ])

    @callback(Output('graph1', 'figure'), Input('interval-component', 'n_intervals'))

    def update_data(n_intervals):
        global df_group
        y_parameter='counts'
        if y_parameter =="counts":
            df_plot_data=create_df_group(df_file, time_interval)
            x_parameter='interval'
        elif y_parameter in ['dscp', 'rtt', 'len']:
            df_plot_data=df_file
            x_parameter='timestamp'
       
        figure=px.scatter(df_plot_data, x=x_parameter, y=y_parameter,
                        size="len", color="flow_info", hover_name="dscp",
                        log_x=False, size_max=30)
        return figure




    app1.run_server(debug=True)



    

if __name__ == '__main__':
    main()