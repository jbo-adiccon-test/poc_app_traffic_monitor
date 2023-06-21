#!/usr/bin/env python

# Program to open and close socket
# AFM
# Adiccon Mai 2023


import socket
import os
import time
import pandas as pd
from io import StringIO
import ast

READER_PORT = 4000
SERVER_PORT = 4001
SHOW_PORT = 4002


global send_list
send_list = ""

# Listen to data_reader and data_show:
ip = socket.gethostbyname(socket.gethostname())
socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
socket.bind((ip, SERVER_PORT))
print("Data server started OK ...")

# Send to data_show
def socket_send(string):
    print("SENDING DATA ...")
    socket.sendto(bytes(string, "utf-8"), (ip, SHOW_PORT))
    print("OK")

# -----------------------------------------------------
#                 PROCESS DATA READER
# -----------------------------------------------------

def process_reader(data):
    global send_list
    send_list=send_list+data
    print(send_list)





# -----------------------------------------------------
#                  PROCESS DATA SHOW
# -----------------------------------------------------

def process_show(data):
    if data == "get_new_df":
        global send_list
        socket_send(str(send_list))
        send_list = ""
    else:
        pass




# -----------------------------------------------------
#                        LOOP
# -----------------------------------------------------


while True:
    data, add = socket.recvfrom(65536)
    #print(add)
    data = data.decode("utf-8")
    if add[1] == READER_PORT:
        print("data received")
        process_reader(data)
    if add[1] == SHOW_PORT:
        print("SHOW_PORT")
        process_show(data)

socket.close()
