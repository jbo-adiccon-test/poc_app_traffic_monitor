# SuperFastPython.com
# example of returning a value from a thread
from time import sleep
from threading import Thread
 
# function executed in a new thread
def task():
    # block for a moment
    sleep(1)
    # correctly scope the global variable
    global data
    # store data in the global variable
    data = 'Hello from a new thread'
 
# define the global variable
data = None
# create a new thread
thread = Thread(target=task)
# start the thread
thread.start()
# wait for the thread to finish
thread.join()
# report the global variable
print(data)
