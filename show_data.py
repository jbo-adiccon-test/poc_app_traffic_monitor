'''
Read Data and Plot with Dash
'''


# importing the module
import json
import pandas as pd
a = []
file_name='teams.ndjson'
# reading the data from the file
i=0
df = pd.read_json(file_name, lines=True)


#Create new column "flow" with tuples from scr, scrport, dst, dstport
df['flow'] = list(zip(df.src, df.srcport, df.dst, df.dstport))
print(df.size)



