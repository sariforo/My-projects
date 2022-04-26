import csv
import json
import pandas as pd
import re
import datetime
from dateutil.parser import parse
from datetime import datetime

# datetime_list = [
#     parse('Thu Mar 8 13:37:03 2018 +0200'),
#     parse('Tue Apr 2 12:15:10 2013 +0300'),
# ]
#
# # parsetime=parse('Thu Mar 8 13:37:03 2018')
# # print(parsetime)
# oldest = min(datetime_list)
# print(oldest)
list = []
count_true=0
count_false=0
with open("D:\\work 2021\\Result_json\\TOTAL2.json", "r", encoding="utf8") as jread:
    # with open("D:\\work 2021\\new 4.json", "r", encoding="utf8") as jread:
    data = json.load(jread)
    json.dumps(data, indent=2)
    for d in data:
        try:
            for f in d['files']:
                try:
                    for h in f["hunk"]:
                        # print(parse(d["date"]))
                        # i = 0
                         if len(h["del_code"]) != 0:
                              if h['self_fix']=='true':
                                  count_true = count_true+1
                              elif  h['self_fix']=='false':
                                  count_false=count_false+1

                except Exception as e:
                    print(e)
        except Exception as e:
            print(e)
            print(d['commit'])

print('number of self-fixed: ', count_true)
print('number of non-self-fixed: ', count_false)

