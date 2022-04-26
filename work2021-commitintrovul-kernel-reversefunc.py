import pandas as pd
import csv
import os
import json
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlsplit
import time
list=[]
base_url='https://git.kernel.org'

u="https://android.googlesource.com/platform/system/core/+/014b01706cc64dc9c2ad94a96f62e07c058d0b5d"

headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36'}



def next_page_content(next_pageurl):
   log_req = requests.get(next_pageurl)
   soup_cont = BeautifulSoup(log_req.text, 'html.parser')
   return  soup_cont

#Get all table row
def get_table(content):
     # log_req = requests.get(next_url)
     # log_soup = BeautifulSoup(log_req.text, 'html.parser')
    # print(log_url)
     table = content.find('table', class_='list nowrap')
     return table


pagenumber=0

# get message
def check_sourcecode(n):
    dict_intro = {}
    # hist_commit = base_url + n['href']
    idcommit=re.findall('.*(id=.*)', str(n['href']))[0]
    # print(idcommit)
    hist_commit = find_make_url[0] + '/commit/' + fname + '?' + idcommit
    # hist_commit=log_url+'?'+idcommit
    # print(hist_commit)
    history_link = requests.get(hist_commit, headers=headers)
    # history_info = BeautifulSoup(history_link.text, 'html.parser')
    author = BeautifulSoup(history_link.text, 'html.parser')
    author_table = author.find('table', summary='commit info')
    author_name = author_table.find_all('tr')[0].find_all('td')[0].string
    author_date = author_table.find_all('tr')[0].find_all('td')[1].string
    blob_history = hist_commit.replace('/commit/', '/plain/')
    # print(blob_history)
    req_file = requests.get(blob_history)
    source = req_file.text
    # print(source)

    if newcode in source:
        intro_id = re.findall('.*id=(.*)', hist_commit)[0]
        # print(intro_id,'sssss')
        dict_intro['del_line'] = c
        dict_intro['intro_id'] = intro_id
        # print(dict_intro['intro_id'])
        dict_intro['intro_mess'] = n.string
        dict_intro['intro_author'] = author_name
        dict_intro['intro_date'] = author_date
        h["del_code"]["intro_commit_info"].append(dict_intro)
        # print(dict_intro)


def parse_page(url):
    log_req = requests.get(url)
    if log_req.status_code == requests.codes.ok:
        logsoup = BeautifulSoup(log_req.text, 'html.parser')
        table = logsoup.find('table', class_='list nowrap')
        try:
            ntr = 0
            for items in table.find_all('tr'):
                    links = items.find_all('a')
                # spans = items.find_all('span')
                # tds = items.find_all('td')
                # for l in links:
                    ntr = ntr + 1
                    # if links[0].string == d["message"] and len(msg) == 0:
                    if d['commit'] in links[0]['href'] and len(msg) == 0:

                        msg.append(links[0].string)
                        next_link = links[0].find_all_next('a')
                        nlc = 0
                        for n in next_link:
                            nlc = nlc + 1
                            if nlc < len(next_link):
                                try:
                                 # print(n)
                                 check_sourcecode(n)
                                except Exception as e:
                                    print(e)
                                    print(d['commit'])
                        else:                                               # when reach to the end of n loop and won't check more items
                            break
                    if len(msg)!= 0:       # only ckeck links when found msg in inferior page
                        try:
                            check_sourcecode(links[0])
                        except Exception as e:
                            print(e)
                            print(d['commit'])
            if logsoup.find('ul', {"class": "pager"}).findAll('li'):     #check pages to find msg
             next_page_text = logsoup.find('ul', {"class": "pager"}).findAll('li')[-1].text
             time.sleep(2)
             if next_page_text == '[next]':
                next_page_partial = logsoup.find('ul', {"class": "pager"}).findAll('li')[-1].find('a')['href']
                next_page_url = "https://git.kernel.org/{0}".format(next_page_partial)
                # print(next_page_url)
                parse_page(next_page_url)
        except Exception as e:
            print(e)
            print(d['commit'])
# with open("D:\\work 2021\\new 4.json", "r", encoding="utf8") as jread:
with open("D:\\work 2021\\json-intro -commit\\Kernel\\kernelfinal7.json", "r", encoding="utf8") as jread:
   data = json.load(jread)
   json.dumps(data, indent=2)
   try:
    for d in data:
     if 'linux-2.6.git' in d['url']:
            new_url = d['url'].replace('linux-2.6.git', 'linux.git')
            # print(new_url)
     else:
            new_url = d['url']
     req_link = requests.get(d["url"])
     author_info_fix = BeautifulSoup(req_link.text, 'html.parser')
     author_table_fix = author_info_fix.find('table', summary='commit info')
     author_name_fix = author_table_fix.find_all('tr')[0].find_all('td')[0].string
     author_date_fix = author_table_fix.find_all('tr')[0].find_all('td')[1].string
     d['date'] = author_date_fix
     d['name'] = author_name_fix
     try:
      for f in d["files"]:
        fname=str(f["fname"]).replace('-','/')
        print(fname)
        make_url= new_url.split('/',10)
        # print(make_url)
        if 'a=commit;' in new_url:
         find_make_url= re.findall('(.*);a=commit',new_url)
        else:
         find_make_url= re.findall('(.*)/commit',new_url)
        # print(find_make_url[0])
        # new_url= make_url[0]+'//'+make_url[2]+'/'+make_url[3]+'/'+make_url[4]+'/'+make_url[5]+'/'+make_url[6]+'/'+make_url[7]+'/'+make_url[8]
        # commit_url=new_url+'/'+ fname
        # print(new_url)
        # r = requests.get(commit_url)
      # print(d["url"]+'/'+fname)
      #   soup = BeautifulSoup(r.text, 'html.parser')
        log_url = find_make_url[0]+'/log/'+ fname
        print(log_url)
        try:
          for h in f['hunk']:
            i = 0
            if len(h["del_code"])!=0:
              h["del_code"]["intro_commit_info"]=[]
         # if len(h["del_code"]) !=0:

              for c in h["del_code"]["content"]:
                if len(c[1:].strip()) > 3:
                  newcode = c[1:].strip()
                  msg = []
                  parse_page(log_url)
        except Exception as e:
            print(e)
            print(d['commit'])
     except Exception as e:
         print(e)
         print(d['commit'])
     list.append(d)
   except Exception as e:
       print(e)
       # print(d['commit'])

with open('D:\\kernel-mined-reversed100.json', 'w') as writejson:
                json.dump(list, writejson, sort_keys=True, indent=4, ensure_ascii=False)


