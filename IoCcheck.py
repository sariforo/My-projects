import argparse
import csv
from datetime import datetime
import os
import json
import IndicatorTypes
from dateutil.parser import parse
import configparser
import Utils



parser = argparse.ArgumentParser()
parser.add_argument('-i', help='Name of the ini file that holds the API keys', metavar='ini-file',
                    default=os.path.dirname(os.path.abspath(__file__)) + '\my.ini')
parser.add_argument("-f", "--inputfile", type=argparse.FileType('r'), help="file one")
args = parser.parse_args()


pulses = list()
if args.i:
    config = configparser.ConfigParser()
    config.read(args.i)
    alienkey = config['DEFAULT']['Al_PUBLIC_API_KEY']
    bazaarkey = config['DEFAULT']['MB_PUBLIC_API_KEY']
    mispurl = config['MISP']['MISP_URLS']
    mispkey = config['MISP']['MISP_AUTH_KEYS']
    #kasperkey = config['DEFAULT']['OptK_PUBLIC_API_KEY']
    kasperkey= config['DEFAULT']['Optk_PUBLIC_API_KEY_sannio']
    #kasperkey= config['DEFAULT']['Optk_PUBLIC_API_KEY_yahoo']
    hashlookup_url = config['HASHLOOKUP']['HASHLOOKUP_URLS']
    virustotalkey = config['DEFAULT']['VT_PUBLIC_API_KEY']
    #virustotalkey = config['DEFAULT']['VT_PUBLIC_API_KEY_yahoo'] #300 left
    #virustotalkey = config['DEFAULT']['VT_PUBLIC_API_KEY_sannio']

def vt_search():
    indicator_vt_details = Utils.get_indicator_vt(row['indicator_type'], row['indicator'], virustotalkey)
    if 'data' in indicator_vt_details :
     if len(indicator_vt_details['data']) > 0:
        res_vt = indicator_vt_details['data'][0]
        stat = {'last_analysis_stats': res_vt['attributes']['last_analysis_stats'],
                'total_votes': res_vt['attributes']['total_votes']}
        '''
        "last_analysis_stats": {
        "harmless": <int>,
        "malicious": <int>,
        "suspicious": <int>,
        "timeout": <int>,
        "undetected": <int>       
        '''
        if row['indicator_type'] == 'url' or row['indicator_type'] == 'md5' or row['indicator_type'] == 'sha256' or row[
            'indicator_type'] == 'sha1':
            if 'first_submission_date' in res_vt['attributes']:
                vt_first_submission_time = res_vt['attributes']['first_submission_date']
                vt_date = datetime.fromtimestamp(vt_first_submission_time)
                diff_time = parse(row["date"]) - vt_date
                if diff_time.total_seconds() < 0:
                    row['diff_time']['virustime'] = {'date': vt_date, 'diff':{'sec': diff_time.total_seconds(),
                                                  'min': diff_time.total_seconds() / 60,
                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                  'day': diff_time.days},'cmp': 'later' }
                else:
                    row['diff_time']['virustime'] = {'date': vt_date, 'diff':{'sec': diff_time.total_seconds(),
                                                  'min': diff_time.total_seconds() / 60,
                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                  'day': diff_time.days}, 'cmp': 'sooner'}
                row['observed_source']['virustotal'] = True
                row['IOC_Status']['virustotal'] = stat

            else:

                row['diff_time']['virustime'] = 'null'
                row['observed_source']['virustotal'] = True
                row['IOC_Status']['virustotal'] = stat

                '''
                DOMAIN
                 "creation_date": <int:timestamp>,

                 IP
                  "whois_date": <int:timestamp>

                  url, hash
                   "first_submission_date": <int:timestamp>, 
                '''
        elif row['indicator_type'] == 'domain':
            if 'creation_date' in res_vt['attributes']:
                vt_first_submission_time = res_vt['attributes']['creation_date']
                vt_date = datetime.fromtimestamp(vt_first_submission_time)
                diff_time = parse(row["date"]) - vt_date
                if diff_time.total_seconds() < 0:
                    row['diff_time']['virustime'] = {'date': vt_date,'diff':{'sec': diff_time.total_seconds(),
                                                  'min': diff_time.total_seconds() / 60,
                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                  'day': diff_time.days}, 'cmp': 'later'}
                else:
                    row['diff_time']['virustime'] = {'date': vt_date,'diff':{'sec': diff_time.total_seconds(),
                                                  'min': diff_time.total_seconds() / 60,
                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                  'day': diff_time.days}, 'cmp': 'sooner'}

                row['observed_source']['virustotal'] = True
                row['IOC_Status']['virustotal'] = stat
            else:
                row['diff_time']['virustime'] = 'null'
                row['observed_source']['virustotal'] = True
                row['IOC_Status']['virustotal'] = stat
        elif row['indicator_type'] == 'ip':
            if 'whois_date' in res_vt['attributes']:
                vt_first_submission_time = res_vt['attributes']['whois_date']
                vt_date = datetime.fromtimestamp(vt_first_submission_time)
                diff_time = parse(row["date"]) - vt_date
                if diff_time.total_seconds() < 0:
                    row['diff_time']['virustime'] = {'date': vt_date,'diff':{'sec': diff_time.total_seconds(),
                                                  'min': diff_time.total_seconds() / 60,
                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                  'day': diff_time.days}, 'cmp': 'later'}
                else:
                    row['diff_time']['virustime'] = {'date': vt_date, 'diff':{'sec': diff_time.total_seconds(),
                                                  'min': diff_time.total_seconds() / 60,
                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                  'day': diff_time.days},'cmp': 'sooner'}

                row['observed_source']['virustotal'] = True
                row['IOC_Status']['virustotal'] = stat

            else:
                row['diff_time']['virustime'] = 'null'
                row['observed_source']['virustotal'] = True
                row['IOC_Status']['virustotal'] = stat
     else:
        row['observed_source']['virustotal'] = False
        row['diff_time']['virustime'] = 'not found'
        row['IOC_Status']['virustotal'] = 'not found'


# hashlookup
def hashlookup_search():
    indicator_lookup_details = Utils.get_hashlookup(hashlookup_url, row['indicator_type'], row['indicator'])
    if row['indicator_type'] == 'md5' or row['indicator_type'] == 'sha256' or row['indicator_type'] == 'sha1':
        if len(indicator_lookup_details) > 0 and not "message" in indicator_lookup_details:
            if "insert-timestamp" in indicator_lookup_details:
                convert_time = datetime.fromtimestamp(float(indicator_lookup_details['insert-timestamp']))
                diff_time = parse(row["date"]) - (convert_time)
                if diff_time.total_seconds() < 0:
                    row['diff_time']['hashlooktime'] = {'date': convert_time,'diff':{'sec': diff_time.total_seconds(),
                                                  'min': diff_time.total_seconds() / 60,
                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                  'day': diff_time.days}, 'cmp': 'later'}
                else:
                    row['diff_time']['hashlooktime'] = {'date': convert_time,'diff':{'sec': diff_time.total_seconds(),
                                                  'min': diff_time.total_seconds() / 60,
                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                  'day': diff_time.days}, 'cmp': 'sooner'}

                row['observed_source']['hashlookup'] = True
                '''
                hashlookuptrust = 50: no opinino
                hashlookuptrust < 50: less trust
                hashlookuptrust > 50: improved trust
                '''
                if indicator_lookup_details["hashlookup:trust"] == 50:
                    row['IOC_Status']['hashlookup'] = 'no opinion'
                elif indicator_lookup_details["hashlookup:trust"] < 50:
                    row['IOC_Status']['hashlookup'] = 'less trust'
                elif indicator_lookup_details["hashlookup:trust"] > 50:
                    row['IOC_Status']['hashlookup'] = 'improved trust'

            else:
                row['observed_source']['hashlookup'] = True
                row['diff_time']['hashlooktime'] = 'null'
                if indicator_lookup_details["hashlookup:trust"] == 50:
                    row['IOC_Status']['hashlookup'] = 'no opinion'
                elif indicator_lookup_details["hashlookup:trust"] < 50:
                    row['IOC_Status']['hashlookup'] = 'less trust'
                elif indicator_lookup_details["hashlookup:trust"] > 50:
                    row['IOC_Status']['hashlookup'] = 'improved trust'
        else:
            row['observed_source']['hashlookup'] = False
            row['diff_time']['hashlooktime'] = 'not found'
            row['IOC_Status']['hashlookup'] = 'not found'



def AlienVault_search(type):
    indicator_details = Utils.get_indicator_details(alienkey, type, row['indicator'])
    if indicator_details:
        if row['indicator_type'] == 'ip':
            first_date_alien = list()
            if indicator_details['passive_dns']['passive_dns'] != []:  # no first seen time available
                if 'first' in indicator_details['passive_dns']['passive_dns'][0]:
                    for t in indicator_details['passive_dns']['passive_dns']:
                        first_date_alien.append(t['first'])
                    min_date_alien = min(first_date_alien)
                    diff_time = (parse(row["date"]) - parse(min_date_alien))
                    if diff_time.total_seconds() < 0:
                        row['diff_time']['alientime'] = {'date': parse(min_date_alien),'diff':{'sec': diff_time.total_seconds(),
                                                  'min': diff_time.total_seconds() / 60,
                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                  'day': diff_time.days}, 'cmp': 'later'}
                    else:
                        row['diff_time']['alientime'] = {'date': parse(min_date_alien),'diff':{'sec': diff_time.total_seconds(),
                                                  'min': diff_time.total_seconds() / 60,
                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                  'day': diff_time.days}, 'cmp': 'sooner'}

                    row['observed_source']['alienvault'] = True
                    row['IOC_Status']['alienvault'] = {'malwarecount': indicator_details['malware']['count'],
                                                       'reputation': indicator_details['reputation']['reputation'], 'validation':indicator_details['general']['validation']}
                else:
                    row['observed_source']['alienvault'] = True
                    row['IOC_Status']['alienvault'] = 'absence'
                    row['diff_time']['alientime'] = 'null'

            else:
                if indicator_details['general']['pulse_info']['pulses'] != []:  # there is but no pulses

                    row['observed_source']['alienvault'] = True
                    row['IOC_Status']['alienvault'] = {'malwarecount': indicator_details['malware']['count'],
                                                       'reputation': indicator_details['reputation']['reputation'],'validation':indicator_details['general']['validation']}

                    row['diff_time']['alientime'] = 'null'

                else:
                    row['observed_source']['alienvault'] = False
                    row['diff_time']['alientime'] = 'not found'
                    row['IOC_Status']['alienvault'] = 'not found'


        # elif row['indicator_type']=='domain':
        #
        #     first_date_alien = list()
        #     if indicator_details['passive_dns']['passive_dns'] != []:  # no first seen time available
        #         for t in indicator_details['passive_dns']['passive_dns']:
        #             first_date_alien.append(t['first'])
        #         min_date_alien = min(first_date_alien)
        #         diff_time = (parse(row["date"]) - parse(min_date_alien))
        #         if diff_time.total_seconds() < 0:
        #             row['diff_time']['alientime'] = [parse(min_date_alien), 'later']
        #         else:
        #             row['diff_time']['alientime'] = [parse(min_date_alien), 'sooner']
        #
        #         row['diff_time']['alienvault'] = {'sec': diff_time.total_seconds(),
        #                                           'min': diff_time.total_seconds() / 60,
        #                                           'hour': diff_time.total_seconds() / 60 ** 2,
        #                                           'day': diff_time.days}
        #
        #         if row['diff_time']['alienvault'] != {}:
        #            row['observed_source']['alienvault'] = True
        #     else:
        #           row['observed_source']['alienvault'] = False

        elif row['indicator_type'] == 'md5' or row['indicator_type'] == 'sha256' or row['indicator_type'] == 'sha1':
            if indicator_details['general']['pulse_info']['pulses'] != []:
                if 'created' in indicator_details['general']['pulse_info']['pulses'][0]:
                    alientime = indicator_details['general']['pulse_info']['pulses'][0]['created']
                    diff_time = (parse(row["date"]) - parse(alientime))
                    if diff_time.total_seconds() < 0:
                        row['diff_time']['alientime'] = {'date': parse(alientime), 'diff':{'sec': diff_time.total_seconds(),
                                                  'min': diff_time.total_seconds() / 60,
                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                  'day': diff_time.days},'cmp': 'later'}
                    else:
                        row['diff_time']['alientime'] = {'date': parse(alientime),'diff':{'sec': diff_time.total_seconds(),
                                                  'min': diff_time.total_seconds() / 60,
                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                  'day': diff_time.days}, 'cmp': 'sooner'}


                    row['observed_source']['alienvault'] = True
                    row['IOC_Status']['alienvault'] = {
                        'active': indicator_details['general']['pulse_info']['pulses'][0][
                            'related_indicator_is_active'],
                        'tag': indicator_details['general']['pulse_info']['pulses'][0]['tags']}
                else:
                    row['observed_source']['alienvault'] = True
                    row['diff_time']['alientime'] ='null'
                    row['IOC_Status']['alienvault'] = 'absence'

            else:
                row['observed_source']['alienvault'] = False
                row['diff_time']['alientime'] = 'not found'
                row['IOC_Status']['alienvault'] = 'not found'

        elif row['indicator_type'] == 'url' or row['indicator_type'] == 'domain':
            if indicator_details:
                if len( indicator_details['url_list']['url_list']) > 0:
                 if 'date' in indicator_details['url_list']['url_list'][0]:
                    alientime = indicator_details['url_list']['url_list'][0]['date']
                    diff_time = (parse(row["date"]) - parse(alientime))
                    if diff_time.total_seconds() < 0:
                        row['diff_time']['alientime'] = {'date': parse(alientime),'diff':{'sec': diff_time.total_seconds(),
                                                  'min': diff_time.total_seconds() / 60,
                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                  'day': diff_time.days}, 'cmp': 'later'}
                    else:
                        row['diff_time']['alientime'] = {'date': parse(alientime), 'diff':{'sec': diff_time.total_seconds(),
                                                  'min': diff_time.total_seconds() / 60,
                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                  'day': diff_time.days},'cmp': 'sooner'}

                    if row['diff_time']['alientime'] != {}:
                        row['observed_source']['alienvault'] = True    ####check later
                        row['IOC_Status']['alienvault'] = {"validation":indicator_details["general"]["validation"]}
                elif indicator_details['passive_dns']['passive_dns'] != []:
                    first_date_alien = list()
                    for t in indicator_details['passive_dns']['passive_dns']:
                            first_date_alien.append(t['first'])
                    alientime = min(first_date_alien)
                    diff_time = (parse(row["date"]) - parse(alientime))
                    if diff_time.total_seconds() < 0:
                        row['diff_time']['alientime'] = {'date': parse(alientime),
                                                         'diff': {'sec': diff_time.total_seconds(),
                                                                  'min': diff_time.total_seconds() / 60,
                                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                                  'day': diff_time.days}, 'cmp': 'later'}
                    else:
                        row['diff_time']['alientime'] = {'date': parse(alientime),
                                                         'diff': {'sec': diff_time.total_seconds(),
                                                                  'min': diff_time.total_seconds() / 60,
                                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                                  'day': diff_time.days}, 'cmp': 'sooner'}

                    if row['diff_time']['alientime'] != {}:
                        row['observed_source']['alienvault'] = True  ####check later
                        row['IOC_Status']['alienvault'] = {"validation":indicator_details["general"]["validation"]}

            else:
                row['observed_source']['alienvault'] = False
                row['diff_time']['alienvault'] = 'not found'
                row['IOC_Status']['alienvault'] = 'not found'


####MISP

def MISP_search():
    attribute_details = (Utils.get_misp_connect(mispurl, mispkey)).search(controller='attributes',value=row['indicator'])
    if attribute_details['Attribute'] != []:
        first_date_misp = list()
        for t in attribute_details['Attribute']:
            if 'timestamp' in t:
                convert_time = datetime.fromtimestamp(int(t['timestamp']))
                first_date_misp.append(convert_time)
        if first_date_misp != []:
            min_date_misp = min(first_date_misp)
            diff_time = (parse(row["date"]) - (min_date_misp))
            if diff_time.total_seconds() < 0:
                row['diff_time']['misptime'] = {'date': min_date_misp,'diff':{'sec': diff_time.total_seconds(),
                                                  'min': diff_time.total_seconds() / 60,
                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                  'day': diff_time.days}, 'cmp': 'later'}
            else:
                row['diff_time']['misptime'] = {'date': min_date_misp, 'diff':{'sec': diff_time.total_seconds(),
                                                  'min': diff_time.total_seconds() / 60,
                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                  'day': diff_time.days},'cmp': 'sooner'}

            row['observed_source']['misp'] = True
            row['IOC_Status']['misp'] = 'absence'


    else:
        row['observed_source']['misp'] = False
        row['diff_time']['misptime'] = 'not found'
        row['IOC_Status']['misp'] = 'not found'


# opentip kasper
def OpenTipKasper_search(type):
    indicator_kasper_details = Utils.get_indicator_kasper(type, row['indicator'], kasperkey)
    if len(indicator_kasper_details) > 0 and not "\n" in indicator_kasper_details:
        res_jes = json.loads(indicator_kasper_details[0])  # as the result is string we convert it to json
        if type == 'ip':
          if  'IpWhoIs' in res_jes:
            if 'Created' in res_jes['IpWhoIs']['Net']:
                kaspertconvert = parse(res_jes['IpWhoIs']['Net']['Created'])
                if res_jes["Zone"]=='Gray' or res_jes["Zone"]=='Grey':
                  category='not categorized'
                elif   res_jes["Zone"]=='Red':
                    category ='Dangerous'
                elif res_jes["Zone"] == 'Orange':
                    category = 'Not trusted'
                elif res_jes["Zone"] == 'Yellow':
                    category ='Not applicable'
                elif res_jes["Zone"] == 'Green':
                    category ='Good'
                row['IOC_Status']['kasper'] = {'stat':res_jes['IpGeneralInfo']['Status'], 'category':category}
                kaspertime = kaspertconvert.replace(tzinfo=None)
                diff_time = parse(row["date"]) - kaspertime
                if diff_time.total_seconds() < 0:
                    row['diff_time']['kaspertime'] = {'date': kaspertime, 'diff':{'sec': diff_time.total_seconds(),
                                                  'min': diff_time.total_seconds() / 60,
                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                  'day': diff_time.days}, 'cmp': 'later'}

                else:
                    row['diff_time']['kaspertime'] = {'date': kaspertime,'diff':{'sec': diff_time.total_seconds(),
                                                  'min': diff_time.total_seconds() / 60,
                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                  'day': diff_time.days}, 'cmp': 'sooner'}

                row['observed_source']['kasper'] = True

            else:
                row['observed_source']['kasper'] = True
                row['IOC_Status']['kasper'] = 'null'
                row['diff_time']['kaspertime'] = 'null'


        elif type == 'hash':
            if 'FirstSeen' in res_jes['FileGeneralInfo']:
                kaspertconvert = parse(res_jes['FileGeneralInfo']['FirstSeen'])
                if res_jes["Zone"] == 'Gray' or res_jes["Zone"] == 'Grey':
                    category = 'not categorized'
                elif res_jes["Zone"] == 'Red':
                    category = 'Malware'
                elif res_jes["Zone"] == 'Orange':
                    category = 'Not applicable'
                elif res_jes["Zone"] == 'Yellow':
                    category = 'Adware/other'
                elif res_jes["Zone"] == 'Green':
                    category = 'Clean'
                row['IOC_Status']['kasper'] = {'stat':res_jes['FileGeneralInfo']['FileStatus'], 'category':category}
                kaspertime = kaspertconvert.replace(tzinfo=None)
                diff_time = parse(row["date"]) - kaspertime
                if diff_time.total_seconds() < 0:

                    row['diff_time']['kaspertime'] = {'date': kaspertime,'diff':{'sec': diff_time.total_seconds(),
                                                  'min': diff_time.total_seconds() / 60,
                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                  'day': diff_time.days}, 'cmp': 'later'}

                else:
                    row['diff_time']['kaspertime'] = {'date': kaspertime,'diff':{'sec': diff_time.total_seconds(),
                                                  'min': diff_time.total_seconds() / 60,
                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                  'day': diff_time.days}, 'cmp': 'sooner'}

                row['observed_source']['kasper'] = True

            else:
                row['observed_source']['kasper'] = True
                row['IOC_Status']['kasper'] = 'null'
                row['diff_time']['kaspertime'] = 'null'

        elif type == 'url':
          if  'UrlDomainWhoIs' in res_jes:
            if 'Created' in res_jes['UrlDomainWhoIs']:
                kaspertconvert = parse(res_jes['UrlDomainWhoIs']['Created'])
                if res_jes["Zone"] == 'Gray' or res_jes["Zone"] == 'Grey':
                    category = 'not categorized'
                elif res_jes["Zone"] == 'Red':
                    category = 'Dangerous'
                elif res_jes["Zone"] == 'Orange':
                    category = 'Not applicable'
                elif res_jes["Zone"] == 'Yellow':
                    category = 'Adware/other'
                elif res_jes["Zone"] == 'Green':
                    category = 'Good'
                row['IOC_Status']['kasper'] ={'stat':'', 'category':category}
                kaspertime = kaspertconvert.replace(tzinfo=None)
                diff_time = parse(row["date"]) - kaspertime
                if diff_time.total_seconds() < 0:
                    row['diff_time']['kaspertime'] = {'date': kaspertime, 'diff':{'sec': diff_time.total_seconds(),
                                                  'min': diff_time.total_seconds() / 60,
                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                  'day': diff_time.days},'cmp': 'later'}

                else:
                    row['diff_time']['kaspertime'] = {'date': kaspertime, 'diff':{'sec': diff_time.total_seconds(),
                                                  'min': diff_time.total_seconds() / 60,
                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                  'day': diff_time.days},'cmp': 'sooner'}

                row['observed_source']['kasper'] = True
            else:
                row['observed_source']['kasper'] = True
                if res_jes["Zone"] == 'Gray' or res_jes["Zone"] == 'Grey':
                    category = 'not categorized'
                elif res_jes["Zone"] == 'Red':
                    category = 'Dangerous'
                elif res_jes["Zone"] == 'Orange':
                    category = 'Not applicable'
                elif res_jes["Zone"] == 'Yellow':
                    category = 'Adware/other'
                elif res_jes["Zone"] == 'Green':
                    category = 'Good'
                row['IOC_Status']['kasper'] = {'stat': '', 'category': category}
                row['diff_time']['kaspertime'] = 'null'
          else:
              if res_jes["Zone"] == 'Gray' or res_jes["Zone"] == 'Grey':
                  category = 'not categorized'
              elif res_jes["Zone"] == 'Red':
                  category = 'Dangerous'
              elif res_jes["Zone"] == 'Orange':
                  category = 'Not applicable'
              elif res_jes["Zone"] == 'Yellow':
                  category = 'Adware/other'
              elif res_jes["Zone"] == 'Green':
                  category = 'Good'
              row['IOC_Status']['kasper'] = {'stat': '', 'category': category}
        elif type == 'domain':
            if 'DomainWhoIsInfo' in res_jes:
                kaspertconvert = parse(res_jes['DomainWhoIsInfo']['Created'])
                kaspertime = kaspertconvert.replace(tzinfo=None)
                diff_time = parse(row["date"]) - kaspertime
                if diff_time.total_seconds() < 0:
                    row['diff_time']['kaspertime'] = {'date': kaspertime,'diff':{'sec': diff_time.total_seconds(),
                                                  'min': diff_time.total_seconds() / 60,
                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                  'day': diff_time.days}, 'cmp': 'later'}

                else:
                    row['diff_time']['kaspertime'] = {'date': kaspertime,'diff':{'sec': diff_time.total_seconds(),
                                                  'min': diff_time.total_seconds() / 60,
                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                  'day': diff_time.days}, 'cmp': 'sooner'}

                row['observed_source']['kasper'] = True
                row['IOC_Status']['kasper'] = 'null'

            else:
                row['observed_source']['kasper'] = True
                row['IOC_Status']['kasper'] = 'null'
                row['diff_time']['kaspertime'] = 'null'

    else:
        row['observed_source']['kasper'] = False
        row['IOC_Status']['kasper'] = 'not found'
        row['diff_time']['kaspertime'] = 'not found'


# MalwareBazaar

def MalwareBazaar_search():
    bazaarresult = Utils.get_Bazaarhash_details(bazaarkey, row['indicator_type'], row['indicator'])
    if row['indicator_type'] == 'md5' or row['indicator_type'] == 'sha256' or row['indicator_type'] == 'sha1':

        if bazaarresult['query_status'] != "hash_not_found" or bazaarresult['query_status'] == 'ok':
            bazaartime = bazaarresult['data'][0]['first_seen']
            diff_time = (parse(row["date"]) - parse(bazaartime))
            if diff_time.total_seconds() < 0:
                row['diff_time']['malBazaartime'] = {'date': bazaartime,'diff':{'sec': diff_time.total_seconds(),
                                                  'min': diff_time.total_seconds() / 60,
                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                  'day': diff_time.days}, 'cmp': 'later'}
            else:
                row['diff_time']['malBazaartime'] = {'date': bazaartime, 'diff':{'sec': diff_time.total_seconds(),
                                                  'min': diff_time.total_seconds() / 60,
                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                  'day': diff_time.days},'cmp': 'sooner'}

            '''
              "Triage": {
                        "signatures": [
                            {
                                "score": "10",
                                "signature": "Emotet"
                            },
                            {
                                "score": null,
                                "signature": "Suspicious behavior: EnumeratesProcesses"
                            },
                            {
                                "score": null,
                                "signature": "Suspicious use of WriteProcessMemory"
                            }
                        ],
                        "tags": [
                            "family:emotet",
                            "botnet:epoch5",
                            "banker",
                            "trojan"
            '''
            if 'Triage' in bazaarresult['data'][0]['vendor_intel'] and 'tags' in bazaarresult['data'][0]:
              row['IOC_Status']['malwarebazaar'] = {'tags': bazaarresult['data'][0]['tags'],
                                                      'malfamily': bazaarresult['data'][0]['vendor_intel']['Triage']['tags']}
            else:
                row['IOC_Status']['malwarebazaar'] ='absence'
            row['observed_source']['malwarebazaar'] = True

        else:
            row['observed_source']['malwarebazaar'] = False
            row['IOC_Status']['malwarebazaar'] = 'absence'
            row['diff_time']['malBazaartime'] = 'absence'


def UrlHaus_search(type):
    if type == 'md5' or type == 'sha256' or type == 'sha1':
        json_response = Utils.query_urlhaus_hash(row['indicator'])

    elif type == 'url':
        json_response = Utils.query_urlhaus_url(row['indicator'])

    elif type == 'domain' or type == 'ip':
        json_response = Utils.query_urlhaus_host(row['indicator'])

    if json_response['query_status'] == 'ok':
        if type == 'md5' or type == 'sha256' or type == 'sha1' or type == 'domain' or type == 'ip':
            urlhaustime = parse(json_response["firstseen"]).replace(tzinfo=None)  # hash/payloads first seen
            for u in json_response['urls']:
                if u['url_status'] == 'online':
                    row['IOC_Status']['urlhaus'] == 'active'
                elif u['url_status'] == 'offline':
                    row['IOC_Status']['urlhaus'] == 'inactive'
                elif u['url_status'] == 'unknown':
                    row['IOC_Status']['urlhaus'] == 'unknown'
        elif type == 'url':
            urlhaustime = parse(json_response['date_added']).replace(tzinfo=None)  # url date added
            '''
                  json_response['url_status']
                  online: The malware URL is active (online) and currently serving a payload
                  offline: The malware URL is inactive (offline) and serving o no payload
                  unknown: The currently malware URL status could not be determined
                  '''
            if json_response['url_status'] == 'online':
                row['IOC_Status']['urlhaus'] == 'active'
            elif json_response['url_status'] == 'offline':
                row['IOC_Status']['urlhaus'] == 'inactive'
            elif json_response['url_status'] == 'unknown':
                row['IOC_Status']['urlhaus'] == 'unknown'

        diff_time = parse(row["date"]) - (urlhaustime)
        if diff_time.total_seconds() < 0:
            row['diff_time']['urlhaustime'] = {'date': urlhaustime,'diff':{'sec': diff_time.total_seconds(),
                                                  'min': diff_time.total_seconds() / 60,
                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                  'day': diff_time.days}, 'cmp': 'later'}
        else:
            row['diff_time']['urlhaustime'] = {'date': urlhaustime,'diff':{'sec': diff_time.total_seconds(),
                                                  'min': diff_time.total_seconds() / 60,
                                                  'hour': diff_time.total_seconds() / 60 ** 2,
                                                  'day': diff_time.days}, 'cmp': 'sooner'}



        row['observed_source']['urlhaus'] = True

    elif json_response['query_status'] == 'no_results':
        row['observed_source']['urlhaus'] = False
        row['IOC_Status']['urlhaus'] = 'not found'
        row['diff_time']['urlhaustime'] ='not found'

    else:
        print("Something went wrong")


if __name__ == '__main__':

    if args.inputfile:
        r = csv.reader(args.inputfile)
        data = [line for line in r]
        resultfile_header = Utils.generateResultFilename(args.inputfile.name)
        with open(resultfile_header, 'w', newline='') as fwrite:
            w = csv.writer(fwrite)
            w.writerow(['date', 'user', 'indicator_type', 'indicator', 'label', 'tweetlink'])
            w.writerows(data)
        tweetfile = csv.DictReader(open(resultfile_header))
        for row in tweetfile:
            row['observed_source'] = {'alienvault': '', 'misp': '', 'malwarebazaar': '', 'kasper': '',
                                      'virustotal': '', 'hashlookup': '',
                                      'urlhaus': ''}
            row['diff_time'] = {'alientime': '',
                                'malBazaartime': '',
                                'misptime': '',
                                'virustime': '',
                                'kaspertime': '',
                                'hashlooktime': '',
                                'urlhaustime': ''}
            row['IOC_Status'] = {'alienvault': '', 'misp': '', 'malwarebazaar': '', 'kasper': '',
                                 'virustotal': '', 'hashlookup': '', 'urlhaus': ''}
            # AlienVault
            if row['indicator_type'] == 'ip':
             try:
                AlienVault_search(IndicatorTypes.IPv4)
                # MISP
                MISP_search()
                # Opentip_kasper
                OpenTipKasper_search('ip')
                UrlHaus_search(row['indicator_type'])
                # virustotal
                vt_search()
                row['diff_time']['malBazaartime'] = '-'
                row['observed_source']['malwarebazaar'] = '-'
                row['IOC_Status']['malwarebazaar'] = '-'
                row['observed_source']['hashlookup'] = '-'
                row['diff_time']['hashlooktime'] = '-'
                row['IOC_Status']['hashlookup'] = '-'
                pulses.append(row)
             except Exception as e:
                 print(str(e))

            elif row['indicator_type'] == 'domain':
             try:
                AlienVault_search(IndicatorTypes.DOMAIN)
                UrlHaus_search(row['indicator_type'])
                MISP_search()
                ################# Opentip_kasper
                OpenTipKasper_search('domain')
                ###### virustotal
                vt_search()
                row['diff_time']['malBazaartime'] = '-'

                row['observed_source']['malwarebazaar'] = '-'
                row['IOC_Status']['malwarebazaar'] = '-'
                row['observed_source']['hashlookup'] = '-'

                row['diff_time']['hashlooktime'] = '-'
                row['IOC_Status']['hashlookup'] = '-'

                pulses.append(row)
             except Exception as e:
                 print(str(e))
            elif row['indicator_type'] == 'md5':
             try:
                # alien
                AlienVault_search(IndicatorTypes.FILE_HASH_MD5)
                MISP_search()
                # malbazaar
                MalwareBazaar_search()
                ############ Opentip kasper
                OpenTipKasper_search('hash')
                ############ urlhaus
                UrlHaus_search(row['indicator_type'])
                ###### virustotal
                vt_search()
                ####### hashlookup
                hashlookup_search()

                pulses.append(row)
             except Exception as e:
                 print(str(e))
            elif row['indicator_type'] == 'sha256':
              try:
                AlienVault_search(IndicatorTypes.FILE_HASH_SHA256)
                MISP_search()
                # malbazaar
                MalwareBazaar_search()
                ############ Opentip kasper
                OpenTipKasper_search('hash')
                ################### urlhaus
                UrlHaus_search(row['indicator_type'])
                ###### virustotal
                vt_search()
                ####### hashlookup
                hashlookup_search()
                pulses.append(row)

              except Exception as e:
                 print(str(e))

            elif row['indicator_type'] == 'url':
             try:
                AlienVault_search(IndicatorTypes.URL)
                MISP_search()
                ############ Opentip kasper
                OpenTipKasper_search('url')
                ######### urlhaus
                UrlHaus_search(row['indicator_type'])
                ###### virustotal
                vt_search()
                row['diff_time']['malBazaartime'] = '-'

                row['observed_source']['malwarebazaar'] = '-'
                row['IOC_Status']['malwarebazaar'] = '-'
                row['observed_source']['hashlookup'] = '-'

                row['diff_time']['hashlooktime'] = '-'
                row['IOC_Status']['hashlookup'] = '-'
                pulses.append(row)
             except Exception as e:
                 print(str(e))

            elif row['indicator_type'] == 'sha1':
             try:
                ########## alienvault
                AlienVault_search(IndicatorTypes.FILE_HASH_SHA1)
                MISP_search()
                # malbazaar
                MalwareBazaar_search()
                ############ Opentip kasper
                OpenTipKasper_search('hash')
                ########## urlhaus
                UrlHaus_search(row['indicator_type'])
                ###### virustotal
                vt_search()
                ####### hashlookup
                hashlookup_search()
                pulses.append(row)
             except Exception as e:
                 print(str(e))
        #resultfilejson = Utils.generateResultFilename('finalresult.json')
        resultfilejson = Utils.generateResultFilename(os.path.splitext(os.path.basename(args.inputfile.name))[0]+'.json')
        with open(resultfilejson, 'w') as writejson:
            json.dump(pulses, writejson, sort_keys=True, indent=4, default=str, ensure_ascii=False)
