import pymisp
import requests
import json
import sys
import smtplib
from requests.auth import HTTPBasicAuth
from email.mime.text import MIMEText
from datetime import datetime
from config_misp import misp_url, misp_authkey, misp_verifycert, misp_return_format, misp_searchable_types, event_blacklist
from config_kibana import KFIELDS, TYPEMAPPING, kibana_url, kibana_user, kibana_pw, kibana_json, kibana_headers, kib_index

VERSION="1.2"
RECIPIENTS=[''] #Recipients can be added here if alerting on matches via mail

class IOCMONITOR():
    def __init__(self, args=None):
        self.curdate=datetime.today().strftime('%Y.%m.%d')
        self.kwargs={"category":"Network activity", "type_attribute":"", "to_ids":1, "published":1, "enforceWarninglist":1, "last":"48h"}
        self.misp=None
        self.kjson_data=None
        self.iocTypes=misp_searchable_types
        self.iocDict={'url':[], 'domain':[],'ip':[],'user-agent':[]}
        self.kibanaEnabled=False
        self.mispEnabled=False
        self.kurl=""
        self.hitDict=dict()
        self.eventBlacklist=[]

    def mispSearch(self, type_attribute):
        if not self.mispEnabled:
            print("MISP connection not set up. Run mispSetup().")
            return ""
        self.kwargs['type_attribute']=type_attribute
        resp=self.misp.search('attributes', **self.kwargs)
        if resp['response']:
            # Check if event not in custom blacklist for known useless events
            resp['response']['Attribute'][:][i for i in resp['response']['Attribute'] if i.get('event_id') not in self.eventBlacklist]
            return resp['response']['Attribute']
        return ""

    def checkForHits(self):
        if not self.mispEnabled:
            print("MISP connection not set up. Run mispSetup()")
            return ""
        for k in self.iocDict.keys():
            for attributes in self.iocDict[k]:
                for attr in attributes:
                    nu=False
                    val=self.getsearchval(attr["value"], attr["type"], k)
                    hitList=self.kibanaSearch(val, k)
                    if hitList:
                        for hit in hitList:
                            hitKey=hit[kib_index][KFIELDS["user"]]+"_"+hit[kib_index][KFIELDS["cip"]]+"_"+val
                            if hitKey in self.hitDict.keys():
                                self.hitDict[hitkey]['Count']+=1
                            else:
                                self.hitDict[hitKey]={'User':hit[kib_index][KFIELDS["user"]], 'ClientIP':hit[kib_index][KFIELDS["cip"]],
                                                    'Request':hit[kib_index][KFIELDS["URI"]], 'Hit':attr["value"], 'EventID':attr['event_id'],
                                                    'Info':attr['Event']['info'], 'Method':hit[kib_index][KFIELDS['method']],
                                                    'Datetime':hit[kib_index][KFIELDS['DateTime']],
                                                    'Count':1}

    def kibanaSetup(self):
        self.kurl=kibana_url % self.curdate
        with open(kibana_json, 'r') as f:
            self.kjson_data=json.loads(f.read())
        self.kibanaEnabled=True

    def mispSetup(self):
        self.misp=pymisp.PyMISP(misp_url, misp_authkey, misp_verifycert, misp_return_format)
        self.mispEnabled=True
        with open(event_blacklist, 'r') as eb:
            for line in eb.read().splitlines():
                self.eventBlacklist.append(line)
        for i in self.iocTypes['url']:
            self.iocDict['url'].append(self.mispSearch(i))
        for i in self.iocTypes['domain']:
            self.iocDict['domain'].append(self.mispSearch(i))
        for i in self.iocTypes['ip']:
            self.iocDict['ip'].append(self.mispSearch(i))
        for i in self.iocTypes['user-agent']:
            self.iocDict['user-agent'].append(self.mispSearch(i))

    def kibanaEscape(self,ioc):
        ioc=ioc.translate(str.maketrans({'+':r'\+',
                                         '-':r'\-',
                                         '=':r'\=',
                                         '>':r'\>',
                                         '<':r'\<',
                                         '!':r'\!',
                                         '(':r'\(',
                                         ')':r'\)',
                                         '{':r'\{',
                                         '}':r'\}',
                                         '[':r'\[',
                                         ']':r'\]',
                                         '^':r'\^',
                                         '"':r'\"',
                                         '~':r'\~',
                                         '*':r'\*',
                                         '?':r'\?',
                                         ':':r'\:',
                                         '/':r'\/',
                                         '\\':r'\\'}))
        return ioc

        def kibanaSearch(self, i, type):
            if not self.kibanaEnabled:
                self.kibanaSetup()
            ioc = self.kibanaEscape(i)
            try:
                self.kjson_data["query"]["bool"]["must"]["bool"]["should"][0]["term"].clear()
                if len(self.kjson_data["query"]["bool"]["must"]["bool"]["should"]) > 1:
                    self.kjson_data["query"]["bool"]["must"]["bool"]["should"].pop()
                self.kjson_data["query"]["bool"]["must"]["bool"]["should"][0]["term"][TYPEMAPPING[type][0]] = ioc
                if len(TYPEMAPPING[type]) > 1:
                    if len(self.kjson_data["query"]["bool"]["must"]["bool"]["should"]) > 1:
                        self.kjson_data["query"]["bool"]["must"]["bool"]["should"][1]["term"][
                            TYPEMAPPING[type][1]] = ioc
                    else:
                        self.kjson_data["query"]["bool"]["must"]["bool"]["should"].append(
                            {"term": {TYPEMAPPING[type][1]: ioc}})
                elif len(self.kjson_data["query"]["bool"]["must"]["bool"]["should"]) > 1:
                    self.kjson_data["query"]["bool"]["must"]["bool"]["should"].pop()
            except Exception as e:
                print("Exception occurred during kibana query build: %s" % e)
                sys.exit(1)
                pass
            resp = requests.request("POST", self.kurl, headers=kibana_headers,
                                    auth=HTTPBasicAuth(kibana_user, kibana_pw),
                                    data=json.dumps(self.kjson_data),
                                    verify=False)
            resp_data = resp.json()
            try:
                if resp_data["hits"]["total"] < 1:
                    return None
                else:
                    return resp_data["hits"]["hits"]
            except:
                print(resp_data["hits"])
                print("Error occurred during searching in Kibana")
                return None

        def sendReport(self, output="json"):
            rep = ""
            for v in self.hitDict.values():
                for a, b in v.items():
                    rep += "%s : %s" % (a, b)
                    rep += '\n'
                rep += '------------------------\n'
            if rep == "":
                print("Nothing to report")
                return
            msg = MIMEText(rep)
            msg['Subject'] = "Hits in Kibana for MISP IoCs"
            msg['From'] = "misp-kibana-search"
            msg['To'] = RECIPIENTS[0]
            s = smtplib.SMTP('localhost')
            s.sendmail('root@localhost', RECIPIENTS, msg.as_string())
            s.quit()
            return

        @staticmethod
        def getsearchval(val, type, searchtype):
            if "|port" in type or (type == "domain|ip" and searchtype == "domain"):
                return val.split('|')[0]
            if type == "domain|ip" and searchtype == "ip":
                return val.split('|')[1]
            return val

        return ioc
