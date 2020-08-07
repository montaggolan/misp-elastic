import pymisp
import requests
import json
import smtplib
import ssl
from requests.auth import HTTPBasicAuth
from email.mime.text import MIMEText
from urllib.parse import urlparse
from datetime import datetime
from elasticsearch import Elasticsearch
from iocmon_conf import misp_config, elastic_config, event_blacklist, TYPEMAPPING

VERSION = "2.0"
RECIPIENTS = ['']


class IOCMONITOR():
    def __init__(self, targetLogPlatform, loginNecessary=False, args=None):
        self.curdate = datetime.today().strftime('%Y.%m.%d')
        self.kwargs = {"category": "Network activity", "type_attribute": "", "to_ids": 1, "published": 1,
                       "enforceWarninglist": 1, "last": "10d"}
        self.misp = None
        self.es = None
        self.eljson_data = None
        self.iocTypes = misp_config['misp_searchable_types']
        self.iocDict = dict()
        self.elasticEnabled = False
        self.mispEnabled = False
        self.elurl = ""
        self.loginNecessary = loginNecessary
        self.targetLogPlatform = targetLogPlatform
        self.hitDict = dict()
        self.eventBlacklist = []

    def mispSearch(self, type_attribute):
        if not self.mispEnabled:
            print("MISP connection not set up. Run mispSetup().")
            return ""
        self.kwargs['type_attribute'] = type_attribute
        resp = self.misp.search('attributes', **self.kwargs)
        try:
            resp['Attribute'][:] = [i for i in resp['Attribute'] if i.get('event_id') not in self.eventBlacklist]
            return resp['Attribute']
        except KeyError:
            print('Nothing new found for past 48h in MISP')
        return ""

    def checkForHits(self):
        hitList = []
        if not self.mispEnabled:
            self.errorexit("MISP connection not set up. Run mispSetup().")
            return ""
        for k in self.iocDict.keys():
            for attributes in self.iocDict[k]:
                for attr in attributes:
                    val = self.getsearchval(attr["value"], attr["type"], k)
                    hitList = self.elasticQuery(val, k)
                    if hitList:
                        for hit in hitList:
                            self.populateHits(hit, attr, val)

    def elasticSetup(self):
        if self.loginNecessary:
            r = self.pLogin()
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self.es = Elasticsearch(host=elastic_config['elastic_ip'], port=elastic_config['elastic_port'],
                                    headers={'Cookie': 'ssid=' + r.cookies['ssid']},
                                    url_prefix='/lms-search/', use_ssl=True, ca_certs=False, verify_certs=False,
                                    ssl_context=context, send_get_body_as='POST', timeout=100)
        else:
            self.elurl = elastic_config['elastic_url'] % self.curdate
        with open(elastic_config['elastic_json'], 'r') as f:
            self.eljson_data = json.loads(f.read())
        self.elasticEnabled = True

    def mispSetup(self, targetLogs):
        requests.packages.urllib3.disable_warnings()
        self.misp = pymisp.PyMISP(url=misp_config['misp_url'], key=misp_config['misp_authkey'],
                                  ssl=misp_config['misp_verifycert'], debug=False)
        self.mispEnabled = True
        self.buildIocDict(targetLogs)

    def elasticEscape(self, ioc):
        ioc = ioc.translate(str.maketrans({'+': r'\+',
                                           '-': r'\-',
                                           '=': r'\=',
                                           '>': r'\>',
                                           '<': r'\<',
                                           '!': r'\!',
                                           '(': r'\(',
                                           ')': r'\)',
                                           '{': r'\{',
                                           '}': r'\}',
                                           '[': r'\[',
                                           ']': r'\]',
                                           '^': r'\^',
                                           '"': r'\"',
                                           '~': r'\~',
                                           '*': r'\*',
                                           '?': r'\?',
                                           ':': r'\:',
                                           '/': r'\/',
                                           '\\': r'\\'}))
        return ioc

    def pLogin(self):
        loginParams = {}
        if len(elastic_config['elastic_pw']) > 1:
            loginParams['username'] = elastic_config['elastic_user']
            loginParams['password'] = elastic_config['elastic_pw']
        else:
            self.errorexit("You must have a password set")
        requests.packages.urllib3.disable_warnings()
        r = requests.post(elastic_config['elastic_login_url'], headers=elastic_config['elastic_headers'],
                          json=loginParams, verify=False)
        return r

    def elasticQuery(self, i, iocType):
        if not self.elasticEnabled:
            self.elasticSetup()
        ioc = self.elasticEscape(i)
        try:
            typeRange = len(TYPEMAPPING[self.targetLogPlatform][iocType])
            self.eljson_data["query"]["bool"]["must"]["bool"] = {}
            for x in range(0, typeRange):
                if iocType in misp_config["misp_searchable_types"]["url"]:
                    if not x:
                        self.eljson_data["query"]["bool"]["must"]["bool"] = {"must": [], "should": []}
                        self.eljson_data["query"]["bool"]["must"]["bool"]["must"].append({"term": {
                            TYPEMAPPING[self.targetLogPlatform][iocType][x]: self.elasticEscape(
                                self.parseUrl(i, TYPEMAPPING[self.targetLogPlatform][iocType][x]))}})
                    elif TYPEMAPPING[self.targetLogPlatform][iocType][x] == "referrer":
                        self.eljson_data["query"]["bool"]["must"]["bool"]["should"].append(
                            {"term": {TYPEMAPPING[self.targetLogPlatform][iocType][x]: ioc}})
                    else:
                        tmpVal = self.parseUrl(i, TYPEMAPPING[self.targetLogPlatform][iocType][x])
                        if tmpVal:
                            self.eljson_data["query"]["bool"]["must"]["bool"]["must"].append({"term": {
                                TYPEMAPPING[self.targetLogPlatform][iocType][x]: self.elasticEscape(
                                    self.parseUrl(i, TYPEMAPPING[self.targetLogPlatform][iocType][x]))}})
                else:
                    if not x:
                        self.eljson_data["query"]["bool"]["must"]["bool"] = {"should": []}
                    self.eljson_data["query"]["bool"]["must"]["bool"]["should"].append(
                        {"term": {TYPEMAPPING[self.targetLogPlatform][iocType][x]: ioc}})
        except Exception as e:
            self.errorexit("Exception occurred during elastic query build: %s" % e)
        if self.es:
            resp = self.es.search(index=elastic_config['elastic_index'], body=self.eljson_data)
        else:
            resp = requests.request("POST", self.elurl, headers=elastic_config['elastic_headers'],
                                    auth=HTTPBasicAuth(elastic_config['elastic_user'], elastic_config['elastic_pw']),
                                    data=json.dumps(self.eljson_data), verify=False)
        try:
            if resp["hits"]["total"] < 1:
                print("No hits found.")
                return None
            else:
                print("MATCH: %s" % ioc)
                return resp["hits"]["hits"]
        except:
            print("Error occurred during search.")
            return None

    def sendReport(self, output="json"):
        rep = ""
        for v in self.hitDict.values():
            for a, b in v.items():
                rep += "%s: %s" % (a, b)
                rep += '\n'
            rep += '------------------------\n'
        if rep == "":
            print("Nothing to report")
            return
        msg = MIMEText(rep)
        msg['Subject'] = "Hits from MISP IoC Monitor"
        msg['From'] = "mispmon"
        msg['To'] = RECIPIENTS[0]
        s = smtplib.SMTP('localhost')
        s.sendmail('user@localhost', RECIPIENTS, msg.as_string())
        s.quit()
        return

    def populateHits(self, hit, attr, val):
        if "proxy" in hit["_source"][TYPEMAPPING[self.targetLogPlatform]['parser']]:
            hitKey = self.extractFieldValue(hit, 9, "proxy") + "_" + self.extractFieldValue(hit, 10, "proxy") + "_" + val
            if hitKey in self.hitDict.keys():
                self.hitDict[hitKey]['Count'] += 1
            else:
                self.hitDict[hitKey] = {
                    'User': self.extractFieldValue(hit, 9, "proxy"),
                    'ClientIP': self.extractFieldValue(hit, 10, "proxy"),
                    'Request': self.extractFieldValue(hit, 11, "proxy") + "://" + \
                               self.extractFieldValue(hit, 12, "proxy") + ":" + \
                               self.extractFieldValue(hit, 15, "proxy") + \
                               self.extractFieldValue(hit, 13, "proxy") + \
                               self.extractFieldValue(hit, 14, "proxy"),
                    'Hit': attr["value"],
                    'EventID': attr['event_id'],
                    'Info': attr['Event']['info'],
                    'Method': self.extractFieldValue(hit, 0, "proxy"),
                    'Datetime': self.extractFieldValue(hit, 6, "proxy"),
                    'Category': self.extractFieldValue(hit, 1, "proxy"),
                    'Count': 1
                }
        else:
            self.errorexit("No suitable parser found.")

    def extractFieldValue(self, hit, fNr, logSource):
        try:
            return str(hit["_source"][TYPEMAPPING[self.targetLogPlatform][logSource][fNr]])
        except KeyError:
            return "-"

    def buildIocDict(self, targetLogs):
        if targetLogs == "proxy":
            self.iocDict = {'url': [], 'domain': [], 'ip': [], 'user-agent': []}
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
        else:
            self.errorexit("Support for these logs not implemented.")

    @staticmethod
    def getsearchval(val, iocType, searchtype):
        if "|port" in iocType or (iocType == "domain|ip" and searchtype == "domain"):
            tmpDomain = val.split('|')[0]
            if tmpDomain[:4] == "www.":
                return tmpDomain[4:]
            return tmpDomain
        if iocType == "domain|ip" and searchtype == "ip":
            return val.split('|')[1]
        if iocType == "domain" and val[:4] == "www.":
            return val[4:]
        return val

    @staticmethod
    def parseUrl(url, section):
        u = urlparse(url)
        if section == "domain":
            if not u.scheme:
                return u.path.split('/')[0]
            else:
                return u.hostname
        if section == "uri_path":
            if not u.scheme:
                return '/'.join(u.path.split('/')[1:])
            else:
                return u.path
        if section == "uri_query":
            return u.query
        return url

    @staticmethod
    def errorexit(reason):
        print(reason + "\n")
        exit()