import sys
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
from iocmon2_conf import misp_config, elastic_config, event_blacklist, TYPEMAPPING, log_whitelist
from pymisp.mispevent import MISPEvent

VERSION="2.6"
RECIPIENTS=['']
MAIL_FROM=''


class IOCMONITOR():
    def __init__(self, args, targetLogPlatform="", loginNecessary=False):
        self.curdate=datetime.today().strftime('%Y.%m.%d')
        self.kwargs=args
        self.misp=None
        self.es=None
        self.eljson_data=None
        self.iocTypes=misp_config['misp_searchable_types']
        self.iocDict=dict()
        self.elasticEnabled=False
        self.mispEnabled=False
        self.elurl=""
        self.loginNecessary=loginNecessary
        self.targetLogPlatform=targetLogPlatform
        self.targetLogs=[key for key in TYPEMAPPING[targetLogPlatform]['targetLogs'].keys()]
        self.hitDict=dict()
        self.eventBlacklist=[]
        self.whitelist=log_whitelist
        #self.outputFile=

    def mispSearch(self, type_attribute="", returnEvent=False, searchType="attributes"):
        if searchType=="attributes":
            st=['attributes','Attribute']
        elif searchType=="events":
            st=['events','Event']
        if not self.mispEnabled:
            print("MISP connection not set up. Run mispSetup().")
            return ""
        if type_attribute:
            self.kwargs['type_attribute']=type_attribute
        resp = self.misp.search(st[0], **self.kwargs)
        try:
            if st[0] == 'attributes':
                resp['response'][st[1]][:]=[i for i in resp['response'][st[1]] if i.get('event_id') not in self.eventBlacklist]
            else:
                resp['response'][:]=[i for i in resp['response'] if i['Event']['id'] not in self.eventBlacklist]
            #resp['Attribute'][:]=[i for i in resp['Attribute'] if i.get('event_id') not in self.eventBlacklist]
            if returnEvent:
                return resp
            else:
                return resp['response'][st[1]]
            #return resp['Attribute']
        except Exception as e:
            print('Exception %s' % e)
        return ""

    def checkForHits(self):
        hitList=[]
        if not self.mispEnabled:
            self.errorexit("MISP connection not set up. Run mispSetup().")
            return ""
        for k in self.iocDict.keys():
            for attributes in self.iocDict[k]:
                for attr in attributes:
                    val=self.getsearchval(attr["value"], attr["type"], k)
                    if not val:
                        continue
                    hitList=self.elasticQuery(val, k)
                    #print(hitList)
                    if hitList:
                        for hit in hitList:
                            for match in hit:
                                self.populateHits(match, attr)

    def elasticSetup(self):
        if self.loginNecessary:
            r = self.pLogin()
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self.es = Elasticsearch(host=elastic_config['elastic_ip'], port=elastic_config['elastic_port'], headers={'Cookie': 'ssid=' + r.cookies['ssid']},
            url_prefix='/lms-search/', use_ssl=True, ca_certs=False, verify_certs=False, ssl_context=context, send_get_body_as='POST', timeout=100)
        else:
            self.elurl=elastic_config['elastic_url'] % self.curdate
        with open(elastic_config['elastic_json'],'r') as f:
            self.eljson_data=json.loads(f.read())
        self.elasticEnabled=True

    def mispSetup(self, targetLogs="", bid=True):
        requests.packages.urllib3.disable_warnings()
        self.misp=pymisp.PyMISP(url=misp_config['misp_url'], key=misp_config['misp_authkey'],
        ssl=misp_config['misp_verifycert'], debug=False)
        self.mispEnabled=True
        if bid:
            self.buildIocDict(targetLogs)

    def elasticEscape(self,ioc):
        #print(ioc)
        ioc2=ioc.translate(str.maketrans({'+':r'\+',
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

    def pLogin(self):
        loginParams = {}
        if len(elastic_config['elastic_pw']) > 1:
            loginParams['username'] = elastic_config['elastic_user']
            loginParams['password'] = elastic_config['elastic_pw']
        else:
            self.errorexit("You must have user:password set")
        requests.packages.urllib3.disable_warnings()
        r = requests.post(elastic_config['elastic_login_url'], headers=elastic_config['elastic_headers'], json=loginParams, verify=False)
        return r

    def elasticQuery(self, i, iocType):
        resp=None
        resps=[]
        if not self.elasticEnabled:
            self.elasticSetup()
        try:
            ioc=self.elasticEscape(i)
        except Exception as e:
            print("Translation of ioc didn't work %s" % e)
            pass
        try:
            typeRange=len(TYPEMAPPING[self.targetLogPlatform][iocType])
            while len(self.eljson_data["query"]["bool"]["must"]) > 2:
                self.eljson_data["query"]["bool"]["must"].pop(1)
            self.eljson_data["query"]["bool"]["must"][0]["term"]={}
            for x in range(0, typeRange):
                if iocType in misp_config["misp_searchable_types"]["url"]:
                    if not x:
                        parsedUrlPart=self.parseUrl(i, TYPEMAPPING[self.targetLogPlatform][iocType][x])
                        if not parsedUrlPart:
                            continue
                        self.eljson_data["query"]["bool"]["must"][0]["term"]={TYPEMAPPING[self.targetLogPlatform][iocType][x]:self.elasticEscape(parsedUrlPart)}
                    elif TYPEMAPPING[self.targetLogPlatform][iocType][x] == "referrer":
                        while len(self.eljson_data["query"]["bool"]["must"]) > 2:
                            self.eljson_data["query"]["bool"]["must"].pop(1)
                        self.eljson_data["query"]["bool"]["must"][0]["term"]={TYPEMAPPING[self.targetLogPlatform][iocType][x]:self.elasticEscape(parsedUrlPart)}
                    else:
                        try:
                            tmpVal=self.parseUrl(i, TYPEMAPPING[self.targetLogPlatform][iocType][x])
                            if tmpVal:
                                parsedUrlPart=self.parseUrl(i, TYPEMAPPING[self.targetLogPlatform][iocType][x])
                                if not parsedUrlPart:
                                    continue
                                self.eljson_data["query"]["bool"]["must"].insert(-1,{"term":{TYPEMAPPING[self.targetLogPlatform][iocType][x]:self.elasticEscape(parsedUrlPart)}})
                        except:
                            pass
                elif iocType == 'regkey|value' and x == 'file_path':
                    self.eljson_data["query"]["bool"]["must"][0]["term"]={TYPEMAPPING[self.targetLogPlatform][iocType][x]:'\\'.join(ioc.split('|'))}
                else:
                    #while len(self.eljson_data["query"]["bool"]["must"]) > 2:
                    #    self.eljson_data["query"]["bool"]["must"].pop(1)
                    self.eljson_data["query"]["bool"]["must"][0]["term"]={TYPEMAPPING[self.targetLogPlatform][iocType][x]:ioc}
                if iocType in misp_config["misp_searchable_types"]["url"] and x < 2:
                    continue
                else:
                    #print(self.eljson_data)
                    resp = self.sendRequestJSON()
                    #print(resp)
                try:
                    #print(resp)
                    if resp and resp["hits"]["total"]>=1:
                        resps.append(resp["hits"]["hits"])
                except Exception as e:
                    #print(self.eljson_data)
                    #exc_type, exc_obj, exc_tb = sys.exc_info()
                    #print(exc_type, exc_tb.tb_lineno)
                    #print(e)
                    print("Error occurred during search.")
                    pass
            return resps
        except Exception as e:
            #exc_type, exc_obj, exc_tb = sys.exc_info()
            #print(exc_type, exc_tb.tb_lineno)
            print("Exception occurred during elastic query build: %s" % e)
            #print(self.eljson_data)
            return None

    def sendRequestJSON(self):
        resp=None
        if self.es:
            try:
                resp=self.es.search(index=elastic_config['elastic_index'], body=self.eljson_data)
            except Exception as e:
                print(e)
                pass
        else:
            resp=requests.request("POST", self.elurl, headers=elastic_config['elastic_headers'],
                auth=HTTPBasicAuth(elastic_config['elastic_user'], elastic_config['elastic_pw']), data=json.dumps(self.eljson_data), verify=False)
        return resp

    def sendReport(self, output="json", mailPerEvent=False):
        rep=""
        eventsHit=[]
        if mailPerEvent:
            for hit in self.hitDict:
                if self.hitDict[hit]['EventID'] not in eventsHit:
                    eventsHit.append(self.hitDict[hit]['EventID'])
            if not eventsHit:
                print("Nothing to report")
                return
            for e in eventsHit:
                rep=""
                for hit in self.hitDict:
                    if self.hitDict[hit]['EventID'] == e:
                        for a,b in self.hitDict[hit].items():
                            rep+="%s: %s" % (a,b)
                            rep+='\n'
                        rep+='------------------------\n'
                msg = MIMEText(rep)
                msg['Subject']="Hits from MISP IoC Monitor for EventID %s" % e
                msg['From']=MAIL_FROM
                msg['To']=RECIPIENTS[0]
                s = smtplib.SMTP('localhost')
                for recip in RECIPIENTS:
                    s.sendmail(MAIL_FROM, recip, msg.as_string())
                s.quit()
        else:
            for v in self.hitDict.values():
                for a,b in v.items():
                    rep+="%s: %s" % (a,b)
                    rep+='\n'
                rep+='------------------------\n'
            if rep=="":
                print("Nothing to report")
                return
            msg = MIMEText(rep)
            msg['Subject']="Hits from MISP IoC Monitor"
            msg['From']=MAIL_FROM
            msg['To']=RECIPIENTS[0]
            s = smtplib.SMTP('localhost')
            for recip in RECIPIENTS:
                s.sendmail(MAIL_FROM, recip, msg.as_string())
            s.quit()
        return

    def populateHits(self, hit, attr):
        foundParser=False
        for t in self.targetLogs:
            if t in hit["_source"][TYPEMAPPING[self.targetLogPlatform]['parser']]:
                trgtLog=t
                foundParser=True
                break
        if not foundParser:
            print("No suitable parser found for hit %s" % hit)
            return
        hitKey=""
        portUnusal=False
        for hk in TYPEMAPPING[self.targetLogPlatform]['targetLogs'][trgtLog][1]['hitKey']:
            hitKey+=self.extractFieldValue(hit, hk, trgtLog)
        if hitKey in self.hitDict.keys():
            self.hitDict[hitKey]['Count']+=1
        else:
            self.hitDict[hitKey]={}
            for field in TYPEMAPPING[self.targetLogPlatform]['targetLogs'][trgtLog][0].keys():
                fieldVal=TYPEMAPPING[self.targetLogPlatform]['targetLogs'][trgtLog][0][field]
                if type(fieldVal)==str:
                    self.hitDict[hitKey][field]=self.extractFieldValue(hit, fieldVal, trgtLog)
                elif type(fieldVal)==list:
                    if field=="Request":
                        for i in fieldVal:
                            if i == 'dest_port':
                                portUnusual=True if self.extractFieldValue(hit, i, trgtLog) not in ["80","443"] else False
                                if not portUnusal:
                                    self.hitDict[hitKey][field]= \
                                        self.extractFieldValue(hit, fieldVal[0], trgtLog)+"://"+self.extractFieldValue(hit, fieldVal[1],trgtLog) + \
                                        self.extractFieldValue(hit, fieldVal[3], trgtLog) + self.extractFieldValue(hit, fieldVal[4], trgtLog)
                                else:
                                    self.hitDict[hitKey][field]= \
                                        self.extractFieldValue(hit, fieldVal[0], trgtLog)+"://"+self.extractFieldValue(hit, fieldVal[1],trgtLog) + \
                                        ":" + self.extractFieldValue(hit, fieldVal[2], trgtLog) + self.extractFieldValue(hit, fieldVal[3], trgtLog) + \
                                        self.extractFieldValue(hit, fieldVal[4], trgtLog)
                    elif field in ['SourceIP:Port', 'DestIP:Port']:
                        self.hitDict[hitKey][field]=self.extractFieldValue(hit, fieldVal[0], trgtLog)+":"+self.extractFieldValue(hit, fieldVal[1],trgtLog)
                    else:
                        self.hitDict[hitKey][field]=''
                        for i in fieldVal:
                            self.hitDict[hitKey][field]+=self.extractFieldValue(hit, i, trgtLog)
            if self.checkWhitelist(trgtLog, self.hitDict[hitKey]):
                self.hitDict.pop(hitKey)
                print("Not reporting hit %s in %s logs" % (attr["value"],trgtLog))
                return
            self.hitDict[hitKey]['Hit']=attr["value"]
            self.hitDict[hitKey]['EventID']=attr["event_id"]
            self.hitDict[hitKey]['Info']=attr["Event"]['info']
            self.hitDict[hitKey]['Count']=1

    def checkWhitelist(self, trgtLog, hit):
        for item in self.whitelist:
            if trgtLog in item['logs']:
                for field in hit.keys():
                    if field == item['field']:
                        for v in item['values']:
                            if v in hit[field]:
                                return True
        return False

    def extractFieldValue(self, hit, fName, logSource):
        try:
            return str(hit["_source"][fName])
        except KeyError:
            return ""

    def buildIocDict(self, targetLogs):
        self.iocDict={'url':[],'domain':[],'ip':[],'user-agent':[],'e-mail':[],'process':[],'registry':[]}
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
        for i in self.iocTypes['e-mail']:
            self.iocDict['e-mail'].append(self.mispSearch(i))
        for i in self.iocTypes['process']:
            self.iocDict['process'].append(self.mispSearch(i))
        for i in self.iocTypes['registry']:
            self.iocDict['registry'].append(self.mispSearch(i))
        #else:
        #   self.errorexit("Support for these logs not implemented.")
        count=0
        for k in self.iocDict.keys():
            for attr in self.iocDict[k]:
                for a in attr:
                    count+=1
        #print(count)

    ### TODO
    def pushToTaxii(self, event_data_misp):
        try:
            #misp_event = MISPEvent()
            #misp_event.from_json(json.dumps(event_data_misp))
            #print(misp_event)
            stix_package = pymisp.tools.stix.make_stix_package(json.dumps(event_data_misp), to_json=True)
            print(stix_package)
        except Exception as e:
            print(e)

    @staticmethod
    def getsearchval(val, iocType, searchtype):
        if "|port" in iocType or (iocType=="domain|ip" and searchtype=="domain"):
            tmpDomain = val.split('|')[0]
            if tmpDomain[:4] == "www.":
                return tmpDomain[4:]
            return tmpDomain
        if iocType=="domain|ip" and searchtype=="ip":
            return val.split('|')[1]
        if iocType=="domain" and val[:4] == "www.":
            return val[4:]
        if iocType=="regkey|value" and searchtype=="process":
            return val.split('|')[1]
        return val


    @staticmethod
    def parseUrl(url, section):
        u = urlparse(url)
        if "web_domain" in section:
            #if url[:4] == "www.":
            #    return u.hostname[4:]
            #else:
            #    return u.hostname
            if not u.scheme:
                return u.path.split('/')[0]
            else:
                return u.hostname
        if 'uri_path' in section:
            if not u.scheme:
                rVal = '/'.join(u.path.split('/')[1:])
            else:
                rVal = u.path
            if rVal[0] != '/':
                rVal = '/' + rVal
            return rVal
        if 'uri_query' in section:
            if u.query:
                return '?' + u.query
            else:
                return ""
        return url

    @staticmethod
    def errorexit(reason):
        print (reason + "\n")
        exit()
