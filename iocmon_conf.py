misp_config={
    'misp_url':'',
    'misp_authkey':'',
    'misp_verifycert':False,
    'misp_return_format':'json',
    'misp_searchable_types':{
        'url':['url','uri'],
        'domain':['domain', 'domain|ip', 'hostname'],
        'ip':['ip-src', 'ip-dst', 'ip-dst|port',
        'ip-src|port', 'domain|ip'],
        'user-agent':['user-agent'],
        'e-mail':['email-src', 'email-dst', 'email-reply-to'],
        'process':['filename', 'windows-service-name', 'windows-service-displayname', 'regkey|value'],
        'registry':['regkey', 'regkey|value']
    }
}
# 'email-subject', 'email-x-mailer', 'email-attachment'

elastic_config={
    'elastic_url':'',
    'elastic_ip':'127.0.0.1',
    'elastic_port':'443',
    'elastic_login_url':'https://127.0.0.1:443/api/auth/login',
    'elastic_index':r'index-*',
    'elastic_user':"",
    'elastic_pw':'',
    'elastic_json':'elastic.json',
    'elastic_headers':{'Content-Type':'application/json', 'Accept': 'application/json', 'kbn-xsrf':'reporting'}
    }

event_blacklist="event_blacklist.txt"

log_whitelist=[
    {
        'logs':['firewall'],
        'field':'Outcome',
        'values':['Drop'],
        'action':'log'
    },
    {
        'logs':['firewall'],
        'field':'Protocol',
        'values':['6'],
        'action':'log'
    },
    {
        'logs':['bind-dns'],
        'field':'SourceIP:Port',
        'values':['1,1,1,1'],
        'action':'log'
    }
]

TYPEMAPPING={
    "Kibana":{
        'domain':['proxy_host.keyword','proxy_supplier_name.keyword'],
        'ip':['proxy_s_supplier_ip.keyword'],
        'url':['proxy_uri.keyword'],
        'user-agent':['proxy_user_agent.keyword'],
        'all':['proxy_method', 'proxy_categories', 'proxy_s_supplier_ip',
           'proxy_status', 'tags', 'proxy_referer', 'proxy_uri_port',
           'proxy_date_time_utc','proxy_filter_result','proxy_user_agent',
           'proxy_user', 'proxy_c_ip', 'proxy_uri']
    },
    "Elastic":{
        'domain':['web_domain.keyword', 'query.keyword'],
        'ip':['dest_ip', 'src_ip', 'dest_host.keyword'],
        'url':['web_domain.keyword', 'uri_path.keyword', 'uri_query.keyword'],
        'user-agent':['user_agent.keyword'],
        'e-mail':['sender.keyword', 'recipient.keyword'],
        'process':['process_name.keyword', 'process.keyword', 'file_name.keyword'],
        'registry':['file_path', 'file_parent', 'file_name.keyword'],
        'parser':'elastic_parser_name',
        'targetLogs':{
            'proxy':[
                {
                    'User':'user',
                    'ClientIP':'src_ip',
                    'Request':['protocol', 'web_domain', 'dest_port', 'uri_path', 'uri_query'],
                    'User Agent':'user_agent',
                    'Destination IP':'dest_ip',
                    'Method':'method',
                    'Action':'action',
                    'Datetime':'time',
                    'Category':'category',
                    'Result Code':'result_code',
                    'Proxy Action':'proxy_action',
                    'Referer':'referrer'
                },
                {
                    'hitKey':['user', 'src_ip', 'web_domain', 'uri_path', 'uri_query']
                }
            ],
            'bind-dns':[
                {
                    'Identifier':'identifier',
                    'SourceIP:Port':['src_ip', 'src_port'],
                    'DNS Host':'host',
                    'Outcome':'outcome',
                    'Activity':'activity_type',
                    'Query Type':'query_type',
                    'Query':'query',
                    'Datetime':'time'
                },
                {
                    'hitKey':['src_ip', 'src_port', 'query']
                }
            ],
            'named-dns':[
                {
                    'Identifier':'identifier',
                    'Outcome':'outcome',
                    'Activity':'activity_type',
                    'Query Type':'query_type',
                    'Query':'query',
                    'Destination IP':'dest_ip',
                    'Datetime':'time'
                },
                {
                    'hitKey':['query', 'dest_ip']
                }
            ],
            'email':[
                {
                    'Vendor':'Vendor',
                    'Sender':'sender',
                    'Recipients':'recipients',
                    'Datetime':'time'
                },
                {
                    'hitKey':['sender', 'recipients']
                }
            ],
            'firewall':[
                {
                    'Host':'host',
                    'Activity':'activity_type',
                    'Rule':'rule',
                    'Product':'Product',
                    'SourceIP:Port':['src_ip','src_port'],
                    'DestIP:Port':['dest_ip', 'dest_port'],
                    'Protocol':'protocol',
                    'User':'user',
                    'Outcome':'outcome',
                    'Datetime':'time'
                },
                {
                    'hitKey':['src_ip', 'src_port', 'dest_ip', 'dest_port', 'outcome']
                }
            ],
            'syslog':[
                {
                    'Process Name':'process_name',
                    'Directory':'directory',
                    'Process Id':'pid',
                    'Event Source':'forwarder',
                    'Hostname':'host',
                    'DestIP:Port':['dest_ip', 'dest_port'],
                    'Destination Host':'dest_host',
                    'Activity':'activity_type',
                    'Outcome':'outcome',
                    'Event Name':'event_name',
                    'Event Code':'event_code',
                    'Vendor':'vendor',
                    'Product':'Product',
                    'Datetime':'time'
                },
                {
                    'hitKey':['process_name', 'host', 'pid']
                }
            ],
            'database':[
                {
                    'Process':'process',
                    'Activity':'activity_type',
                    'Outcome':'outcome',
                    'Host':'host',
                    'Destination Host':'dest_host',
                    'Destination Port':'dest_port',
                    'Protocol':'protocol',
                    'Data Type':'data_type',
                    'User': 'user',
                    'Vendor':'Vendor',
                    'Product':'Product',
                    'Datetime':'time'
                },
                {
                    'hitKey':['process', 'host', 'dest_host']
                }
            ]
        }
    }
}
