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
        'user-agent':['user-agent']
    }
}

elastic_config={
    'elastic_url':'',
    'elastic_ip':'',
    'elastic_port':'443',
    'elastic_login_url':'',
    'elastic_index':r'elastic-*',
    'elastic_user':"",
    'elastic_pw':'',
    'elastic_json':'',
    'elastic_headers':{'Content-Type':'application/json', 'Accept': 'application/json', 'kbn-xsrf':'reporting'}
    }

event_blacklist=""

TYPEMAPPING={
    "Elastic":{
        'domain':['domain'],
        'ip':['dest_ip', 'src_ip'],
        'url':['domain', 'uri_path', 'uri_query'],
        'user-agent':['user_agent'],
        'parser':'parser_name',
        'proxy':['method', 'category', 'dest_ip',
            'result_code', 'referrer', 'dest_port',
            'time', 'proxy_action', 'user_agent',
            'user', 'src_ip', 'protocol', 'domain',
            'uri_path', 'uri_query', 'dest_port']
    }
}
