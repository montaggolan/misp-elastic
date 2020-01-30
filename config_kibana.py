KFIELDS={
'method':'method', 'sip':'supplier_ip', 'status':'status', 'referer':'referer',
'port':'uri_port', 'DateTime':'date_time_utc', 'result':'filter_result',
'UA':'user_agent', 'user':'user', 'cip':'client_ip', 'URI':'uri'}
TYPEMAPPING={
'domain':['host.keyword', 'supplier_name.keyword'],
'ip':['supplier_ip.keyword'],
'url':['uri.keyword'],
'user-agent':['user_agent.keyword']}
kib_index = 'index'
kibana_url = ''
kibana_user = ''
kibana_pw = ''
kibana_json = ''
kibana_headers = ''
