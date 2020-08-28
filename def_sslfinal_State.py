# -*- coding: utf-8 -*-
import ssl_checker as sc
import sys
import time

url = 'https://www.nar.com/'
sys.argv = ["def_sslfinal_State.py", "-H", url]

'''
## SSLfinal_State	 SSL 발급자
def sslfinal_state(url):    #분명한 조건 구분 필요
    #ssl api 활용 https://github.com/narbehaj/ssl-checker
    #if 신뢰할 수 있고, 유효기간 1년 이상인 경우 1
    #if 유효기간 1년 미만인경우 0
    #if 신뢰할 수 없는 경우 0 (GeoTrust, GoDaddy,NetworkSolutions,Thawte, Comodo(Sectigo), Doster and VeriSign) 이 아닌경우    #else -1
    'DigiCert Inc' 
    'GoDaddy.com, Inc.'
    'Sectigo Limited'
    'DigiCert Inc'
    'Amazon'

    # https://en.wikipedia.org/wiki/Certificate_authority
    1 : IdenTrust  51.2%    'IdenTrust'
    2 : DigiCert  19.7%     'DigiCert Inc'
    3 : Sectigo  17.7%      'Sectigo Limited'
    4 : GoDaddy  6.9%       'GoDaddy INC.'
    5 : GlobalSign  3.0%    'GlobalSign nv-sa'

    naver : Sectigo / facebook : DigiCert / google : Google Trust Services

'''
def sslfinal_state(url): 
    sc_args = sc.get_args()
    #sc.show_result(sc_args)
    #print(sc_args.hosts[0])
    sc_filter_hostname = sc.filter_hostname(sc_args.hosts[0])
    #print(sc_filter_hostname[0])  #host
    #print(sc_filter_hostname[1])  #port
    host = sc_filter_hostname[0]
    port = sc_filter_hostname[1]
    #sc_cert = sc.get_cert(sc_filter_hostname[0], sc_filter_hostname[1], sc_args)
    #sc.get_cert_info()
    sc_cert = sc.get_cert(host, port, sc_args)
    sc_cert_info = sc.get_cert_info(host, sc_cert)
    #print(sc_cert_info)

    #print(sc_cert_info['days_left'])
    #print(sc_cert_info['issuer_o'])
    if (sc_cert_info['issuer_o'] == 'DigiCert Inc' or
        sc_cert_info['issuer_o'] == 'GoDaddy.com, Inc.' or
        sc_cert_info['issuer_o'] == 'Sectigo Limited' or
        sc_cert_info['issuer_o'] == 'DigiCert Inc' or
        sc_cert_info['issuer_o'] == 'Amazon' and
        sc_cert_info['days_left'] >= 365 ) :
        return -1
    elif not (sc_cert_info['issuer_o'] == 'DigiCert Inc' or
        sc_cert_info['issuer_o'] == 'GoDaddy.com, Inc.' or
        sc_cert_info['issuer_o'] == 'Sectigo Limited' or
        sc_cert_info['issuer_o'] == 'DigiCert Inc' or
        sc_cert_info['issuer_o'] == 'Amazon'):
        return 0
    else : return 1
    

