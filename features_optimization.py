# -*- coding: utf-8 -*-
# Purpose -
# Running this file (stand alone) - For extracting all the features from a web page for testing.
# Notes -
# 1 stands for phishing
# 0 stands for suspicious
# -1 stands for legitimate

from bs4 import BeautifulSoup
import urllib
import bs4
import re
import socket
import whois
# pip install python-whois
import requests

import pandas as pd
import numpy as np

try:
    from urllib.request import urlopen, Request
except ImportError:
    from urllib2 import urlopen, Request


from datetime import datetime
import time

# https://breakingcode.wordpress.com/2010/06/29/google-search-python/
# Previous package structure was modified. Import statements according to new structure added. Also code modified.
from googlesearch import search
# pip install google-search
# pip install beautifulsoup4
# pip install google

# This import is needed only when you run this file in isolation.
import sys

import nmap
#  https://nmap.org/download.html  << download nmap-7.80-setup.exe
# C:\Users\kgh01\AppData\Local\Programs\Python\Python37\Lib\site-packages\nmap\nmap.py
# 82 line
#     def __init__(self, nmap_search_path=('nmap', '/usr/bin/nmap', '/usr/local/bin/nmap', '/sw/bin/nmap', '/opt/local/bin/nmap', 'C:\\Program Files (x86)\\Nmap\\nmap')):
# 다음과 같이 경로 수정   # 환경변수를 수정해도 됨.... 

from patterns import *
from def_sslfinal_State import *
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
import pyperclip
import threading

import clf

driver_path ='chromedriver_win32\\chromedriver'

# Path of your local server. Different for different OSs.
LOCALHOST_PATH = "input/"
# C:\Users\home\Desktop\tenser\input\Malicious-Web-Content-Detection-Using-Machine-Learning



#1
def having_ip_address(url, status):
    ip_address_pattern = ipv4_pattern + "|" + ipv6_pattern
    match = re.search(ip_address_pattern, url)
    status['01. Having IP address'] =  1 if match else -1

#2
def url_length(url, status):
    if len(url) < 54:
        status['02. URL Length'] = -1
    elif 54 <= len(url) <= 75:
        status['02. URL Length'] = 0
    else:
        status['02. URL Length'] = 1

#3
def shortening_service(url, status):
    match = re.search(shortening_services, url)
    status['03. URL Shortening service'] = 1 if match else -1

#4
def having_at_symbol(url, status):
    match = re.search('@', url)
    status['04. Having @ symbol'] =  1 if match else -1

#5
def double_slash_redirecting(url, status):
    # since the position starts from 0, we have given 6 and not 7 which is according to the document.
    # It is convenient and easier to just use string search here to search the last occurrence instead of re.
    last_double_slash = url.rfind('//')
    status['05. Having double slash'] = 1 if last_double_slash > 6 else -1

#6
def prefix_suffix(domain, status):
    match = re.search('-', domain)
    status['06. Having dash symbol(Prefix Suffix)'] =  1 if match else -1

#7
def having_sub_domain(url, status):
    # Here, instead of greater than 1 we will take greater than 3 since the greater than 1 condition is when www and
    # country domain dots are skipped
    # Accordingly other dots will increase by 1
    if having_ip_address(url, dict()) == 1:
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5]))|(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',
            url)
        pos = match.end()
        url = url[pos:]
    num_dots = [x.start() for x in re.finditer(r'\.', url)]
    if len(num_dots) <= 3:
        status['07. Having multiple subdomains'] = -1
    elif len(num_dots) == 4:
        status['07. Having multiple subdomains'] = 0
    else:
        status['07. Having multiple subdomains'] = 1

import ssl_checker as sc

#8 ssl_state

#9
def domain_registration_length(domain, status):
    expiration_date = domain.expiration_date
    today = time.strftime('%Y-%m-%d')
    today = datetime.strptime(today, '%Y-%m-%d')

    registration_length = 0
    # Some domains do not have expiration dates. This if condition makes sure that the expiration date is used only
    # when it is present.
    if expiration_date:
        registration_length = abs((expiration_date - today).days)
    status['09. Domain Registration Length'] =  1 if registration_length / 365 <= 1 else -1

#10
def favicon(wiki, soup, domain, status):
    for head in soup.find_all('head'):
        for head.link in soup.find_all('link', href=True):
            dots = [x.start() for x in re.finditer(r'\.', head.link['href'])]
            status['10. Favicon'] = -1 if wiki in head.link['href'] or len(dots) == 1 or domain in head.link['href'] else 1
            return
    status['10. Favicon'] = -1

#11 port
def port(hostname, status):
    nm = nmap.PortScanner()
    ports = [21,22,23,80,443,445,1433,1521,3306,3389]
    nnm = nm.scan(arguments = '-T4 -p 21,22,23,80,443,445,1433,1521,3306,3389', hosts = hostname)   #T4 : 속도 (0~4) : 빠른 스캔 

    host_ip = list(nnm['scan'].keys())[0]
    
    p_21 = nm[host_ip]['tcp'][21]['state']
    p_22 = nm[host_ip]['tcp'][22]['state']
    p_23 = nm[host_ip]['tcp'][23]['state']
    p_80 = nm[host_ip]['tcp'][80]['state']
    p_443 = nm[host_ip]['tcp'][443]['state']
    p_445 = nm[host_ip]['tcp'][445]['state']
    p_1433 = nm[host_ip]['tcp'][1433]['state']
    p_1521 = nm[host_ip]['tcp'][1521]['state']
    p_3306 = nm[host_ip]['tcp'][3306]['state']
    p_3389 = nm[host_ip]['tcp'][3389]['state']

    if( p_21 == 'close' and p_22 == 'close' and p_23 == 'close' and p_445 == 'close' and
        p_1433 == 'close' and p_1521 == 'close' and p_3306 == 'close' and p_3389 == 'close' and
        p_80 == 'open' and p_443 == 'open'):
        status['11. port'] = 1
    else :
        status['11. port'] = -1



#12
def https_token(url, status):
    match = re.search(http_https, url)
    if match and match.start() == 0:
        url = url[match.end():]
    match = re.search('http|https', url)
    status['12. HTTP or HTTPS token in domain name']= 1 if match else -1

#13
def request_url(wiki, soup, domain, status):
    i = 0
    success = 0
    for img in soup.find_all('img', src=True):
        dots = [x.start() for x in re.finditer(r'\.', img['src'])]
        if wiki in img['src'] or domain in img['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    for audio in soup.find_all('audio', src=True):
        dots = [x.start() for x in re.finditer(r'\.', audio['src'])]
        if wiki in audio['src'] or domain in audio['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    for embed in soup.find_all('embed', src=True):
        dots = [x.start() for x in re.finditer(r'\.', embed['src'])]
        if wiki in embed['src'] or domain in embed['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    for i_frame in soup.find_all('i_frame', src=True):
        dots = [x.start() for x in re.finditer(r'\.', i_frame['src'])]
        if wiki in i_frame['src'] or domain in i_frame['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    try:
        percentage = success / float(i) * 100
    except:
        status['13. Request URL']= -1
        return

    if percentage < 22.0:
        status['13. Request URL']= -1
    elif 22.0 <= percentage < 61.0:
        status['13. Request URL']= 0
    else:
        status['13. Request URL']= 1

#14
def url_of_anchor(wiki, soup, domain, status):
    i = 0
    unsafe = 0
    for a in soup.find_all('a', href=True):
        # 2nd condition was 'JavaScript ::void(0)' but we put JavaScript because the space between javascript and ::
        # might not be
        # there in the actual a['href']
        if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (
                wiki in a['href'] or domain in a['href']):
            unsafe = unsafe + 1
        i = i + 1
        # print a['href']
    try:
        percentage = unsafe / float(i) * 100
    except:
        status['14. URL of Anchor']= -1
        return
    if percentage < 31.0:
        status['14. URL of Anchor']= -1
        # return percentage
    elif 31.0 <= percentage < 67.0:
        status['14. URL of Anchor']= 0
    else:
        status['14. URL of Anchor']= 1

#15
# Links in <Script> and <Link> tags
def links_in_tags(wiki, soup, domain, status):
    i = 0
    success = 0
    for link in soup.find_all('link', href=True):
        dots = [x.start() for x in re.finditer(r'\.', link['href'])]
        if wiki in link['href'] or domain in link['href'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    for script in soup.find_all('script', src=True):
        dots = [x.start() for x in re.finditer(r'\.', script['src'])]
        if wiki in script['src'] or domain in script['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1
    try:
        percentage = success / float(i) * 100
    except:
        status['15. Links in tags']= -1
        return

    if percentage < 17.0:
        status['15. Links in tags']= -1
    elif 17.0 <= percentage < 81.0:
        status['15. Links in tags']= 0
    else:
        status['15. Links in tags']= 1

#16
# Server Form Handler (SFH)
# Have written conditions directly from word file..as there are no sites to test ######
def sfh(wiki, soup, domain, status):
    for form in soup.find_all('form', action=True):
        if form['action'] == "" or form['action'] == "about:blank":
            status['16. SFH']= 1
            return
        elif wiki not in form['action'] and domain not in form['action']:
            status['16. SFH']= 0
            return
        else:
            status['16. SFH']= -1
            return
    status['16. SFH']= -1

#17
# Mail Function
# PHP mail() function is difficult to retrieve, hence the following function is based on mailto
def submitting_to_email(soup, status):
    for form in soup.find_all('form', action=True):
        status['17. Submitting to email']= 1 if "mailto:" in form['action'] else -1
    # In case there is no form in the soup, then it is safe to return 1.
    status['17. Submitting to email']= -1

#18
def abnormal_url(domain, url, status):
    hostname = domain.name
    match = re.search(hostname, url)
    status['18. Abnormal URL']= -1 if match else 1
#19
def redirect(url, status):
    r = requests.get(url)
    history = r.history

    if (len(history) < 1):
        status['19. Redirect']= -1
    elif (len(history) >= 2 and len(history) < 4):
        status['19. Redirect']= 0
    else :
        status['19. Redirect']= 1

#20 on_mouseover
def onmouseover_fakeurl(url, status):
    # href parse link regular expression
    href_re = re.compile("""href=\"?'?[^"]*\"?'?""")
    try:
        res = urlopen(Request(url))
        html = res.read()
        bs = BeautifulSoup(html, 'html.parser')
        tags = [str(i) for i in bs.findAll('a')]

        for tag in tags :
            urls = [re.sub(""""|https://|http://|'|"|;|href=""", "", i) for i in href_re.findall(tag)] # a tag extract href url
            for url in urls[1:]:
                if url == urls[0]:
                    status['20. on_mouseover']= 1
                    return
                    #fake url exist so pishing
        else:
            status['20. on_mouseover']= -1
    except:
        status['20. on_mouseover']= 1

#21 RightClick 22 popUpWindow


def selenium_Right_click_AND_Popup(url, status):
    options = webdriver.ChromeOptions()
    
    options.add_argument("no-sandbox")
    options.add_argument("disable-gpu")   # 가속 사용 x
    options.add_argument("lang=ko_KR")    # 가짜 플러그인 탑재
    options.add_argument("disable-infobars")
    options.add_argument("--disable-extensions")

    try:
        driver = webdriver.Chrome(driver_path, options=options)
        driver.get(url)

        bodys = driver.find_element_by_xpath('//body')
        driver.implicitly_wait(1) # wait for parse

        pyperclip.copy("")
        bcp = pyperclip.paste()

        bodys.click()
        bodys.send_keys(Keys.HOME)
        bodys.send_keys(Keys.CONTROL, 'a')
        bodys.send_keys(Keys.CONTROL, 'c')

        afcp = pyperclip.paste().replace(" ", "")

        if bcp == afcp :
            print("can't copy anymore")
            status["21.RightClick"] = 1

        else:
            print("something copied")
            status["21.RightClick"] = -1

        parentWindow = driver.current_window_handle

        for winHandle in driver.window_handles:
            if winHandle != parentWindow:
                driver.switch_to_window(winHandle)
                fields = driver.find_elements_by_xpath("//body//input[@type='text']|//input[@type='password']|//textarea")
                print("has popup page!")
                if len(fields) > 0:
                    status["22. popUpWindow"] = 1
                    #phishing
                else:
                    status["22. popUpWindow"] = -1
                    #legit
            else:  #no popupWindow
                status["22. popUpWindow"] = -1
    except:
        status["21.RightClick"] = 1
        status["22. popUpWindow"] = 1
    driver.close()
    driver.quit()
    
#23
# IFrame Redirection
def i_frame(soup, status):
    for i_frame in soup.find_all('i_frame', width=True, height=True, frameBorder=True):
        # Even if one iFrame satisfies the below conditions, it is safe to return -1 for this method.
        if i_frame['width'] == "0" and i_frame['height'] == "0" and i_frame['frameBorder'] == "0":
            status['23. IFrame'] = 1
        if i_frame['width'] == "0" or i_frame['height'] == "0" or i_frame['frameBorder'] == "0":
            status['23. IFrame'] = 0
    # If none of the iframes have a width or height of zero or a frameBorder of size 0, then it is safe to return 1.
    status['23. IFrame'] = -1

#24
def age_of_domain(domain, status):
    creation_date = domain.creation_date
    expiration_date = domain.expiration_date
    ageofdomain = 0
    if expiration_date:
        ageofdomain = abs((expiration_date - creation_date).days)
    status['24. Age of Domain']= 1 if ageofdomain / 30 < 6 else -1

#26
def web_traffic(url, status):
    try:
        rank = \
            bs4.BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find(
                "REACH")['RANK']
    except TypeError:
        status['26. Web Traffic']= 1
        return
    rank = int(rank)
    status['26. Web Traffic']= -1 if rank < 100000 else 0

#27
def google_index(url, status):
    site = search(url, 5)
    status['27. Google Index']= -1 if site else 1

#28 LinksPointingToPage


def getExternalLinks(url):
    response = requests.get(url)
    html = BeautifulSoup(response.text, "html.parser")
    externalLinks = []
    
    for link in html.findAll("a",
                             href=re.compile("^(http|www)((?!"+get_hostname_from_url(url)+").)*$")):
        if link.attrs['href'] is not None:
            if link.attrs['href'] not in externalLinks:
                externalLinks.append(link.attrs['href'])
    return externalLinks

def links_pointing_to_page(url, status):
    if len(getExternalLinks(url)) == 0:
        status['28. LinksPointingToPage']= 1
    elif 0 < len(getExternalLinks(url)) and 2 > len(getExternalLinks(url)):
        status['28. LinksPointingToPage']= 0
    else :
        status['28. LinksPointingToPage']= -1


#29
def statistical_report(url, hostname, status):
    try:
        ip_address = socket.gethostbyname(hostname)
    except:
        status['29. Statistical Reports']= 1
        return
    url_match = re.search(
        r'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
    ip_match = re.search(
        '146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
        '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
        '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
        '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
        '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
        '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',
        ip_address)
    if url_match:
        status['29. Statistical Reports']= 1
    elif ip_match:
        status['29. Statistical Reports']= 1
    else:
        status['29. Statistical Reports']= -1

def get_hostname_from_url(url):
    hostname = url
    # TODO: Put this pattern in patterns.py as something like - get_hostname_pattern.
    #pattern = "https://|http://|www.|https://www.|http://www."
    pattern = "www.|https://www.|http://www.|https://|http://"
    pre_pattern_match = re.search(pattern, hostname)

    if pre_pattern_match:
        hostname = hostname[pre_pattern_match.end():]
        post_pattern_match = re.search("/", hostname)
        if post_pattern_match:
            hostname = hostname[:post_pattern_match.start()]

    return hostname

# TODO: Put the DNS and domain code into a function.
#C:\Users\home\Desktop\tenser\input\Malicious-Web-Content-Detection-Using-Machine-Learning\markup.txt


def parse_url(url):
    with open(LOCALHOST_PATH  + '\markup.txt', 'r') as files:
        soup_string = files.read()

    soup = BeautifulSoup(soup_string, 'html.parser')
    hostname = get_hostname_from_url(url)

    threads = []
    status = {}
    threads.append(threading.Thread(target=having_ip_address, args=(url, status))) #1
    threads.append(threading.Thread(target=url_length, args=(url, status))) #2
    threads.append(threading.Thread(target=shortening_service, args=(url, status))) #3    
    threads.append(threading.Thread(target=having_at_symbol, args=(url, status))) #4
    threads.append(threading.Thread(target=double_slash_redirecting, args=(url, status))) #5    
    threads.append(threading.Thread(target=prefix_suffix, args=(hostname, status))) #6
    threads.append(threading.Thread(target=having_sub_domain, args=(url, status))) #7
    
    status['08. SSL Final State']= sslfinal_state(url) #8

    
    dns = -1
    try:
        domain = whois.query(hostname)
    except:
        dns = 1

    if dns == 1:
        status['09. Domain Registration Length'] = 1
    else:
        threads.append(threading.Thread(target=domain_registration_length, args=(domain, status))) #9
    
    
    threads.append(threading.Thread(target=favicon, args=(url, soup, hostname, status))) #10    
    threads.append(threading.Thread(target=port, args=(hostname, status))) #11    
    threads.append(threading.Thread(target=https_token, args=(url, status))) #12
    threads.append(threading.Thread(target=request_url, args=(url, soup, hostname, status))) #13    
    threads.append(threading.Thread(target=url_of_anchor, args=(url, soup, hostname, status))) #14
    threads.append(threading.Thread(target=links_in_tags, args=(url, soup, hostname, status))) #15
    threads.append(threading.Thread(target=sfh, args=(url, soup, hostname, status))) #16    
    threads.append(threading.Thread(target=submitting_to_email, args=(soup, status))) #17


    if dns == 1:
        status['18. Abnormal URL'] = 1
    else:
        threads.append(threading.Thread(target=abnormal_url, args=(domain, url, status))) #18
    
    threads.append(threading.Thread(target=redirect, args=(url, status))) #19
    threads.append(threading.Thread(target=onmouseover_fakeurl, args=(url, status))) #20
    threads.append(threading.Thread(target=selenium_Right_click_AND_Popup, args=(url, status))) #21, 22
    threads.append(threading.Thread(target=i_frame, args=(soup, status))) #23

    if dns == 1:
        status['24. Age of Domain'] = 1
    else:
        threads.append(threading.Thread(target=age_of_domain, args=(domain, status))) #24

    status['25. DNS Record'] = dns

    threads.append(threading.Thread(target=web_traffic, args=(soup, status))) #26
    threads.append(threading.Thread(target=google_index, args=(url, status))) #27
    threads.append(threading.Thread(target=links_pointing_to_page, args=(url, status))) #28
    
    threads.append(threading.Thread(target=statistical_report, args=(url, hostname, status))) #29
    

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    result_arr = popstatus(status)
    result = clf.clf_fnc(result_arr)
    return result[0]

"""
    print('\n'
          '1. Having IP address\n'
          '2. URL Length\n'
          '3. URL Shortening service\n'
          '4. Having @ symbol\n'
          '5. Having double slash\n'
          '6. Having dash symbol(Prefix Suffix)\n'
          '7. Having multiple subdomains\n'
          '8. SSL Final State\n'  
          '9. Domain Registration Length\n'
          '10. Favicon\n'
          '11. port \n'  
          '12. HTTP or HTTPS token in domain name\n'
          '13. Request URL\n'
          '14. URL of Anchor\n'
          '15. Links in tags\n'
          '16. SFH\n'
          '17. Submitting to email\n'
          '18. Abnormal URL\n'
          '19. Redirect\n' 
          '20. on_mouseover \n'
          '21. RightClick \n'
          '22. popUpWindow \n'
          '23. IFrame\n'
          '24. Age of Domain\n'
          '25. DNS Record\n'
          '26. Web Traffic\n'
          #'27. Page_Rank \n' #-
          '27. Google Index\n'
          '28. LinksPointingToPage \n'
          '29. Statistical Reports\n')
"""
   

def popstatus(status):
    arr=[]
    for i in sorted(status.keys()):
        arr.append(status[i])
    return arr

def time_check(url):
    stt = time.time()
    parse_url(url)
    print("running time : %f" %(time.time() - stt))


if __name__ == "__main__":
    url = "https://www.naver.com"
    url2 = "https://twenz.drivethruhustler.com/kr/?o=2020&r=mmg154302897tbsd&a=63&sa=9773"
    time_check(url2)

