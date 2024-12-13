import sys
import requests
import json
from lxml import objectify
import pandas as pd
import time
import base64
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from dateutil.relativedelta import relativedelta
import re
from io import BytesIO
from .qualys_redact import redactor, RedactorOptions
from pdfrw import PdfReader, PdfWriter, PageMerge
from pe_reports.data.config import staging_config

from .data.pe_db.db_query_source  import api_was_report_insert
API_DIC = staging_config(section="was")
username = API_DIC.get("username")
password = API_DIC.get("password")

class InvalidQualysCall(Exception):
    """Raise When qualys returns an error."""
    pass
class InvalidApiCall(Exception):
    """Raise when the API call is invalid or no data is returned."""
    pass

def qualys_post_call(link,header,data,validate=True):
    """Make a call to Qualys API."""
    response = requests.request("POST",link, headers=header,data=json.dumps(data))
    if validate != True:
        return json.loads(response.text)
    if response.status_code != 200:
        print("Error Code: %s", response.status_code)
        raise InvalidQualysCall
    responseJson = json.loads(response.text)
    if responseJson['ServiceResponse']['responseCode'] != 'SUCCESS':
        print(responseJson['ServiceResponse']['responseCode'])
        raise InvalidApiCall
    return responseJson

def qualys_get_call(link, header):
    response = requests.request("GET", link, headers=header, data={})
    if response.status_code != 200:
        print("Error Code: %s", response.status_code)
        raise InvalidQualysCall
    
    responseJson = json.loads(response.text)
    if responseJson['ServiceResponse']['responseCode'] != 'SUCCESS':
        print(responseJson['ServiceResponse']['responseCode'])
        raise InvalidApiCall
    return responseJson

def qualys_report_download(link,header):
    response = requests.request("GET", link, headers=header, data={})
    if response.status_code != 200:
        print("Error Code: %s", response.status_code)
        raise InvalidQualysCall
    return response.text


def app_count(tag):
    try:
        header = {
            'Content-Type' : "application/json",
            'accept' : "application/json",
            'user' : username,
            'password' : password
            }
        
        url = "https://qualysapi.qg3.apps.qualys.com/qps/rest/3.0/count/was/webapp"

        payload = {
            "ServiceRequest": {
                "filters": {
                    "Criteria":[
                        {
                            "field" : "tags.name",
                            "operator" : "EQUALS",
                            "value" : tag
                        }
                    ]
                }
            }
        }
        
        app_cnt = qualys_post_call(url,header,payload)
        return app_cnt['ServiceResponse']['count']
    except:
        print("Failed to retrieve webapp count")
        return None
    
def get_tag(org):
    try:
        header = {
            'Content-Type' : "application/json",
            'accept' : "application/json",
            'user' : username,
            'password' : password
            }
        
        url = "https://qualysapi.qg3.apps.qualys.com/qps/rest/2.0/search/am/tag"

        payload = {
            "ServiceRequest": {
                "filters": {
                    "Criteria":[
                        {
                            "field" : "name",
                            "operator" : "EQUALS",
                            "value" : org
                        }
                    ]
                }
            }
        }
        
        tag_response = qualys_post_call(url,header,payload)
        if tag_response['ServiceResponse']['count'] == 0:
            print("No Tag found with that name.")
            return None
        else:
            tag_id = tag_response['ServiceResponse']['data'][0]['Tag']
            # print("The tag ID is: " + tag_id )
        return tag_id
    except:
        print("Failed to retrieve tag id")
        return None
    
    
def create_webapp_report_v2(org, tag_info):
    try:
        header = {
            'Content-Type' : "application/json",
            'accept' : "application/json",
            'user' : username,
            'password' : password
            }
        
        url = "https://qualysapi.qg3.apps.qualys.com/qps/rest/3.0/create/was/report"

        payload = {
            "ServiceRequest": {
                "data":{
                    "Report":{
                        "name":f"<![CDATA[{tag_info['name']}]]>",
                        "format":"XML",
                        "type":"WAS_WEBAPP_REPORT",
                        "template":{
                            "id":"1994875"
                        },
                        "config":{
                            "webAppReport":{
                                "target":{
                                    "tags":{
                                        "included":{
                                            "option":"ALL",
                                            "tagList":{
                                                "Tag":{
                                                    "id":tag_info['id']
                                                }}}}}}}}}}}
        
        report = qualys_post_call(url,header,payload,False)
        
        if report.get("ServiceResponse",{}).get("responseCode", None) == "SUCCESS":
            return report.get("ServiceResponse",{}).get("data",[{}])[0].get("Report",{}).get('id',None)
        else:
            print(f"Got the INVALID_REQUEST response. skipping {org}")
            return None
        
    except Exception as e:
        print(e)
        print("Failed to create report")
        return None

def get_report(id):
    header = {
        'Content-Type' : "application/json",
        'accept' : "application/json",
        'user' : username,
        'password' : password
    }

    status_url = f"https://qualysapi.qg3.apps.qualys.com/qps/rest/3.0/status/was/report/{id}"
    
    status_response = qualys_get_call(status_url, header)
    
    while status_response.get('ServiceResponse',{}).get('data',[{}])[0].get('Report', {}).get('status',None) != "COMPLETE":
        if status_response.get('ServiceResponse',{}).get('data',[{}])[0].get('Report', {}).get('status',None) == 'ERROR':
            print("Oops, it looks like the report has errored. Aborting the process.")
            return None
        else:
            time.sleep(30)
            status_response = qualys_get_call(status_url, header)
    
    download_url = f"https://qualysapi.qg3.apps.qualys.com/qps/rest/3.0/download/was/report/{id}"

    download_response = qualys_report_download(download_url, header)
    # print(download_response)
    return download_response
    

def tag_dict_v2():

    try:
        header = {
            'Content-Type' : "application/json",
            'accept' : "application/json",
            'user' : username,
            'password' : password
            }
        
        url = "https://qualysapi.qg3.apps.qualys.com/qps/rest/2.0/search/am/tag"

        payload = {
            "ServiceRequest": {
                "preferences": {
                "limitResults": 1000
                },
                "filters": {
                "Criteria": {
                    "field": "name",
                    "operator": "EQUALS",
                    "value": "WAS_CUSTOMERS"
                }
                }
            }
        }
        tag_description_dict = {}
        tag_response = qualys_post_call(url,header,payload)

        for tag in tag_response.get("ServiceResponse",{}).get("data",[{"Tag":{}}])[0].get("Tag",{}).get("children",{}).get("list",[]):
            
            
            tag_description_dict[tag.get("TagSimple",{})['name']] = str(tag.get("TagSimple",{})['name'])
        
        return tag_description_dict

    except Exception as e:
        print(e)
        print("Failed to retrieve tag dict")
        return None
    
def app_find(name):

    try:
        header = {
            'Content-Type' : "application/json",
            'accept' : "application/json",
            'user' : username,
            'password' : password
            }
        
        url = "https://qualysapi.qg3.apps.qualys.com/qps/rest/2.0/search/am/tag"

        payload = {
            "ServiceRequest": {
                "preferences": {
                "limitResults": 1000
                },
                "filters": {
                "Criteria": {
                    "field": "name",
                    "operator": "EQUALS",
                    "value": name
                }
                }
            }
        }
        tag_description_dict = {}
        tag_response = qualys_post_call(url,header,payload)

        for tag in tag_response.get("ServiceResponse",{}).get("data",[{"Tag":{}}])[0].get("Tag",{}).get("children",{}).get("list",[]):
            tag_description_dict[tag.get("TagSimple",{})['name']] = str(tag.get("TagSimple",{})['name'])
        
        return tag_description_dict

    except Exception as e:
        print(e)
        print("Failed to retrieve tag dict")
        return None

def max_age(tag):

    try:
        header = {
            'Content-Type' : "application/json",
            'accept' : "application/json",
            'user' : username,
            'password' : password
            }
        
        url = "https://qualysapi.qg3.apps.qualys.com/qps/rest/3.0/search/was/finding"

        critical_payload = {
            "ServiceRequest": {
                "preferences": {
                "limitResults": 1
                },
                "filters": {
                "Criteria": [
                    {
                        "field": "webApp.tags.name",
                        "operator": "EQUALS",
                        "value": tag
                    },
                    {
                        "field": "status",
                        "operator": "IN",
                        "value": "ACTIVE, NEW, REOPENED"
                    },
                    {
                        "field": "severity",
                        "operator": "EQUALS",
                        "value": "4"
                    },
                    {
                        "field": "ignoredReason",
                        "operator": "NOT EQUALS",
                        "value": "FALSE_POSITIVE"
                    }
                ]
                }
            }
        }

        urgent_payload = {
            "ServiceRequest": {
                "preferences": {
                "limitResults": 1
                },
                "filters": {
                "Criteria": [
                    {
                        "field": "webApp.tags.name",
                        "operator": "EQUALS",
                        "value": tag
                    },
                    {
                        "field": "status",
                        "operator": "IN",
                        "value": "ACTIVE, NEW, REOPENED"
                    },
                    {
                        "field": "severity",
                        "operator": "EQUALS",
                        "value": "5"
                    },
                    {
                        "field": "ignoredReason",
                        "operator": "NOT EQUALS",
                        "value": "FALSE_POSITIVE"
                    }
                ]
                }
            }
        }
        
        critical_response = qualys_post_call(url,header,critical_payload)
        urgent_response = qualys_post_call(url,header,urgent_payload)

        critical_date = critical_response.get('ServiceResponse',{}).get('data',[{}])[0].get('Finding',{}).get('firstDetectedDate', None)
        urgent_date = urgent_response.get('ServiceResponse',{}).get('data',[{}])[0].get('Finding',{}).get('firstDetectedDate', None)

        if critical_date:
            critical_diff = pd.Timestamp.now().tz_localize('UTC') - pd.to_datetime(critical_date).tz_convert('UTC')
            critical_diff = critical_diff.days
        else:
            critical_diff = '0'

        if urgent_date:
            urgent_diff = pd.Timestamp.now().tz_localize('UTC') - pd.to_datetime(urgent_date).tz_convert('UTC')
            urgent_diff = str(urgent_diff.days)
        else:
            urgent_diff = '0'

        return critical_diff, urgent_diff
    except Exception as e:
        print(e)
        print("Failed to retrieve tag dict")
        return None

def get_summary_info(report):
    root = objectify.fromstring(report.encode())

    data = {}

    try:
        scan_start = str(root.HEADER.GENERATION_DATETIME)
    except AttributeError:
        print("There was an error. Here is the XML:\n")
        print(report)
        sys.exit()

    

    date_obj = datetime.strptime(str(scan_start[:11]), "%d %b %Y")

    # Format the datetime object to ISO 8601 format
    data['date_pulled'] = date_obj.strftime("%Y-%m-%dT%H:%M:%SZ")

    data['security_risk'] = str(root.SUMMARY.GLOBAL_SUMMARY.SECURITY_RISK)
    data['total_info'] = str(root.SUMMARY.GLOBAL_SUMMARY.INFORMATION_GATHERED)
    data['num_apps'] = str(root.SUMMARY.GLOBAL_SUMMARY.WEB_APPLICATIONS)
    name = str(root.HEADER.NAME)

    if data['security_risk'] == 'High':
        data['risk_color'] = 'CB0000'
    if data['security_risk'] == 'Medium':
        data['risk_color'] = 'FFC702'
    if data['security_risk'] == 'Low':
        data['risk_color'] = '32CB00'
    data['sensitive_count'] = str(root.SUMMARY.GLOBAL_SUMMARY.SENSITIVE_CONTENT)
    if data['sensitive_count'] == '0':
        data['sensitive_color'] = '5e9732'
    else:
        data['sensitive_color'] = 'c41230'
        
    data['max_days_open_urgent'], data['max_days_open_critical'] = max_age(name)
    if data['max_days_open_urgent'] == '0':
        data['urgent_color'] = '5e9732'
    else: data['urgent_color'] = 'c41230'
    if data['max_days_open_critical'] == '0':
        data['critical_color'] = '5e9732'
    else: data['critical_color'] = 'c41230'

    print("Done getting info.")
    return data

def webapp_vuln_table(report_xml):

    root = objectify.fromstring(report_xml.encode())

    webapp_vuln_dict = {}

    total_1 = 0
    total_2 = 0
    total_3 = 0
    total_4 = 0
    total_5 = 0
    overall_total = 0

    for webapp in root.SUMMARY.SUMMARY_STATS.SUMMARY_STAT:

        lvl5 = webapp.LEVEL5
        total_5 += lvl5
        lvl4 = webapp.LEVEL4
        total_4 += lvl4
        lvl3 = webapp.LEVEL3
        total_3 += lvl3
        lvl2 = webapp.LEVEL2
        total_2 += lvl2
        lvl1 = webapp.LEVEL1
        total_1 += lvl1
        tot_vulns = lvl1+lvl2+lvl3+lvl4+lvl5

        webapp_vuln_dict[str(webapp.WEB_APPLICATION)] = [int(lvl1),int(lvl2),int(lvl3),int(lvl4),int(lvl5),int(tot_vulns)]
        overall_total += tot_vulns

    return webapp_vuln_dict

def get_ssn_and_cc(tag):
    try:
        header = {
            'Content-Type' : "application/json",
            'accept' : "application/json",
            'user' : username,
            'password' : password
            }
        
        url = "https://qualysapi.qg3.apps.qualys.com/qps/rest/3.0/search/was/finding"

        ssn_payload = {
            "ServiceRequest": {
                "preferences": {
                "limitResults": 1000,
                "verbose":True
                },
                "filters": {
                "Criteria": [
                    {
                        "field": "webApp.tags.name",
                        "operator": "EQUALS",
                        "value": tag
                    },
                    {
                        "field": "status",
                        "operator": "NOT EQUALS",
                        "value": "FIXED"
                    },
                    {
                        "field": "qid",
                        "operator": "EQUALS",
                        "value": "150034"
                    },
                    {
                        "field": "ignoredReason",
                        "operator": "NOT EQUALS",
                        "value": "FALSE_POSITIVE"
                    }
                ]
                }
            }
        }

        cc_payload = {
            "ServiceRequest": {
                "preferences": {
                "limitResults": 1000,
                "verbose": True
                },
                "filters": {
                "Criteria": [
                    {
                        "field": "webApp.tags.name",
                        "operator": "EQUALS",
                        "value": tag
                    },
                    {
                        "field": "status",
                        "operator": "NOT EQUALS",
                        "value": "FIXED"
                    },
                    {
                        "field": "qid",
                        "operator": "EQUALS",
                        "value": "150033"
                    },
                    {
                        "field": "ignoredReason",
                        "operator": "NOT EQUALS",
                        "value": "FALSE_POSITIVE"
                    }
                ]
                }
            }
        }
        
        cc_response = qualys_post_call(url,header,cc_payload)
        ssn_response = qualys_post_call(url,header,ssn_payload)


        ssn_data = []
        ssn_links = []
        cc_data = []
        cc_links = []
        # print(cc_response)
        if cc_response.get('ServiceResponse',{}).get('data',None):
            for finding in cc_response.get('ServiceResponse',{}).get('data',[]):
                cc_list = str(finding.get('Finding',{}).get('resultList',{}).get('list',[{}])[0].get('Result',{}).get('payloads',{}).get('list',[{}])[0].get('PayloadInstance',{}).get('response',None))
                cc_link = str(finding.get('Finding',{}).get('resultList',{}).get('list',[{}])[0].get('Result',{}).get('payloads',{}).get('list',[{}])[0].get('PayloadInstance',{}).get('request',{}).get('link',None))
                cc_links.append(cc_link)
                cc_data.append(cc_list)
        print(ssn_response)

        if ssn_response.get('ServiceResponse',{}).get('data',None):
            for finding in ssn_response.get('ServiceResponse',{}).get('data',[]):
                ssn_list = str(finding.get('Finding',{}).get('resultList',{}).get('list',[{}])[0].get('Result',{}).get('payloads',{}).get('list',[{}])[0].get('PayloadInstance',{}).get('response',None))
                ssn_link = str(finding.get('Finding',{}).get('resultList',{}).get('list',[{}])[0].get('Result',{}).get('payloads',{}).get('list',[{}])[0].get('PayloadInstance',{}).get('request',{}).get('link',None))
                ssn_links.append(ssn_link)
                ssn_data.append(ssn_list)

        return {
            "SSN_URLs": ssn_links,
            "SSN_FOUND": ssn_data,
            "CC_URL": cc_links,
            "CREDIT_CARDS_FOUND": cc_data
        }


    except Exception as e:
        print(e)
        print("Failed to retrieve tag dict")
        return None

def app_overview_table(report_xml):
    root = objectify.fromstring(report_xml.encode())
    appendix = root.APPENDIX
    webapp_table_dict = {}

    for webapp in appendix.WEB_APPLICATION:

        name = str(webapp.NAME)
        url = str(webapp.URL)
        try:
            os = str(webapp.OPERATING_SYSTEM)
        except AttributeError:
            os = "N/A"
        scope = str(webapp.SCOPE)
        webapp_table_dict[name] = [url,scope,os]

    return webapp_table_dict

def return_links(report):
    root = objectify.fromstring(report.encode())
    
    links_data = []  # List to hold dictionaries
    
    for webapp in root.RESULTS.WEB_APPLICATION:
        app_name = webapp.NAME
        app_info = {'web_application': app_name, 'links': []}
        
        for info in webapp.INFORMATION_GATHERED_LIST.INFORMATION_GATHERED:
            if info.QID == 150009:
                data = str(info.DATA)
                linklist = base64.b64decode(data).splitlines()
                links = [x.decode('utf-8') for x in linklist]
                app_info['links'].extend(links)
        
        links_data.append(app_info)
    
    return links_data

def return_rejects(report):
    root = objectify.fromstring(report.encode())
    
    rejects_data = []  # List to hold dictionaries
    
    for webapp in root.RESULTS.WEB_APPLICATION:
        app_name = webapp.NAME
        app_rejects = {'web_application': app_name, 'rejected_links': []}
        
        for info in webapp.INFORMATION_GATHERED_LIST.INFORMATION_GATHERED:
            if info.QID == 150041:
                data = str(info.DATA)
                linklist = base64.b64decode(data).splitlines()
                rejected_links = [x.decode('utf-8') for x in linklist]
                app_rejects['rejected_links'].extend(rejected_links)
        
        rejects_data.append(app_rejects)
    
    return rejects_data

def convert_element_to_str(obj):
    if isinstance(obj, objectify.StringElement):
        return str(obj)
    elif isinstance(obj, dict):
        return {key: convert_element_to_str(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_element_to_str(item) for item in obj]
    elif isinstance(obj, tuple):
        return tuple(convert_element_to_str(item) for item in obj)
    else:
        return obj

def return_emails(report):
    root = objectify.fromstring(report.encode())
    
    emails_data = []  # List to hold dictionaries
    
    for webapp in root.RESULTS.WEB_APPLICATION:
        app_name = webapp.NAME
        app_emails = {'web_application': app_name, 'emails': []}
        
        for info in webapp.INFORMATION_GATHERED_LIST.INFORMATION_GATHERED:
            if info.QID == 150054:
                data = str(info.DATA)
                email_list = base64.b64decode(data).splitlines()
                emails = [x.decode('utf-8') for x in email_list]
                app_emails['emails'].extend(emails)
        
        emails_data.append(app_emails)
    
    return emails_data

def qid_counter(report):
    """Performs calculations for different statistical counts based on the found QID."""

    print("...Calculating QID stats...")
    root = ET.fromstring(report)
    qid_count_dict = defaultdict(lambda:0)
    fixed_monthly_dict = defaultdict(lambda:0)
    vulns_monthly_dict = defaultdict(lambda:0)
    for month in range(12):
        keydate = datetime.now() - relativedelta(months=month)
        key = keydate.strftime("%B %Y")
        fixed_monthly_dict[key] = 0
        vulns_monthly_dict[key] = 0
    fixed = 0
    total = 0
    new = 0
    reopened = 0
    active = 0
    for webapp in root.findall("RESULTS/WEB_APPLICATION"):
        vuln_list = webapp.find("./VULNERABILITY_LIST")
        
        for vuln in vuln_list.findall("VULNERABILITY"):
            if vuln.find('STATUS').text == 'FIXED':
                fixed += 1
                for month in range(12):
                    keydate = datetime.now() - relativedelta(months=month)
                    if datetime.strptime(vuln.find('LAST_TIME_DETECTED').text, '%d %b %Y %I:%M%p %Z') <= keydate:
                        key = keydate.strftime("%B %Y")
                        fixed_monthly_dict[key] += 1
            else:
                if vuln.find('STATUS').text == 'NEW':
                    new += 1
                if vuln.find('STATUS').text == 'REOPENED':
                    reopened += 1
                if vuln.find('STATUS').text == 'ACTIVE':
                    active += 1
                total += 1
                for month in range(12):
                    keydate = datetime.now() - relativedelta(months=month)
                    if datetime.strptime(vuln.find('FIRST_TIME_DETECTED').text, '%d %b %Y %I:%M%p %Z') <= keydate:
                        key = keydate.strftime("%B %Y")
                        vulns_monthly_dict[key] += 1
                qid_count_dict[vuln.find("QID").text] +=1
    qid_group_dict = {}
    qid_owasp_dict = {}
    group_count_dict = defaultdict(lambda:0)
    owasp_count_dict = defaultdict(lambda:0)
    qid_list = root.findall("./GLOSSARY/QID_LIST/QID")
    for entry in qid_count_dict:
        for qid in qid_list:
            if entry == qid.find("QID").text:
                # if hasattr(qid, "GROUP"):
                #     qid_group_dict[entry] = qid.find("GROUP").text
                # else:
                #     qid_group_dict[entry] = ""
                try:
                    qid_group_dict[entry] = qid.find("GROUP").text
                except AttributeError:
                    qid_group_dict[entry] = ""
                try:
                    qid_owasp_dict[entry] = qid.find("OWASP").text
                except AttributeError:
                    # print("No OWASP for QID "+entry)
                    qid_owasp_dict[entry] = 'None'

    for qid in qid_count_dict:
        if qid_group_dict[qid] == "PATH":
            group_count_dict["Path Disclosure"] += qid_count_dict[qid]
        if qid_group_dict[qid] == "INFO":
            group_count_dict["Information Disclosure"] += qid_count_dict[qid]
        if qid_group_dict[qid] == "XSS":
            group_count_dict["Cross-Site Scripting"] += qid_count_dict[qid]
        if qid_group_dict[qid] == "BURP":
            group_count_dict["Burp"] += qid_count_dict[qid]
        if qid_group_dict[qid] == "SQL":
            group_count_dict["SQL Injection"] += qid_count_dict[qid]
        if qid_group_dict[qid] == "BUGCROWD":
            group_count_dict["Bugcrowd"] += qid_count_dict[qid]

    for qid in qid_count_dict:
        if qid_owasp_dict[qid] == 'A1':
            owasp_count_dict['Injection'] += qid_count_dict[qid]
        if qid_owasp_dict[qid] == 'A2':
            owasp_count_dict['Broken Authentication'] += qid_count_dict[qid]
        if qid_owasp_dict[qid] == 'A3':
            owasp_count_dict['Sensitive Data Exposure'] += qid_count_dict[qid]
        if qid_owasp_dict[qid] == 'A4':
            owasp_count_dict['XML External Entities (XXE)'] += qid_count_dict[qid]
        if qid_owasp_dict[qid] == 'A5':
            owasp_count_dict['Broken Access Control'] += qid_count_dict[qid]
        if qid_owasp_dict[qid] == 'A6':
            owasp_count_dict['Security Misconfiguration'] += qid_count_dict[qid]
        if qid_owasp_dict[qid] == 'A7':
            owasp_count_dict['Cross-Site Scripting (XSS)'] += qid_count_dict[qid]
        if qid_owasp_dict[qid] == 'A8':
            owasp_count_dict['Insecure Deserialization'] += qid_count_dict[qid]
        if qid_owasp_dict[qid] == 'A9':
            owasp_count_dict['Components with Known Vulnerabilities'] += qid_count_dict[qid]
        if qid_owasp_dict[qid] == 'A10':
            owasp_count_dict['Insufficient Logging & Monitoring'] += qid_count_dict[qid]

    print("...Done.")
    return group_count_dict, owasp_count_dict, fixed_monthly_dict, vulns_monthly_dict, fixed, total+fixed, new, reopened, active

def info_dict_gen(report):
    root = objectify.fromstring(report.encode())

    info_dict = {}
    for webapp in root.SUMMARY.SUMMARY_STATS.SUMMARY_STAT:
        info_dict[webapp.WEB_APPLICATION] = webapp.INFORMATION_GATHERED
    return info_dict

def totalgraphgen(report):
    """Generates the image for the graph for total vulnerabilities."""

    root = ET.fromstring(report)

    tot1 = 0
    tot2 = 0
    tot3 = 0
    tot4 = 0
    tot5 = 0

    for webapp in root.findall("./SUMMARY/SUMMARY_STATS/SUMMARY_STAT"):
        Lvl1 = int(webapp.find("./LEVEL1").text)
        tot1 += Lvl1
        Lvl2 = int(webapp.find("./LEVEL2").text)
        tot2 += Lvl2
        Lvl3 = int(webapp.find("./LEVEL3").text)
        tot3 += Lvl3
        Lvl4 = int(webapp.find("./LEVEL4").text)
        tot4 += Lvl4
        Lvl5 = int(webapp.find("./LEVEL5").text)
        tot5 += Lvl5

    return str(tot1),str(tot2),str(tot3),str(tot4),str(tot5)

class Qid:
    def __init__(self,severity,title,group,description,impact,solution,cvss,cve,cwe):
        self.severity = severity
        self.title = title
        self.group = group
        self.description = description
        self.impact = impact
        self.solution = solution
        self.cvss = cvss
        self.cve = cve
        self.cwe =cwe

def remove_html_tags(text):
    """Remove html tags from a string"""
    clean = re.compile('<.*?>')
    return re.sub(clean, '', text)

def get_qid_stats(xml_data):
    root = objectify.fromstring(xml_data.encode())
    entry_dict = {}
    if hasattr(root.GLOSSARY.QID_LIST,"QID"):
        for entry in root.GLOSSARY.QID_LIST.QID:
            qid = entry.QID
            severity = str(entry.SEVERITY)
            title = str(entry.TITLE)
            if hasattr(entry, "GROUP"):
                group = str(entry.GROUP)
            else:
                print("Warning: No group found for qid.  Set group to empty string")
                group = ""
            description = re.sub('\n','',remove_html_tags(str(entry.DESCRIPTION)))
            impact = re.sub('\n','',remove_html_tags(str(entry.IMPACT)))
            solution = re.sub('\n','',remove_html_tags(str(entry.SOLUTION)))
            try:
                cvss = str(entry.CVSS_BASE)
            except AttributeError:
                cvss = "None"
            try:
                cve = str(entry.CVE)
            except AttributeError:
                cve = "None"
            try:
                cwe = str(entry.CWE)
            except AttributeError:
                cwe = "None"
            entry_dict[qid] = Qid(severity,title,group,description,impact,solution,cvss,cve,cwe)
        return entry_dict
    else:
        print("No QID Glossary found. Check if Customer has findings.")
        return None

def format_request(request):
    headers = request.HEADERS.HEADER    
    headers_str = ''.join([f'{header.key}: {header.value}\n' for header in headers])
    body = request.BODY if request.BODY else ''
    return f'{request.METHOD} {request.URL}\n{headers_str}\n{body}'

class Vulnerability:
    def __init__(self,data):
        self.id = data.ID
        self.uid = data.UNIQUE_ID
        self.qid = data.QID
        self.url = data.URL
        self.first_detect = data.FIRST_TIME_DETECTED
        self.last_detect = data.LAST_TIME_DETECTED
        self.last_test = data.LAST_TIME_TESTED
        self.potential = data.POTENTIAL
        self.status = data.STATUS
        try:
            self.response = data.PAYLOADS.PAYLOAD.RESPONSE.CONTENTS
        except AttributeError:
            # self.response = base64.b64encode("N/A".encode('ascii'))
            self.response = "Ti9B"
        try:
            self.request = format_request(data["PAYLOADS"]["PAYLOAD"]["REQUEST"])
        except AttributeError:
            if hasattr(data,'PAYLOADS.PAYLOAD'):
                self.request = data.PAYLOADS.PAYLOAD.PAYLOAD
            else:
                 self.request = 'n/a'
                 
class InfoGathered:
    def __init__(self,data):
        self.id = data.ID
        self.qid = data.QID
        self.last_detect = data.LAST_TIME_DETECTED

class WebApp:
    def __init__(self,data):
        self.id = data.ID
        self.name = data.NAME
        self.vuln_list = data.VULNERABILITY_LIST
        self.info_list = data.INFORMATION_GATHERED_LIST

def unspace(string):
    string = string.replace(" ","-")
    return string

def respace(string):
    string = string.replace("-"," ")
    return string

def decomma(in_string):
    in_string = re.sub(',','',in_string)

    return in_string

def quote_field(field):
    field = str(field)
    if ',' in field or '"' in field:
        field = field.replace('"', '""')
        return f'"{field}"'
    return field

def csv_dict_generator(report_xml):
    root = objectify.fromstring(report_xml.encode())
    qid_dict = get_qid_stats(report_xml)
    if not qid_dict:
        return None
    info_list = []
    webapp_list = []
    csv_vuln_list= []
    severity_list = []
    age_list = []
    for webapp in root.RESULTS.WEB_APPLICATION:
        webapp_list.append(WebApp(webapp))
    for app in webapp_list:
        web_application = app.name
        for info in app.info_list.getchildren():
            temp = InfoGathered(info)
            qid = temp.qid
            info_list.append(
                {
                    'INFO_ID': str(temp.id),
                    'QID': str(temp.qid),
                    'URL': decomma(str(web_application)),
                    'LAST_DETECTION': temp.last_detect,
                    'SEVERITY': qid_dict[qid].severity,
                    'NAME': decomma(qid_dict[qid].title),
                    'DESCRIPTION': decomma(qid_dict[qid].description),
                    'IMPACT': decomma(qid_dict[qid].impact),
                    'SOLUTION': decomma(qid_dict[qid].solution),
                }
            )

        for vuln in app.vuln_list.getchildren():
            temp = Vulnerability(vuln)
            if temp.status != 'FIXED':
                date_time_obj = datetime.strptime(str(temp.first_detect), '%d %b %Y %I:%M%p %Z')
                age = (pd.Timestamp.now(tz='UTC') - pd.Timestamp(date_time_obj, tz='UTC')).days
                severity = qid_dict[temp.qid].severity
                severity_list.append(severity)
                age_list.append(age)

                qid = temp.qid
                csv_vuln_list.append( {
                    "VULN_ID": str(temp.id),
                    "NAME": decomma(qid_dict[qid].title),
                    "QID": str(qid),
                    "SEVERITY": qid_dict[qid].severity,
                    "BASE_CVSS": qid_dict[qid].cvss,
                    "CWE": decomma(qid_dict[qid].cwe),
                    "CVE": decomma(qid_dict[qid].cve),
                    "FIRST_DETECTION": str(temp.first_detect),
                    "LAST_DETECTION": str(temp.last_detect),
                    "GROUP": qid_dict[qid].group,
                    "WEB_APPLICATION": str(web_application),
                    "URL": decomma(str(temp.url)),
                    "PAYLOAD_REQUEST": quote_field(temp.request),
                    "PAYLOAD_RESPONSE": decomma(str(base64.b64decode(str(temp.response)))),
                    "DESCRIPTION": decomma(qid_dict[qid].description),
                    "IMPACT": decomma(qid_dict[qid].impact),
                    "SOLUTION": decomma(qid_dict[qid].solution),
                    "VULN_TYPE": "Potential" if temp.potential else "Confirmed"
                })
    return csv_vuln_list, info_list, severity_list, age_list

def calculate_details_report(org, tag_info):
    try:
        header = {
            'Content-Type' : "application/json",
            'accept' : "application/json",
            'user' : username,
            'password' : password
            }
        
        url = "https://qualysapi.qg3.apps.qualys.com/qps/rest/3.0/create/was/report"

        payload = {
            "ServiceRequest": {
                "data":{
                    "Report":{
                        "name":f"<![CDATA[{tag_info['name']}]]>",
                        "format":"PDF",
                        "type":"WAS_WEBAPP_REPORT",
                        "template":{
                            "id":"1488462"
                        },
                        "config":{
                            "webAppReport":{
                                "target":{
                                    "tags":{
                                        "included":{
                                            "option":"ALL",
                                            "tagList":{
                                                "Tag":{
                                                    "id":tag_info['id']
                                                }}}}}}}}}}}
        
        report = qualys_post_call(url,header,payload,False)
        
        if report.get("ServiceResponse",{}).get("responseCode", None) == "SUCCESS":
            return report.get("ServiceResponse",{}).get("data",[{}])[0].get("Report",{}).get('id',None)
        else:
            print(f"Got the INVALID_REQUEST response. skipping {org}")
            return None
        
    except Exception as e:
        print(e)
        print("Failed to create details report")
        return None

def is_serializable(obj) -> bool:
    """Check if an object is JSON serializable."""
    try:
        json.dumps(obj)
        return True
    except (TypeError, OverflowError):
        return False

def find_non_serializable(data, parent_key: str = ''):
    """Recursively find and collect non-serializable data."""
    non_serializable = {}
    
    for key, value in data.items():
        full_key = f"{parent_key}.{key}" if parent_key else key
        if isinstance(value, dict):
            # Recursively check nested dictionaries
            nested_non_serializable = find_non_serializable(value, full_key)
            if nested_non_serializable:
                non_serializable.update(nested_non_serializable)
        elif isinstance(value, list):
            # Check list elements
            for index, item in enumerate(value):
                item_key = f"{full_key}[{index}]"
                if not is_serializable(item):
                    non_serializable[item_key] = type(item).__name__
        else:
            # Check individual value
            if not is_serializable(value):
                non_serializable[full_key] = type(value).__name__
    
    return non_serializable

def test_json_serialization(data):
    """Test each key-value pair in a dictionary for JSON serialization and return a list of keys that fail."""
    failed_keys = []
    
    for key, value in data.items():
        try:
            # Try to serialize the key-value pair to JSON
            json.dumps({key: value})
        except (TypeError, OverflowError) as e:
            # If serialization fails, add the key to the failed_keys list
            failed_keys.append(key)
            print(f"Failed to serialize key: {key} - Error: {e}")
    
    return failed_keys

def save_report_to_db(report_dict):

    converted_dict = convert_element_to_str(report_dict)
    # converted_dict['pdf_obj'] = pdf_to_base64(converted_dict['pdf_obj'])
    # non_serializable_data = find_non_serializable(converted_dict)
    # print("Non-serializable data found:")
    # for path, type_name in non_serializable_data.items():
    #     print(f"{path}: {type_name}")
    
    # print(test_json_serialization(converted_dict))
    # print(converted_dict['info_csv'][0])
    # non_serializable_data = find_non_serializable(converted_dict['details_csv'][0])
    # print("Non-serializable data found:")
    # for path, type_name in non_serializable_data.items():
    #     print(f"{path}: {type_name}")
    # exit()

    api_was_report_insert(converted_dict)
    
    pass

def pdf_to_base64(pdf_io: BytesIO) -> str:
    """Convert a BytesIO PDF object to a Base64-encoded string."""
    if pdf_io:
        pdf_io.seek(0)  # Ensure we're at the start of the BytesIO object
        pdf_data = pdf_io.read()
        base64_pdf = base64.b64encode(pdf_data).decode('utf-8')
        return base64_pdf
    else:
        return None

def get_recently_completed_scans(days_back=2):
    header = {
        'Content-Type' : "application/json",
        'accept' : "application/json",
        'user' : username,
        'password' : password
    }

    status_url = "https://qualysapi.qg3.apps.qualys.com/qps/rest/3.0/search/was/wasscanschedule"
    
    now = datetime.now(timezone.utc)

    # Calculate the date for two days ago
    two_days_ago = now - timedelta(days=days_back)

    # Set the time to the start of the day (00:00:00) and make sure it's in UTC
    start_of_day_two_days_ago = two_days_ago.replace(hour=0, minute=0, second=0, microsecond=0)

    # Format the date as a string in ISO 8601 format with Z for UTC
    date_string = start_of_day_two_days_ago.strftime('%Y-%m-%dT%H:%M:%SZ')

    payload = {
            "ServiceRequest": {
                "preferences": {
                "limitResults": 1000
                },
                "filters": {
                "Criteria": [
                    {
                        "field": "lastScan.status",
                        "operator": "EQUALS",
                        "value": "FINISHED"
                    },
                    {
                        "field": "lastScan.launchedDate",
                        "operator": "GREATER",
                        "value": date_string
                    }
                ]
                }
            }
        }
    id_scan_date_dict = {}
    status_response = qualys_post_call(status_url, header, payload)
    has_more_records = True
    while has_more_records is True:
        for scan in status_response.get('ServiceResponse',{}).get('data',[]):
            id_scan_date_dict[scan.get('WasScanSchedule',{}).get('target',{}).get('tags',{}).get('included',{}).get('tagList',{}).get('list',[{}])[0].get('Tag',{}).get('name',None)] = scan.get('WasScanSchedule',{}).get('lastScan',{}).get('launchedDate',None)

        has_more_records = True if status_response.get('ServiceResponse',{}).get("hasMoreRecords",False) == "true" else False

        if has_more_records == True:
            payload['ServiceRequest']['filters']["Criteria"].append({
                "field": "id",
                "operator": "GREATER",
                "value": status_response.get('ServiceResponse',{}).get("lastId")
            })

            status_response = qualys_post_call(status_url, header, payload)

    return id_scan_date_dict

def generate_full_report(tag_info, app_cnt, report_xml, vuln_csv_dict, info_csv_dict, severities, ages, pdf_obj, org_scan_dict):
    report_dict = {}
    report_dict['last_scan_date'] = org_scan_dict[tag_info['name']]
    # tag_description_dict = tag_dict_v2()
    if "description" not in tag_info or not tag_info['description']:
        report_dict['org_name'] = tag_info['name']
    else:
        report_dict['org_name'] = tag_info['description']

    summary_dict = get_summary_info(report_xml)

    report_dict |= summary_dict
    acronym = tag_info['name']
    report_dict['org_was_acronym'] = acronym
    num = len(report_dict['org_name'])
    if num >= 55:
        report_dict['name_len'] = '18cm'
    elif num >= 45:
        report_dict['name_len'] = '16cm'
    elif num >= 40:
        report_dict['name_len'] = '13cm'
    elif num >= 35:
        report_dict['name_len'] = '12cm'
    elif num >= 25:
        report_dict['name_len'] = '10cm'
    elif num >= 14:
        report_dict['name_len'] = '8.5cm'
    else:
        report_dict['name_len'] = '6cm'
    # print(report_dict)

    report_dict['vuln_csv_dict'] = webapp_vuln_table(report_xml) # was webapp_vuln_csv
    
    report_dict['ssn_cc_dict'] = get_ssn_and_cc(tag_info['name']) or {}

    report_dict['app_overview_csv_dict'] = app_overview_table(report_xml)

    # report_dict['details_csv'] = vuln_csv_dict
    
    report_dict['info_csv'] = info_csv_dict
    report_dict['links_crawled'] = return_links(report_xml)
    report_dict['links_rejected'] = return_rejects(report_xml)
    report_dict['emails_found'] = return_emails(report_xml)

    group_count_dict,owasp_count_dict,fixed_monthly_dict,vulns_monthly_dict,fixed,total,new,reopened,active = qid_counter(report_xml)

    report_dict['owasp_count_dict'] = dict(owasp_count_dict)
    report_dict['group_count_dict'] = dict(group_count_dict)
    report_dict['fixed'] = fixed
    report_dict['total'] = total
    report_dict['vulns_monthly_dict'] = dict(vulns_monthly_dict)

    report_dict['path_disc'] = str(group_count_dict["Path Disclosure"])
    report_dict['info_disc'] = str(group_count_dict["Information Disclosure"])
    report_dict['cross_site'] = str(group_count_dict["Cross-Site Scripting"])
    report_dict['burp'] = str(group_count_dict["Burp"])
    report_dict['sql_inj'] = str(group_count_dict["SQL Injection"])
    report_dict['bugcrowd'] = str(group_count_dict["Bugcrowd"])
    report_dict['reopened'] = str(reopened)

    if report_dict['reopened'] == '0':
        report_dict['reopened_color'] = '5e9732'
    else:
        report_dict['reopened_color'] = 'c41230'
    report_dict['new_vulns'] = str(new)
    if report_dict['new_vulns'] == '0':
        report_dict['new_vulns_color'] = '5e9732'
    else:
        report_dict['new_vulns_color'] = 'c41230'
    report_dict['tot_vulns'] = str(active)
    if report_dict['tot_vulns'] == '0':
        report_dict['tot_vulns_color'] = '5e9732'
    else:
        report_dict['tot_vulns_color'] = 'c41230'

    info_dict = info_dict_gen(report_xml)
    
    report_dict['lev1'], report_dict['lev2'], report_dict['lev3'], report_dict['lev4'], report_dict['lev5'] = totalgraphgen(report_xml) #this generates figure1.png
    report_dict['severities'] = severities
    report_dict['ages'] = ages

    if pdf_obj:
        report_dict['pdf_obj'] = pdf_obj
    else:
        report_dict['pdf_obj'] = None

    try:
        save_report_to_db(report_dict)
    except:
        print(f'failed to insert report for {acronym}: Trying again without attachments')
        del report_dict['vuln_csv_dict']
        del report_dict['ssn_cc_dict']
        del report_dict['app_overview_csv_dict']
        del report_dict['info_csv']
        del report_dict['links_crawled'] 
        del report_dict['links_rejected'] 
        del report_dict['emails_found']
        save_report_to_db(report_dict)

def watermarker(input_pdf: BytesIO, watermark_file: str) -> BytesIO:
    # Initialize BytesIO for output
    output_pdf = BytesIO()

    # Read input PDF from BytesIO
    reader_input = PdfReader(input_pdf)
    writer_output = PdfWriter()

    # Read watermark PDF from file path
    
    watermark_input = PdfReader(watermark_file)
    watermark = watermark_input.pages[0]

    # Apply watermark to each page
    for current_page in range(len(reader_input.pages)):
        merger = PageMerge(reader_input.pages[current_page])
        merger.add(watermark).render()
        
    # Write to BytesIO object
    writer_output.trailer = reader_input
    writer_output.write(output_pdf)
    
    output_pdf.seek(0)  # Rewind the BytesIO object to the beginning
    return output_pdf

def unfirstpagify(input_pdf: BytesIO) -> BytesIO:
    # Initialize BytesIO for output
    output_pdf = BytesIO()

    # Read input PDF
    pdf_file = PdfReader(input_pdf)
    writer_output = PdfWriter()

    # Add pages, skipping the first one
    for i in range(1, len(pdf_file.pages)):
        page = pdf_file.getPage(i)
        writer_output.addPage(page)

    # Write to BytesIO object
    writer_output.write(output_pdf)
    output_pdf.seek(0)  # Rewind the BytesIO object to the beginning
    return output_pdf

def download_report(id):
    header = {
        'accept':'application/json',
        'user' : username,
        'password' : password
    }

    status_url = f"https://qualysapi.qg3.apps.qualys.com/qps/rest/3.0/status/was/report/{id}"
    
    status_response = qualys_get_call(status_url, header)
    
    while status_response.get('ServiceResponse',{}).get('data',[{}])[0].get('Report', {}).get('status',None) != "COMPLETE":
        if status_response.get('ServiceResponse',{}).get('data',[{}])[0].get('Report', {}).get('status',None) == 'ERROR':
            print("Oops, it looks like the report has errored. Aborting the process.")
            return None
        else:
            time.sleep(30)
            status_response = qualys_get_call(status_url, header)

    download_url = f"https://qualysapi.qg3.apps.qualys.com/qps/rest/3.0/download/was/report/{id}"

    session = requests.Session()
    session.auth = (username, password)

    response = session.get(download_url)

    if response.status_code != 200:
        print("Failed to download the report. Status code:", response.status_code)
        return None
    
    pdf_data = BytesIO(response.content)
    print(f"Size after download: {len(pdf_data.getvalue())} bytes")
    # Redact
    year = datetime.now().year
    options = RedactorOptions()

    options.input_stream = pdf_data
    options.content_filters = [
    (
        re.compile(r"""CONFIDENTIAL AND PROPRIETARY INFORMATION."""),
        lambda m : ""
    ),
    (
        re.compile(r"""Qualys provides the QualysGuard Service "As Is," without any warranty of any kind. Qualys makes no warranty that the information contained in this report is"""),
        lambda m : ""
    ),
    (
        re.compile(r"""complete or error-free. Copyright """+str(year)+""", Qualys, Inc."""),
        lambda m : ""
    )
]   
    
#     file_path = 'output_pdf_og.pdf'

# # Write the BytesIO object to a file
#     with open(file_path, 'wb') as file:
#         file.write(pdf_data.getvalue())

    pdf_data = redactor(options)
    # print(f"Size after redaction: {len(pdf_data.getvalue())} bytes")

    pdf_data = watermarker(pdf_data, 'cisa_marker_new.pdf')
    # print(f"Size after watermarking: {len(pdf_data.getvalue())} bytes")
    pdf_data = unfirstpagify(pdf_data)
    # print(f"Size after unfirstpagify: {len(pdf_data.getvalue())} bytes")
    # print(pdf_data)
#     file_path = 'output_pdf.pdf'

# # Write the BytesIO object to a file
#     with open(file_path, 'wb') as file:
#         file.write(pdf_data.getvalue())

    return pdf_data

def run_was_report_pull():

    # acronym_list = get_orgs_to_run_on()

    recently_scanned = get_recently_completed_scans(2)

    acronym_list = list(recently_scanned.keys())
    for org in acronym_list:
        print(f"running on {org}")
        app_cnt = app_count(org)

        if app_cnt < 1:
            print("No Web Applications found for tag: %s" % org)
            continue

        tag_info = get_tag(org)
        

        # if app_cnt < 35:
        #     pdf_id = calculate_details_report(org, tag_info)
        #     if pdf_id is None:
        #         pdf_obj = None
        #     else:
        #         pdf_obj = download_report(pdf_id)
                
        # else:
        #     pdf_obj = None
        pdf_obj = None

        report_id = create_webapp_report_v2(org,tag_info)
        
        if report_id is None:
            continue
        report_xml = get_report(report_id)

        vuln_csv_dict, info_csv_dict, severities, ages  = csv_dict_generator(report_xml)
        generate_full_report(tag_info, app_cnt, report_xml, vuln_csv_dict, info_csv_dict, severities, ages, pdf_obj, recently_scanned)
        




if __name__ == '__main__':
    try:
        run_was_report_pull()
    except KeyboardInterrupt:
        print("\nUser has forced a close. Goodbye.")
        sys.exit()