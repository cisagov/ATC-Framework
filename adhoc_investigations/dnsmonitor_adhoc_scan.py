"""Adhoc version of the DNSMonitor scan."""
# Standard Python Libraries
import logging
import socket
import time

# Third-Party Libraries
import dns
import pandas as pd
import requests

# .ini Data
import adhoc_config

# Setup logging
main_log = logging.getLogger(__name__)

# DNSMonitor API info
client_id = adhoc_config.get_ini_data().get("dnsmonitor_id") 
client_secret = adhoc_config.get_ini_data().get("dnsmonitor_secret") 


def dnsmonitor_token():
    """Retreive the DNSMonitor bearer token."""
    scope = "DNSMonitorAPI"
    url = "https://argosecure.com/dhs/connect/token"
    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
        "scope": scope,
    }
    headers = {}
    files = []
    response = requests.request(
        "POST", url, headers=headers, data=payload, files=files
    ).json()
    return response["access_token"]


def get_monitored_domains(token):
    """Get the domains being monitored."""
    # Retrieve list of domains in DNSMonitor and their IDs
    url = "https://dns.argosecure.com/dhs/api/GetDomains"
    payload = {}
    headers = {}
    headers["authorization"] = f"Bearer {token}"
    response = requests.request("GET", url, headers=headers, data=payload)
    # Retry if API fails
    retry_max = 10
    retry_count = 1
    while response.status_code != 200 and retry_count <= retry_max:
        main_log.error(f"DNSMonitor API call failed, code: {response.status_code}")
        main_log.error(f"\tRetrying in 5 sec - retry {retry_count} of {retry_max}")
        time.sleep(5)
        response = requests.get(url, headers=headers, data=payload)
        retry_count += 1
    domain_df = pd.DataFrame(response.json())
    domain_df.rename(columns={"domainName": "domain_name"}, inplace=True)
    # Drop duplicates, for some reason there are domains that are monitored twice?
    domain_df.drop_duplicates("domain_name", inplace=True)

    # CSV file connecting DNSMonitor domains to org names
    # Some domains are attributed to >1 organization
    org_names_df = pd.read_csv("dnsmonitor_monitored_domains.csv")

    # Match up DNSMonitor domains/IDs with org names
    joined_df = pd.merge(domain_df, org_names_df, on="domain_name", how="left")
    return joined_df


def get_domain_alerts(token, domain_ids, start_date, end_date):
    """Get alerts for specified domains."""
    url = "https://dns.argosecure.com/dhs/api/GetAlerts"
    payload = (
        '{\r\n  "domainIds": %s,\r\n  "fromDate": "%s",\r\n  "toDate": "%s",\r\n  "alertType": null,\r\n  "showBufferPeriod": false\r\n}'
        % (domain_ids, start_date, end_date)
    )
    headers = {}
    headers["authorization"] = f"Bearer {token}"
    headers["Content-Type"] = "application/json"
    response = requests.request("GET", url, headers=headers, data=payload)
    # Retry if API fails
    retry_max = 10
    retry_count = 1
    while response.status_code != 200 and retry_count <= retry_max:
        main_log.error(f"DNSMonitor API call failed, code: {response.status_code}")
        main_log.error(f"\tRetrying in 5 sec - retry {retry_count} of {retry_max}")
        time.sleep(5)
        response = requests.get(url, headers=headers, data=payload)
        retry_count += 1
    return pd.DataFrame(response.json())


def get_dns_records(dom_perm):
    """Get DNS records."""
    # NS
    try:
        ns_list = []
        dom_ns = dns.resolver.resolve(dom_perm, "NS")
        for data in dom_ns:
            ns_list.append(str(data.target))
    except Exception:
        ns_list = []
    # MX
    try:
        mx_list = []
        dom_mx = dns.resolver.resolve(dom_perm, "MX")
        for data in dom_mx:
            mx_list.append(str(data.exchange))
    except Exception:
        mx_list = []

    # A
    try:
        ip_address = str(socket.gethostbyname(dom_perm))
        if ":" in ip_address:
            ipv6 = ip_address
            ipv4 = ""
        else:
            ipv4 = ip_address
            ipv6 = ""
    except Exception:
        ipv4 = ""
        ipv6 = ""

    return str(mx_list), str(ns_list), ipv4, ipv6


def check_org_in_dnsmonitor(org_name):
    """Check if organization has any domains currently being monitored by DNSMonitor."""
    token = dnsmonitor_token()
    domain_df = get_monitored_domains(token)
    # Print out any rows that contain the specified org_name
    print("\nSuggestions:")
    print(domain_df.loc[domain_df["org"].str.contains(org_name) == True])
    # Print whether or not the exact org_name is in DNSMonitor
    if org_name in domain_df["org"].values:
        print(f"\n\"{org_name}\" does have records in DNSMonitor\n")
    else:
        print(f"\n\"{org_name}\" does not have records in DNSMonitor\n")


def get_dnsmonitor_data(org_uid, org_abbrv, org_name, start_date, end_date, save_file):
    """Retrieve Shodan data for the specified IPs."""
    main_log.info(f"=== {org_abbrv} DNSMonitor Adhoc Scan Starting ===")
    # Fetch the bearer token
    token = dnsmonitor_token()
    # Get all of the Domains being monitored (sync with csv file)
    main_log.info("Retrieving list of all monitored domains...")
    domain_df = get_monitored_domains(token)
    main_log.info(f"{len(domain_df)} domains being monitored by DNSMonitor")

    # Get monitored domains for the specified org
    monitored_domains = domain_df.loc[domain_df["org"] == org_name]["domainId"].to_list()
    if len(monitored_domains) == 0:
        main_log.info(f"No domains being monitored for: {org_name}")
        main_log.info(f"=== {org_abbrv} DNSMonitor Adhoc Scan Complete ===")
        return 0
    else:
        main_log.info(f"{len(monitored_domains)} domains being monitored for: {org_name}")

    # Retrieve domain alerts for this org's domains
    main_log.info("Retrieving domain alerts for this organization's domains...")
    domain_alerts = get_domain_alerts(token, monitored_domains, start_date, end_date)
    if len(domain_alerts) == 0:
        main_log.info("No domain alerts found for this organization's domains")
        main_log.info(f"=== {org_abbrv} DNSMonitor Adhoc Scan Complete ===")
        return 0
    else:
        main_log.info(f"{len(domain_alerts)} domain alerts found for this organizations's domains")

    # Retrieve DNS record data for each domain alert
    main_log.info("Retrieving DNS info for domain permutations...")
    for alert_idx, alert_row in domain_alerts.iterrows():
        # Get DNS info for this domain permutation
        curr_permu = alert_row["domainPermutation"]
        # print(f"\t({alert_idx+1}/{len(domain_alerts)}) Retrieving DNS info for {curr_permu}")
        mx_list, ns_list, ipv4, ipv6 = get_dns_records(curr_permu)
        # Append DNS info to alert data
        domain_alerts.at[alert_idx, "mail_server"] = mx_list
        domain_alerts.at[alert_idx, "name_server"] = ns_list
        domain_alerts.at[alert_idx, "ipv4"] = ipv4
        domain_alerts.at[alert_idx, "ipv6"] = ipv6
    main_log.info("All DNS info retrieved")

    # Clean up data
    domain_alerts.rename(
        columns={
            "domainId": "domain_id",
            "rootDomain": "root_domain",
            "domainPermutation": "domain_permutation",
            "alertType": "alert_type",
            "message": "alert_message",
            "previousValue": "previous_value", # useful?
            "newValue": "new_value", # useful?
            "dateCreated": "date_created", # interpretation?
        },
        inplace=True
    )
    domain_alerts.sort_values(
        by=[
            "root_domain",
            "date_created",
            "domain_permutation",
            "alert_type",
        ], 
        inplace=True
    )
    domain_alerts.reset_index(drop=True, inplace=True)
    # Save to file
    main_log.info(f"Saving to file: {save_file}")
    domain_alerts.to_csv(save_file)
    main_log.info(f"=== {org_abbrv} DNSMonitor Adhoc Scan Complete ===")
    return 1