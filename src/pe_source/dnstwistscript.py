"""Use DNS twist to fuzz domain names and cross check with a blacklist."""
# Standard Python Libraries
import contextlib
import datetime
import json
import logging
import pathlib
import time
import traceback

# Third-Party Libraries
import dnstwist
import dshield
import pandas as pd
import requests

from .data.pe_db.db_query_source import (
    addSubdomain,
    connect,
    execute_dnstwist_data,
    get_data_source_uid,
    get_orgs,
    getSubdomain,
    org_root_domains,
)

# Save findings as the last day of the report period
# date = (datetime.datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
date = datetime.datetime.now().strftime("%Y-%m-%d")
LOGGER = logging.getLogger(__name__)

def check_local_blocklist(ip):
    """Check the local PE DB blocklist for the specified IP."""
    query = f"SELECT * FROM blocklist WHERE ip = '{ip}'"
    try:
        conn = connect()
        df = pd.read_sql_query(query, conn)
        conn.close()
        if not df.empty:
            print(f"*** Local db blocklist results found for: {ip}")
            # malicious = df["malicious"]
            attacks = df["attacks"][0]
            reports = df["reports"][0]
            # return malicious, attacks, reports
            return attacks, reports
        else:
            # return False, 0, 0 
            print(f"*** No local db blocklist results found for: {ip}")
            return 0, 0
    except Exception as e:
        LOGGER.warning(f"Failed to retrieve local blocklist info for {ip} - {e}")

def check_api_blocklist(ip):
    """Check Blocklist.de's API for the specified IP."""
    blocklist_url = "http://api.blocklist.de/api.php?ip=" + str(ip)
    response = requests.get(blocklist_url)
    # Retry clause
    retry_count, max_retries, time_delay = 1, 10, 5
    while response.status_code != 200 and retry_count <= max_retries:
        LOGGER.warning(f"Retrying Blocklist.de API endpoint (code {response.status_code}), attempt {retry_count} of {max_retries} (url: {blocklist_url})")
        time.sleep(time_delay)
        response = requests.get(blocklist_url)
        retry_count += 1
    response = response.content
    # Parse response
    try:
        if str(response) != "b'attacks: 0<br />reports: 0<br />'":
            attacks = int(str(response).split("attacks: ")[1].split("<")[0])
            reports = int(str(response).split("reports: ")[1].split("<")[0])
            return attacks, reports
        else:
            return 0, 0
    except Exception as e:
        LOGGER.error(f"Error: Failed retrieving blocklist.de info for ip: {ip}")
        return 0, 0

def checkBlocklist(dom, sub_domain_uid, source_uid, pe_org_uid, perm_list):
    """Cross reference the dnstwist results with DShield Blocklist."""
    malicious = False
    ipv4_blocklist_reports = 0
    ipv4_blocklist_attacks = 0
    ipv4_dshield_records = 0
    ipv4_dshield_attacks = 0
    ipv6_blocklist_reports = 0
    ipv6_blocklist_attacks = 0
    ipv6_dshield_records = 0
    ipv6_dshield_attacks = 0

    # Skip if original input domain
    if "original" in dom["fuzzer"]:
        return None, perm_list

    # Check if IPv4 available
    if "dns_a" not in dom:
        # skip if no IPv4 IP
        return None, perm_list
    elif str(dom["dns_a"][0]) == "!ServFail":
        # skip if IPv4 is servfail
        return None, perm_list
    else:
        # If valid IPv4 is available, check against blocklist
        # Check IP in local DB blocklist
        try:
            # ipv4_blocklist_attacks, ipv4_blocklist_reports = check_local_blocklist(str(dom["dns_a"][0])) # local blocklist version
            ipv4_blocklist_attacks, ipv4_blocklist_reports = check_api_blocklist(str(dom["dns_a"][0])) # blocklist.de api version
        except Exception:
            ipv4_blocklist_attacks = 0
            ipv4_blocklist_reports = 0
        # Check IP in DShield API
        try:
            ipv4_dshield_results = dshield.ip(str(dom["dns_a"][0]), return_format=dshield.JSON)
            ipv4_dshield_results = json.loads(ipv4_dshield_results)
            ipv4_dshield_threats = ipv4_dshield_results["ip"]["threatfeeds"]
            ipv4_dshield_attacks = ipv4_dshield_results["ip"]["attacks"]
            ipv4_dshield_attacks = int(0 if ipv4_dshield_attacks is None else ipv4_dshield_attacks)
            ipv4_dshield_records = len(ipv4_dshield_threats)
        except Exception:
            ipv4_dshield_attacks = 0
            ipv4_dshield_records = 0

    # Check if IPv6 available
    if "dns_aaaa" not in dom:
        # If no IPv6 IP, set to blank
        dom["dns_aaaa"] = [""]
    elif str(dom["dns_aaaa"][0]) == "!ServFail":
        # If IPv6 is servfail, set to blank
        dom["dns_aaaa"] = [""]
    else:
        # If valid IPv6 is available, check against blocklist
        # Check IP in local DB blocklist
        try:
            # ipv6_blocklist_attacks, ipv6_blocklist_reports = check_local_blocklist(str(dom["dns_aaaa"][0])) # local blocklist version
            ipv6_blocklist_attacks, ipv6_blocklist_reports = check_api_blocklist(str(dom["dns_aaaa"][0])) # blocklist.de api version
        except Exception:
            ipv6_blocklist_attacks = 0
            ipv6_blocklist_reports = 0
        # Check IP in DSheild API
        try:
            ipv6_dshield_results = dshield.ip(str(dom["dns_aaaa"][0]), return_format=dshield.JSON)
            ipv6_dshield_results = json.loads(ipv6_dshield_results)
            ipv6_dshield_threats = ipv6_dshield_results["ip"]["threatfeeds"]
            ipv6_dshield_attacks = ipv6_dshield_results["ip"]["attacks"]
            ipv6_dshield_attacks = int(0 if ipv6_dshield_attacks is None else ipv6_dshield_attacks)
            ipv6_dshield_records = len(ipv6_dshield_threats)
        except Exception:
            ipv6_dshield_attacks = 0
            ipv6_dshield_records = 0
    
    # Calculate total stats
    total_blocklist_reports = ipv4_blocklist_reports + ipv6_blocklist_reports
    total_blocklist_attacks = ipv4_blocklist_attacks + ipv6_blocklist_attacks
    total_dshield_records = ipv4_dshield_records + ipv6_dshield_records
    total_dshield_attacks = ipv4_dshield_attacks + ipv6_dshield_attacks
    # If any attacks/records/reports are found from either blocklist or dshield, mark as malicious
    if total_blocklist_reports > 0 or total_blocklist_attacks > 0 or total_dshield_records > 0 or total_dshield_attacks > 0:
        malicious = True
    
    # Clean-up other fields if missing
    if "ssdeep_score" not in dom:
        dom["ssdeep_score"] = ""
    if "dns_mx" not in dom:
        dom["dns_mx"] = [""]
    if "dns_ns" not in dom:
        dom["dns_ns"] = [""]

    # Ignore duplicates
    permutation = dom["domain"]
    if permutation in perm_list:
        return None, perm_list
    else:
        perm_list.append(permutation)

    # Return blocklist/dshield info for this domain permutation
    domain_dict = {
        "organizations_uid": pe_org_uid,
        "data_source_uid": source_uid,
        "sub_domain_uid": sub_domain_uid,
        "domain_permutation": dom["domain"],
        "ipv4": dom["dns_a"][0],
        "ipv6": dom["dns_aaaa"][0],
        "mail_server": dom["dns_mx"][0],
        "name_server": dom["dns_ns"][0],
        "fuzzer": dom["fuzzer"],
        "date_active": date,
        "ssdeep_score": dom["ssdeep_score"],
        "malicious": malicious,
        "blocklist_attack_count": total_blocklist_attacks, # attacks,
        "blocklist_report_count": total_blocklist_reports, # reports,
        "dshield_record_count": total_dshield_records, # dshield_count,
        "dshield_attack_count": total_dshield_attacks, # dshield_attacks,
    }

    return domain_dict, perm_list


def execute_dnstwist(root_domain, test=0):
    """Run dnstwist on a specified root domain."""
    pathtoDict = str(pathlib.Path(__file__).parent.resolve()) + "/data/common_tlds.dict"
    dnstwist_result = dnstwist.run(
        registered=True,
        tld=pathtoDict,
        format="json",
        threads=8,
        domain=root_domain,
    )
    if test == 1:
        return dnstwist_result
    finalorglist = dnstwist_result + []
    if root_domain.split(".")[-1] == "gov": 
        for dom in dnstwist_result:
            if (
                ("tld-swap" not in dom["fuzzer"])
                and ("original" not in dom["fuzzer"])
                and ("replacement" not in dom["fuzzer"])
                and ("repetition" not in dom["fuzzer"])
                and ("omission" not in dom["fuzzer"])
                and ("insertion" not in dom["fuzzer"])
                and ("transposition" not in dom["fuzzer"])
            ):
                LOGGER.info("\tRunning again on %s", dom["domain"])
                secondlist = dnstwist.run(
                    registered=True,
                    tld=pathtoDict,
                    format="json",
                    threads=8,
                    domain=dom["domain"],
                )
                finalorglist += secondlist
    return finalorglist


def run_dnstwist(orgs_list):
    """Run DNStwist on certain domains and upload findings to database."""
    # Retrieve full org info from PE database
    pe_orgs = get_orgs()
    pe_orgs_final = []
    if orgs_list == "all":
        for pe_org in pe_orgs:
            if pe_org["report_on"]:
                pe_orgs_final.append(pe_org)
            else:
                continue
    elif orgs_list == "DEMO":
        for pe_org in pe_orgs:
            if pe_org["demo"]:
                pe_orgs_final.append(pe_org)
            else:
                continue
    else:
        for pe_org in pe_orgs:
            if pe_org["cyhy_db_name"] in orgs_list:
                pe_orgs_final.append(pe_org)
            else:
                continue

    # alphabetize org list for consistent order
    pe_orgs_final = sorted(pe_orgs_final, key=lambda d: d["cyhy_db_name"])

    # Get data source uid
    PE_conn = connect()
    source_uid = get_data_source_uid("DNSTwist")
    
    # Run DNSTwist on each organization
    failures = []
    for org_idx, org in enumerate(pe_orgs_final):
        pe_org_uid = org["organizations_uid"]
        org_name = org["name"]
        pe_org_id = org["cyhy_db_name"]
        LOGGER.info(f"Running DNSTwist on {pe_org_id} ({org_idx+1} of {len(pe_orgs_final)})")
        # Retrieve DNSTwist data from crossfeed
        try:
            # Get root domains for this org
            # root_dict = org_root_domains(PE_conn, pe_org_uid) # TSQL ver.
            root_dict = org_root_domains(pe_org_uid) # API ver.
            # Dedupe list of root domains
            list_of_roots = [d['root_domain'] for d in root_dict]
            list_of_roots = [s.strip() for s in list_of_roots]
            list_of_roots = list(set(list_of_roots))
            LOGGER.info(f"Found {len(list_of_roots)} roots for {pe_org_id}")
            # Iterate over each root domain
            domain_list = []
            perm_list = []
            for root_idx, root in enumerate(list_of_roots):
                # Run DNSTwist on each root
                root_domain = root
                if root_domain == "Null_Root":
                    continue
                LOGGER.info("Running DNSTwist on root domain: %s", root)
                with open(
                    "dnstwist_output.txt", "w"
                ) as f, contextlib.redirect_stdout(f):
                    finalorglist = execute_dnstwist(root_domain)
                LOGGER.info(f"Finished running DNSTwist on root domain: {root}")

                # Get subdomain uid
                sub_domain = root_domain
                try:
                    sub_domain_uid = getSubdomain(sub_domain)
                except Exception:
                    # If subdomain not in database, add it
                    addSubdomain(sub_domain, pe_org_uid, True) # api ver.
                    # addSubdomain(PE_conn, sub_domain, pe_org_uid, True) # tsql ver.
                    sub_domain_uid = getSubdomain(sub_domain)

                # Check root domain using Blocklist/DShield
                LOGGER.info(f"Running blocklist/dshield check on the DNSTwist results from root domain: {root}")
                for dom_idx, dom in enumerate(finalorglist):
                    domain_name = dom.get("domain")
                    print(f"{pe_org_id} - Running blocklist/dshield check on permutation: {domain_name} ({dom_idx+1}/{len(finalorglist)}), from root: {root} ({root_idx+1}/{len(list_of_roots)})")
                    domain_dict, perm_list = checkBlocklist(
                        dom, sub_domain_uid, source_uid, pe_org_uid, perm_list
                    )
                    if domain_dict is not None:
                        domain_list.append(domain_dict)
                LOGGER.info(f"Finished running blocklist/dshield check on the DNSTwist results from root domain: {root}")
        except Exception:
            LOGGER.error(f"Failed retrieving DNSTwist data for {pe_org_id}")
            failures.append(org_name)
            LOGGER.error(traceback.format_exc())

        # Insert DNSTwist data into PE database
        LOGGER.info(f"Inserting DNSTwist data for {pe_org_id}")
        try:
            for domain in domain_list:
                execute_dnstwist_data(domain)
        except Exception:
            # TODO: Create custom exceptions.
            # Issue 265: https://github.com/cisagov/pe-reports/issues/265
            LOGGER.info("Failure inserting data into database.")
            failures.append(org_name)
            LOGGER.info(traceback.format_exc())
        
    # Output summary stats
    LOGGER.info(f"{len(pe_orgs_final) - len(failures)}/{len(pe_orgs_final)} orgs successfully underwent the DNSTwist scan")
    LOGGER.info(f"{len(failures)}/{len(pe_orgs_final)} orgs had a significant failure during the DNSTwist scan")

    # Clean up and log failures
    PE_conn.close()
    if failures != []:
        LOGGER.error("These orgs failed: ", failures)


if __name__ == "__main__":
    run_dnstwist("all")
