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
import psycopg2.extras as extras
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

date = datetime.datetime.now().strftime("%Y-%m-%d")
LOGGER = logging.getLogger(__name__)


def checkBlocklist(dom, sub_domain_uid, source_uid, pe_org_uid, perm_list):
    """Cross reference the dnstwist results with DShield Blocklist."""
    malicious = False
    attacks = 0
    reports = 0
    if "original" in dom["fuzzer"]:
        return None, perm_list
    elif "dns_a" not in dom:
        return None, perm_list
    else:
        if str(dom["dns_a"][0]) == "!ServFail":
            return None, perm_list

        # Check IP in Blocklist API
        blocklist_url = "http://api.blocklist.de/api.php?ip=" + str(dom["dns_a"][0])
        response = requests.get(blocklist_url)
        # Retry clause
        retry_count, max_retries, time_delay = 1, 10, 5
        while response.status_code != 200 and retry_count <= max_retries:
            LOGGER.warning(f"Retrying Blocklist.de API endpoint (code {response.status_code}), attempt {retry_count} of {max_retries} (url: {blocklist_url})")
            time.sleep(time_delay)
            response = requests.get(blocklist_url)
            retry_count += 1
        response = response.content

        if str(response) != "b'attacks: 0<br />reports: 0<br />'":
            try:
                malicious = True
                attacks = int(str(response).split("attacks: ")[1].split("<")[0])
                reports = int(str(response).split("reports: ")[1].split("<")[0])
            except Exception:
                malicious = False
                dshield_attacks = 0
                dshield_count = 0

        # Check IP in DSheild API
        try:
            results = dshield.ip(str(dom["dns_a"][0]), return_format=dshield.JSON)
            results = json.loads(results)
            threats = results["ip"]["threatfeeds"]
            attacks = results["ip"]["attacks"]
            attacks = int(0 if attacks is None else attacks)
            malicious = True
            dshield_attacks = attacks
            dshield_count = len(threats)
        except Exception:
            dshield_attacks = 0
            dshield_count = 0

    # Check IPv6
    if "dns_aaaa" not in dom:
        dom["dns_aaaa"] = [""]
    elif str(dom["dns_aaaa"][0]) == "!ServFail":
        dom["dns_aaaa"] = [""]
    else:
        # Check IP in Blocklist API
        blocklist_url = "http://api.blocklist.de/api.php?ip=" + str(dom["dns_aaaa"][0])
        response = requests.get(blocklist_url)
        # Retry clause
        retry_count, max_retries, time_delay = 1, 10, 5
        while response.status_code != 200 and retry_count <= max_retries:
            LOGGER.warning(f"Retrying Blocklist.de API endpoint (code {response.status_code}), attempt {retry_count} of {max_retries} (url: {blocklist_url})")
            time.sleep(time_delay)
            response = requests.get(blocklist_url)
            retry_count += 1
        response = response.content

        if str(response) != "b'attacks: 0<br />reports: 0<br />'":
            try:
                malicious = True
                attacks = int(str(response).split("attacks: ")[1].split("<")[0])
                reports = int(str(response).split("reports: ")[1].split("<")[0])
            except Exception:
                malicious = False
                dshield_attacks = 0
                dshield_count = 0

        # Check IP in DSheild API
        try:
            results = dshield.ip(str(dom["dns_aaaa"][0]), return_format=dshield.JSON)
            results = json.loads(results)
            threats = results["ip"]["threatfeeds"]
            attacks = results["ip"]["attacks"]
            attacks = int(0 if attacks is None else attacks)
            malicious = True
            dshield_attacks = attacks
            dshield_count = len(threats)
        except Exception:
            dshield_attacks = 0
            dshield_count = 0

    # Clean-up other fields
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
        "blocklist_attack_count": attacks,
        "blocklist_report_count": reports,
        "dshield_record_count": dshield_count,
        "dshield_attack_count": dshield_attacks,
    }
    return domain_dict, perm_list


def execute_dnstwist(root_domain, test=0):
    """Run dnstwist on each root domain."""
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
                LOGGER.info("Running again on %s", dom["domain"])
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
    PE_conn = connect()
    source_uid = get_data_source_uid("DNSTwist")

    """ Get P&E Orgs """
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

    failures = []
    for org in pe_orgs_final:
        pe_org_uid = org["organizations_uid"]
        org_name = org["name"]
        pe_org_id = org["cyhy_db_name"]

        # Only run on orgs in the org list
        if pe_org_id in orgs_list or orgs_list == "all" or orgs_list == "DEMO":
            LOGGER.info("Running DNSTwist on %s", pe_org_id)

            """Collect DNSTwist data from Crossfeed"""
            try:
                # Get root domains
                root_dict = org_root_domains(pe_org_uid)
                domain_list = []
                perm_list = []
                for root in root_dict:
                    root_domain = root["root_domain"]
                    if root_domain == "Null_Root":
                        continue
                    LOGGER.info("\tRunning on root domain: %s", root["root_domain"])

                    with open(
                        "dnstwist_output.txt", "w"
                    ) as f, contextlib.redirect_stdout(f):
                        finalorglist = execute_dnstwist(root_domain)

                    # Get subdomain uid
                    sub_domain = root_domain
                    try:
                        sub_domain_uid = getSubdomain(sub_domain)
                    except Exception as error:
                        # TODO: Create custom exceptions.
                        # Issue 265: https://github.com/cisagov/pe-reports/issues/265
                        # Add and then get it
                        addSubdomain(sub_domain, pe_org_uid, True)  # api ver.
                        # addSubdomain(PE_conn, sub_domain, pe_org_uid, True) # tsql ver.
                        sub_domain_uid = getSubdomain(sub_domain)

                    # Check Blocklist
                    for dom in finalorglist:
                        domain_dict, perm_list = checkBlocklist(
                            dom, sub_domain_uid, source_uid, pe_org_uid, perm_list
                        )
                        if domain_dict is not None:
                            domain_list.append(domain_dict)
            except Exception as error:
                # TODO: Create custom exceptions.
                # Issue 265: https://github.com/cisagov/pe-reports/issues/265
                LOGGER.info("Failed selecting DNSTwist data.")
                failures.append(org_name)
                LOGGER.info(traceback.format_exc())

            """Insert cleaned data into PE database."""
            try:
                for domain in domain_list:
                    execute_dnstwist_data(domain)
            except Exception:
                # TODO: Create custom exceptions.
                # Issue 265: https://github.com/cisagov/pe-reports/issues/265
                LOGGER.info("Failure inserting data into database.")
                failures.append(org_name)
                LOGGER.info(traceback.format_exc())

    PE_conn.close()
    if failures != []:
        LOGGER.error("These orgs failed:")
        LOGGER.error(failures)


if __name__ == "__main__":
    run_dnstwist("all")


