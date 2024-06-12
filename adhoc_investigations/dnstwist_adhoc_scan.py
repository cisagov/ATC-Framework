"""Adhoc version of the DNSTwist scan."""
# Standard Python Libraries
import datetime
import json
import logging
import time

# Third-Party Libraries
import dnstwist
import dshield
import pandas as pd
import requests

from adhoc_helpers import calc_progress

# Setup logging
main_log = logging.getLogger(__name__)

date = datetime.datetime.now().strftime("%Y-%m-%d")    


def checkBlocklist(domain_dict, org_uid):
    """Retrieve DShield Blocklist results for DNSTwist domain."""
    # Stat variables
    malicious = False
    attacks = 0
    reports = 0

    # Check IPv4 info
    if "original" in domain_dict["fuzzer"]:
        return None
    elif "dns_a" not in domain_dict:
        return None
    elif str(domain_dict["dns_a"][0]) == "!ServFail":
        return None
    else:
        # Check IP in Blocklist API
        response = requests.get(
            "http://api.blocklist.de/api.php?ip=" + str(domain_dict["dns_a"][0])
        )
        # Retry if API fails
        retry_max = 10
        retry_count = 1
        while response.status_code != 200 and retry_count <= retry_max:
            main_log.error(f"blocklist.de API call failed, code: {response.status_code}")
            main_log.error(f"\tRetrying in 5 sec - retry {retry_count} of {retry_max}")
            time.sleep(5)
            response = requests.get(
                "http://api.blocklist.de/api.php?ip=" + str(domain_dict["dns_a"][0])
            )
            retry_count += 1
        response = response.content
        # If Blocklist response is non-zero parse stats
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
            results = dshield.ip(str(domain_dict["dns_a"][0]), return_format=dshield.JSON)
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

    # Check IPv6 info
    if "dns_aaaa" not in domain_dict:
        domain_dict["dns_aaaa"] = [""]
    elif str(domain_dict["dns_aaaa"][0]) == "!ServFail":
        domain_dict["dns_aaaa"] = [""]
    else:
        # Check IP in Blocklist API
        response = requests.get(
            "http://api.blocklist.de/api.php?ip=" + str(domain_dict["dns_aaaa"][0])
        )
        # Retry if API fails
        retry_max = 10
        retry_count = 1
        while response.status_code != 200 and retry_count <= retry_max:
            main_log.error(f"blocklist.de API call failed, code: {response.status_code}")
            main_log.error(f"\tRetrying in 5 sec - retry {retry_count} of {retry_max}")
            time.sleep(5)
            response = requests.get(
                "http://api.blocklist.de/api.php?ip=" + str(domain_dict["dns_aaaa"][0])
            )
            retry_count += 1
        response = response.content
        # If Blocklist response is non-zero parse stats
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
            results = dshield.ip(str(domain_dict["dns_aaaa"][0]), return_format=dshield.JSON)
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

    # Do final clean up on results
    if "ssdeep_score" not in domain_dict:
        domain_dict["ssdeep_score"] = ""
    if "dns_mx" not in domain_dict:
        domain_dict["dns_mx"] = [""]
    if "dns_ns" not in domain_dict:
        domain_dict["dns_ns"] = [""]
    # Assemble final results dictionary
    domain_dict = {
        "organizations_uid": org_uid,
        "data_source_uid": "7ad1b168-981d-11ec-a102-02589a36c9d7",
        # "sub_domain_uid": sub_domain_uid,
        "original_domain": domain_dict["original_domain"],
        "domain_permutation": domain_dict["domain"],
        "ipv4": domain_dict["dns_a"][0],
        "ipv6": domain_dict["dns_aaaa"][0],
        "mail_server": domain_dict["dns_mx"][0],
        "name_server": domain_dict["dns_ns"][0],
        "fuzzer": domain_dict["fuzzer"],
        "date_active": date,
        "ssdeep_score": domain_dict["ssdeep_score"],
        "malicious": malicious,
        "blocklist_attack_count": attacks,
        "blocklist_report_count": reports,
        "dshield_record_count": dshield_count,
        "dshield_attack_count": dshield_attacks,
    }
    return domain_dict


def get_dnstwist_data(org_uid, org_abbrv, domains, save_file):
    """Retrieve DNSTwist data for the specified root domains."""
    main_log.info(f"=== {org_abbrv} DNSTwist Adhoc Scan Starting ===")
    total_dnstwist_results = []
    # Go through list of orginial domains (nasa.gov, nyc.gov etc.)
    domain_ct = 1
    for domain in domains:
        # Run dnstwist on original domain
        main_log.info(f"Running 1st level DNSTwist on {domain}... ({domain_ct} of {len(domains)})")
        try:
            dnstwist_result = dnstwist.run(
                registered=True,
                tld="dnstwist_common_tlds.dict",
                format="json",
                threads=8,
                domain=domain,
                # output=dnstwist.devnull, # suppress output to terminal
            )
        except Exception as e:
            main_log.info(f"Error: {domain} is an invalid domain")
            continue
        finalorglist = dnstwist_result + []
        main_log.info(f"1st level DNSTwist complete for {domain}")

        # Check if original domain is a .gov
        if domain.split(".")[-1] == "gov": 
            # If .gov domain, do a 2nd level DNSTwist on 1st level DNSTwist results
            main_log.info(f"{domain} is a .gov domain, running a 2nd level DNSTwist")
            # Iterate through 1st level dnstwist results
            for dom in dnstwist_result:
                # main_log.info("\tChecking if %s is eligible for 2nd level DNSTwist" % dom["domain"])
                if (
                    ("tld-swap" not in dom["fuzzer"])
                    and ("original" not in dom["fuzzer"])
                    and ("replacement" not in dom["fuzzer"])
                    and ("repetition" not in dom["fuzzer"])
                    and ("omission" not in dom["fuzzer"])
                    and ("insertion" not in dom["fuzzer"])
                    and ("transposition" not in dom["fuzzer"])
                ):
                    # If eligible, run a 2nd level DNSTwist
                    main_log.info("\t\tRunning 2nd level DNSTwist on %s..." % dom["domain"])
                    secondlist = dnstwist.run(
                        registered=True,
                        tld="dnstwist_common_tlds.dict",
                        format="json",
                        threads=8,
                        domain=dom["domain"],
                        # output=dnstwist.devnull, # suppress output to terminal
                    )
                    finalorglist += secondlist
                    main_log.info("\t\t2nd level DNSTwist complete for %s" % dom["domain"])

        # Add original domain 
        finalorglist = [dict(item, original_domain=domain) for item in finalorglist]
        main_log.info(f"DNSTwist complete for {domain}")
        domain_ct += 1
        # Add all the results for this domain to the total overall list
        total_dnstwist_results += finalorglist
    
    # Option to limit output for testing
    # total_dnstwist_results = total_dnstwist_results[:100]

    # Next, compare that total list of DNSTwisted domains to blocklist.de
    main_log.info("Checking DNSTwist results against blocklist/dshield")
    final_results = []
    for idx, domain in enumerate(total_dnstwist_results):
        # main_log.info("Checking %s for Blocklist results..." % domain["domain"])
        if calc_progress(len(total_dnstwist_results), idx) is not None:
            main_log.info(f"Checking for Blocklist results, {calc_progress(len(total_dnstwist_results), idx)}")
        # For each DNSTwist domain, check against blocklist.de
        blocklist_results = checkBlocklist(domain, org_uid)
        if blocklist_results is not None:
            # If results found, add to final_results list
            # main_log.info("\tBlocklist results found for %s" % domain["domain"])
            final_results.append(blocklist_results)
    main_log.info("Blocklist check complete")

    # Consolidate final results into dataframe
    dnstwist_results_df = pd.DataFrame(final_results)
    dnstwist_results_df["org_abbrv"] = org_abbrv
    dnstwist_results_df = dnstwist_results_df[
        [
            "organizations_uid", 
            "org_abbrv", 
            "original_domain", 
            "domain_permutation",
            "ipv4",
            "ipv6",
            "mail_server",
            "name_server",
            "fuzzer",
            "malicious",
            "blocklist_attack_count",
            "blocklist_report_count",
            "dshield_attack_count",
            "dshield_record_count",
            # "ssdeep_score",
            "date_active",
        ]
    ]
    dnstwist_results_df.drop_duplicates(inplace=True)
    num_blocklist_results = len(dnstwist_results_df)
    dnstwist_results_df = dnstwist_results_df.loc[dnstwist_results_df["malicious"] == True]
    dnstwist_results_df.reset_index(drop=True, inplace=True)

    # Print stats and save to file
    main_log.info(f"{len(total_dnstwist_results)} DNSTwist domains found from {org_abbrv}'s domains")
    main_log.info(f"{num_blocklist_results} DNSTwist domains had blocklist/dshield info")
    main_log.info(f"{len(dnstwist_results_df)} of those domains were reported as malicious by blocklist/dshield")

    if len(dnstwist_results_df) == 0:
        main_log.info("No DNSTwist results found")
        main_log.info(f"=== {org_abbrv} DNSTwist Adhoc Scan Complete ===")
        return 0
    else:
        # Save data to file
        main_log.info(f"Saving to file: {save_file}")
        dnstwist_results_df.to_csv(save_file)
        main_log.info(f"=== {org_abbrv} DNSTwist Adhoc Scan Complete ===")
        return 1