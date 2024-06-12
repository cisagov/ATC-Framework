"""Adhoc version of the WhoisXML scan."""
# Standard Python Libraries
import datetime
import json
import logging
import time

# Third-Party Libraries
import pandas as pd
import requests

# .ini Data
import adhoc_config

# Setup logging
main_log = logging.getLogger(__name__)

# WhoisXML API Info
api_key = adhoc_config.get_ini_data().get("whoisxml")


def get_whoisxml_data(org_uid, org_abbrv, root_domains, ips, save_file):
    main_log.info(f"=== {org_abbrv} WhoisXML Adhoc Scan Starting ===")
    # Discover all subdomains from rootdomains
    main_log.info("Discovering subdomains from rootdomains...")
    # Go through each root domain
    total_root_subs = []
    root_ct = 1
    for root_domain in root_domains:
        # Call WhoisXML API to discover all subdomains from root domain
        # main_log.info(f"\tDiscovering subdomains from root domain: {root_domain} ({root_ct} of {len(root_domains)})")
        sub_from_root_url = "https://domains-subdomains-discovery.whoisxmlapi.com/api/v1"
        payload = json.dumps(
            {
                "apiKey": api_key,
                "domains": {"include": [f"{root_domain}"]},
                "subdomains": {"include": ["*"], "exclude": []},
            }
        )
        headers = {"Content-Type": "application/json"}
        sub_from_root_resp = requests.post(sub_from_root_url, headers=headers, data=payload)

        # Retry if API fails
        retry_max = 10
        retry_count = 1
        while sub_from_root_resp.status_code != 200 and retry_count <= retry_max:
            main_log.error(f"WhoisXML API call failed, code: {sub_from_root_resp.status_code}")
            main_log.error(f"\tRetrying in 5 sec - retry {retry_count} of {retry_max}")
            time.sleep(5)
            sub_from_root_resp = requests.post(sub_from_root_url, headers=headers, data=payload)
            retry_count += 1
        sub_from_root_resp = sub_from_root_resp.json()

        root_subs = sub_from_root_resp.get("domainsList")
        if len(root_subs) > 0:
            # main_log.info("\tRetrieved discovered subdomains")
            # Add additional data
            root_subs_df = pd.DataFrame(root_subs, columns=["sub_domain"])
            root_subs_df.insert(0, "ip_origin", None)
            root_subs_df.insert(0, "root_domain_origin", root_domain)
            root_subs_df.insert(0, "organization", org_abbrv)
            root_subs_df.insert(0, "organizations_uid", org_uid)
            root_subs_df["discovered"] = True
            root_subs_df["last_seen"] = datetime.datetime.today().date()
            # Exclude "www.rootdomain" from results
            root_subs_df = root_subs_df[root_subs_df["sub_domain"] != f"www.{root_domain}"]
            total_root_subs.append(root_subs_df)
        # else:
            # main_log.info("\tNo results found for this rootdomain")
        root_ct += 1
    # Compile all rootdomain subdomains into one dataframe
    total_root_subs_df = pd.concat(total_root_subs)
    main_log.info("Finished discovering subdomains from rootdomains")

    # Discover all subdomains from ips
    main_log.info("Discovering subdomains from IPs...")
    # Go through each ip
    total_ip_subs = []
    ip_ct = 1
    for ip in ips:
        # Call WhoisXML API to discover all subdomains from ip
        # main_log.info(f"\tDiscovering subdomains from IP: {ip} ({ip_ct} of {len(ips)})")
        sub_from_ip_url = f"https://dns-history.whoisxmlapi.com/api/v1?apiKey={api_key}&ip={ip}"
        sub_from_ip_resp = requests.get(sub_from_ip_url)

        # Retry if API fails
        retry_max = 10
        retry_count = 1
        while sub_from_ip_resp.status_code != 200 and retry_count <= retry_max:
            main_log.error(f"WhoisXML API call failed, code: {sub_from_ip_resp.status_code}")
            main_log.error(f"\tRetrying in 5 sec - retry {retry_count} of {retry_max}")
            time.sleep(5)
            sub_from_ip_resp = requests.get(sub_from_ip_url)
            retry_count += 1
        sub_from_ip_resp = sub_from_ip_resp.json()

        if sub_from_ip_resp["size"] > 0:
            # If there are results for this IP
            # main_log.info("\tResults found for this IP")
            # Iterate through results
            for result in sub_from_ip_resp["result"]:
                # Add each result to the total list
                try:
                    total_ip_subs.append(
                        {
                            "organizations_uid": org_uid,
                            "organization": org_abbrv,
                            "root_domain_origin": None,
                            "ip_origin": ip,
                            "sub_domain": result["name"],
                            "discovered": True,
                            "last_seen": datetime.datetime.today().date(),
                            #"root": ".".join(result["name"].rsplit(".")[-2:]),
                        }
                    )
                except KeyError:
                    continue
        # else:
            # Otherwise print no results
            # main_log.info("\tNo results found for this IP")
        ip_ct += 1
    # Compile all ip subdomains into one dataframe
    total_ip_subs_df = pd.DataFrame(total_ip_subs)
    main_log.info("Finished discovering subdomains from IPs")

    # Combine all results and drop duplicates
    total_subs_df = pd.concat([total_root_subs_df, total_ip_subs_df], ignore_index = True)

    if len(total_subs_df) > 0:
        total_subs_df.drop_duplicates(inplace=True)
        num_root_subs = len(total_subs_df.loc[~total_subs_df["root_domain_origin"].isna()])
        num_ip_subs = len(total_subs_df.loc[~total_subs_df["ip_origin"].isna()])
        main_log.info(f"{num_root_subs} subdomains found via rootdomains")
        main_log.info(f"{num_ip_subs} subdomains found via ips")
        main_log.info(f"{len(total_subs_df)} subdomains found in total")
        # Save results to file
        main_log.info(f"Saving to file: {save_file}")
        total_subs_df.to_csv(save_file)
        main_log.info(f"=== {org_abbrv} WhoisXML Adhoc Scan Complete ===")
        return 1
    else:
        main_log.info("No results found")
        main_log.info(f"=== {org_abbrv} WhoisXML Adhoc Scan Complete ===")
        return 0

