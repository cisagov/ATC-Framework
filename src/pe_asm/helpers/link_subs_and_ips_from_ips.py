"""Link sub-domains and IPs from IP lookups."""
# Standard Python Libraries
import datetime
import hashlib
import ipaddress
import logging
import threading
import time

# Third-Party Libraries
import numpy as np
import pandas as pd
import requests

# cisagov Libraries
from pe_asm.data.cyhy_db_query import (
    execute_ips,
    pe_db_connect,
    pe_db_staging_connect,
    query_cidrs_by_org,
    query_pe_report_on_orgs,
)
from pe_reports.data.config import whois_xml_api_key

LOGGER = logging.getLogger(__name__)
WHOIS_KEY = whois_xml_api_key()
DATE = datetime.datetime.today().date()


def reverseLookup(ip_obj, failed_ips, conn, thread):
    """Take an ip and find all associated subdomains."""
    # Query WHOisXML
    url = f"https://dns-history.whoisxmlapi.com/api/v1?apiKey={WHOIS_KEY}&ip={ip_obj['ip']}"
    payload = {}
    headers = {}
    response = requests.request("GET", url, headers=headers, data=payload)

    # Retry clause
    retry_count, max_retries, time_delay = 1, 3, 1
    while response.status_code != 200 and retry_count <= max_retries:
        if retry_count >= 2:
            LOGGER.warning(f"Retrying WhoisXML API endpoint (code {response.status_code}), attempt {retry_count} of {max_retries} (url: {url})")
        time.sleep(time_delay)
        response = requests.request("GET", url, headers=headers, data=payload)
        retry_count += 1
    # If API call still unsuccessful
    if response.status_code != 200:
        bad_ip = ip_obj["ip"]
        LOGGER.error(f"Max retries reached for {bad_ip}, labeling as failed")
        failed_ips.append(ip_obj["ip"])
    response = response.json()

    found_domains = []
    try:
        # If there is a response, save domain
        if response["size"] > 0:
            # Insert or update IP
            execute_ips(conn, ip_obj)

            result = response["result"]
            for domain in result:
                # print(domain)
                try:
                    found_domains.append(
                        {
                            "sub_domain": domain["name"],
                            "root": ".".join(domain["name"].rsplit(".")[-2:]),
                        }
                    )
                except KeyError:
                    continue

    except Exception as e:
        LOGGER.error(f"{thread}: Failed to return WHOIsXML response")
        LOGGER.error(f"{thread}: {response}")
        LOGGER.error(f"{thread}: {e}")
    return found_domains, failed_ips


def link_domain_from_ip(ip_obj, org_uid, data_source, failed_ips, conn, thread):
    """From a provided ip find domains and link them in the db."""
    # Lookup domains from IP
    found_domains, failed_ips = reverseLookup(ip_obj, failed_ips, conn, thread)
    for domain in found_domains:
        cur = conn.cursor()
        cur.callproc(
            "link_ips_and_subs",
            (
                DATE,
                ip_obj["ip_hash"],
                ip_obj["ip"],
                org_uid,
                domain["sub_domain"],
                data_source,
                None,
                domain["root"],
            ),
        )
        row = cur.fetchone()
        # print("Row after procedure")
        # print(row)
        conn.commit()
        cur.close()
    return found_domains


def run_ip_chunk(org_name, org_uid, ips_df, thread, conn):
    """Run the provided chunk through the linking process."""
    count = 0
    last_chunk = time.time()
    failed_ips = []
    for ip_index, ip in ips_df.iterrows():
        # internal status logging
        if count % 10 == 0:
            print(f"{thread}: Currently on {org_name}'s IP {count}/{len(ips_df)}")
        # Log progress
        count += 1
        if count % 10000 == 0:
            LOGGER.info(f"{thread}: Running {org_name} IPs: {count}/{len(ips_df)}, {time.time() - last_chunk} seconds for the last IP chunk")
            last_chunk = time.time()

        # Link domain from IP
        try:
            link_domain_from_ip(ip, org_uid, "WhoisXML", failed_ips, conn, thread)
        except requests.exceptions.SSLError as e:
            LOGGER.error(e)
            time.sleep(1)
            continue
    # LOGGER.info(f"{thread} Ips took {time.time() - start_time} to link to subs")


def connect_subs_from_ips(staging, orgs_df=None):
    """For each org find all domains that are associated to an ip and create link in the ip_subs table."""
    # Connect to database
    if staging:
        conn = pe_db_staging_connect()
    else:
        conn = pe_db_connect()

    # Get P&E organizations DataFrame
    if not isinstance(orgs_df, pd.DataFrame):
        orgs_df = query_pe_report_on_orgs(conn)
    num_orgs = len(orgs_df.index)

    # Close database connection
    conn.close()

    # Loop through orgs
    org_count = 1
    for org_index, org in orgs_df.iloc[::-1].iterrows():
        # Connect to database
        if staging:
            conn = pe_db_staging_connect()
        else:
            conn = pe_db_connect()
        org_name = org["cyhy_db_name"]
        LOGGER.info(
            "Running on %s, %d/%d", org_name, org_count, num_orgs
        )
        # Query IPs
        org_uid = org["organizations_uid"]
        # ips_df = query_ips(org_uid, conn)
        cidrs = query_cidrs_by_org(conn, org_uid)
        ips_list = []
        for cidr_index, cidr_row in cidrs.iterrows():
            for ip in list(ipaddress.IPv4Network(cidr_row["network"]).hosts()):
                hash_object = hashlib.sha256(str(ip).encode("utf-8"))
                ip_obj = {
                    "ip_hash": hash_object.hexdigest(),
                    "ip": str(ip),
                    "origin_cidr": cidr_row["cidr_uid"],
                    "first_seen": DATE,
                    "last_seen": DATE,
                    "current": True,
                    "from_cidr": True,
                    "last_reverse_lookup": DATE,
                    "organizations_uid": org_uid,
                }
                ips_list.append(ip_obj)
        ips_df = pd.DataFrame(ips_list)

        LOGGER.info(f"Number of CIDRs: {len(cidrs)}")

        # if no IPS, continue to next org
        if len(ips_df.index) == 0:
            # Close database connection
            conn.close()
            org_count += 1
            continue

        # Split IPs into 8 threads, then call run_ip_chunk function
        num_chunks = 5
        ips_split = np.array_split(ips_df, num_chunks)
        thread_num = 0
        thread_list = []
        while thread_num < len(ips_split):
            thread_name = f"Thread {thread_num + 1}: "
            # Start thread
            t = threading.Thread(
                target=run_ip_chunk,
                args=(org_name, org_uid, ips_split[thread_num], thread_name, conn),
            )
            t.start()
            thread_list.append(t)
            thread_num += 1

        for thread in thread_list:
            thread.join()

        LOGGER.info("All threads have finished.")

        org_count += 1

        # Close database connection
        conn.close()
