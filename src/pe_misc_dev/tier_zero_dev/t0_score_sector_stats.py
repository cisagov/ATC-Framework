"""Scripts for gathering sector-wide data for use in the Tier 0 score."""

# Standard Python Libraries
import csv
import os
import time

# Third-Party Libraries
import pandas as pd
import requests

XPANSE_API_KEY_ID = ""
XPANSE_API_KEY = ""


# --- Retrieve Sector BU Lists ---
def get_xpanse_bu_chunk(chunk_size, page_token=None):
    """Retrieve a chunk of all Xpanse business units and their info."""
    # Call API
    url = "https://api-cisa-xpanse.crtx.gv.paloaltonetworks.com/public_api/v1/assets/get_business_units"
    headers = {
        "x-xdr-auth-id": str(XPANSE_API_KEY_ID),
        "authorization": XPANSE_API_KEY,
    }
    body = {
        "request_data": {
            "search_from": 0,
            "search_to": chunk_size,
            "sort": {"field": "business_unit_name", "keyword": "asc"},
            "use_page_token": True,
        }
    }
    # Use page token if provided
    if page_token is not None:
        body["request_data"]["next_page_token"] = page_token
    response = requests.post(url=url, headers=headers, json=body, timeout=60)
    # Retry clause
    retry_count, max_retries, time_delay = 1, 10, 5
    while response.status_code != 200 and retry_count <= max_retries:
        print(
            f"Retrying Xpanse API business units endpoint (code {response.status_code}), attempt {retry_count} of {max_retries} (url: {url})"
        )
        time.sleep(time_delay)
        response = requests.post(url=url, headers=headers, json=body, timeout=60)
        retry_count += 1
    # Return results
    if retry_count == max_retries:
        raise Exception("Error: Xpanse API business unit endpoint call failed")
    else:
        response = response.json()
        return response


def get_all_xpanse_bu():
    """Retrieve all Xpanse business units and relevant info."""
    bu_list = []
    nxt_page_token = None
    chunk_size = 1000
    total_ct = 0
    chunk_ct = 1
    # Make initial call
    print(
        f"\tWorking on BU chunk, retrieving {chunk_ct*chunk_size} of {total_ct} results..."
    )
    ini_resp = get_xpanse_bu_chunk(1000)
    total_ct = ini_resp.get("reply").get("total_count")
    nxt_page_token = ini_resp.get("reply").get("next_page_token")
    bu_chunk = ini_resp.get("reply").get("business_units")
    # Parse relevant info
    for bu in bu_chunk:
        details = bu.get("additional_details")
        bu_dict = {
            "business_unit_id": bu.get("business_unit_id"),
            "business_unit_name": bu.get("business_unit_name"),
            "parent_id": bu.get("parent_id"),
            "state": details.get("state"),
            "city": details.get("city"),
            "address": details.get("address"),
            "entity_type": details.get("entityType"),
            "region": details.get("region"),
            "sectors": details.get("sectors"),
        }
        bu_list.append(bu_dict)
    chunk_ct += 1

    # If there are more results, keep retrieving
    while nxt_page_token is not None:
        print(
            f"\tWorking on BU chunk, retrieving {chunk_ct*chunk_size} of {total_ct} results..."
        )
        resp = get_xpanse_bu_chunk(chunk_size, nxt_page_token)
        nxt_page_token = resp.get("reply").get("next_page_token")
        bu_chunk = resp.get("reply").get("business_units")
        # Parse relevant info
        for bu in bu_chunk:
            details = bu.get("additional_details")
            bu_dict = {
                "business_unit_id": bu.get("business_unit_id"),
                "business_unit_name": bu.get("business_unit_name"),
                "parent_id": bu.get("parent_id"),
                "state": details.get("state"),
                "city": details.get("city"),
                "address": details.get("address"),
                "entity_type": details.get("entityType"),
                "region": details.get("region"),
                "sectors": details.get("sectors"),
            }
            bu_list.append(bu_dict)
        chunk_ct += 1
    bu_df = pd.DataFrame(bu_list)
    return bu_df


def get_xpanse_sector_list(bu_df, ci_sector):
    """Extract organization list for the specified CI sector given a list of all Xpanse BU's."""
    sector_df = bu_df[bu_df["sectors"].str.contains(ci_sector)].reset_index(drop=True)
    sector_df = sector_df.loc[:, ~sector_df.columns.str.contains("^Unnamed")]
    return sector_df


def get_xpanse_asset_chunk(bu_name, start_date, end_date, chunk_size, page_token=None):
    """Retrieve all assets from Xpanse for the specifed business unit."""
    url = "https://api-cisa-xpanse.crtx.gv.paloaltonetworks.com/public_api/v1/assets/get_assets_internet_exposure/"
    headers = {
        "authorization": XPANSE_API_KEY,
        "x-xdr-auth-id": str(XPANSE_API_KEY_ID),
    }
    body = {
        "request_data": {
            "search_from": 0,
            "search_to": chunk_size,
            "filters": [
                {
                    "field": "business_units_list",
                    "operator": "in",
                    "value": [bu_name],
                },
                {
                    "field": "last_observed",
                    "operator": "range",
                    "value": {
                        "from": int(start_date.timestamp()) * 1000,
                        "to": int(end_date.timestamp()) * 1000,
                    },
                },
            ],
            "use_page_token": True,
        }
    }
    # Use page token if provided
    if page_token is not None:
        body["request_data"]["next_page_token"] = page_token
    response = requests.post(url=url, headers=headers, json=body, timeout=60)
    # Retry clause
    retry_count, max_retries, time_delay = 1, 10, 5
    while response.status_code != 200 and retry_count <= max_retries:
        print(
            f"Retrying Xpanse API get assets endpoint (code {response.status_code}), attempt {retry_count} of {max_retries} (url: {url})"
        )
        time.sleep(time_delay)
        response = requests.post(url=url, headers=headers, json=body, timeout=60)
        retry_count += 1
    # Return results
    if retry_count == max_retries:
        raise Exception("Error: Xpanse API get assets endpoint call failed")
    else:
        response = response.json()
        return response


def parse_asset_data(asset_dict, bu_name):
    """Given an Xpanse asset dict, parse out relevant domain and IP info."""
    domain_list = []
    ip_list = []
    asset_type = asset_dict.get("asset_type")
    if asset_type == "DOMAIN":
        # Process domain data
        domain_dict = {
            "business_unit_name": bu_name,
            "asset_type": "DOMAIN",
            "asset": asset_dict.get("domain"),
            "first_observed": asset_dict.get("first_observed"),
            "last_observed": asset_dict.get("last_observed"),
        }
        domain_list.append(domain_dict)
        # Process IP data
        if (
            ("ips" in asset_dict)
            and (asset_dict.get("ips") is not None)
            and (len(asset_dict.get("ips")) > 0)
        ):
            for ip in asset_dict.get("ips"):
                ip_dict = {
                    "business_unit_name": bu_name,
                    "asset_type": "IP",
                    "asset": ip,
                    "first_observed": asset_dict.get("first_observed"),
                    "last_observed": asset_dict.get("last_observed"),
                }
                ip_list.append(ip_dict)
    return domain_list, ip_list


def convert_ms_to_timestamp_str(df_col):
    """Convert dataframe column of millisecond values to timestamp string."""
    datetime_col = pd.to_datetime(df_col, unit="ms")
    ts_string_col = datetime_col.dt.strftime("%Y-%m-%d %H:%M:%S")
    return ts_string_col


def get_bu_asset_stats(bu_name, start_date, end_date):
    """Retrieve asset stats relevant to the Tier 0 score given a BU's xpanse ID."""
    total_domain_list = []
    total_ip_list = []
    nxt_page_token = None
    total_ct = 0
    chunk_size = 100
    chunk_ct = 1
    # Make initial call
    ini_resp = get_xpanse_asset_chunk(bu_name, start_date, end_date, chunk_size)
    total_ct = ini_resp.get("reply").get("total_count")
    nxt_page_token = ini_resp.get("reply").get("next_page_token")
    print(f"\tWorking on BU asset results {chunk_ct*chunk_size} of {total_ct}")
    chunk_ct += 1

    # If no results, move on
    if total_ct == 0:
        print(f"Error: No asset results found for {bu_name}")
        return pd.DataFrame()

    # Parse relevant info
    asset_list = ini_resp.get("reply").get("assets_internet_exposure")
    for asset in asset_list:
        curr_domain_list, curr_ip_list = parse_asset_data(asset, bu_name)
        total_domain_list.extend(curr_domain_list)
        total_ip_list.extend(curr_ip_list)

    # If there are more results, keep retrieving
    while nxt_page_token is not None:
        print(f"\tWorking on BU asset results {chunk_ct*chunk_size} of {total_ct}")
        resp = get_xpanse_asset_chunk(
            bu_name, start_date, end_date, chunk_size, nxt_page_token
        )
        nxt_page_token = resp.get("reply").get("next_page_token")
        # Parse relevant info
        asset_list = ini_resp.get("reply").get("assets_internet_exposure")
        for asset in asset_list:
            curr_domain_list, curr_ip_list = parse_asset_data(asset, bu_name)
            total_domain_list.extend(curr_domain_list)
            total_ip_list.extend(curr_ip_list)
        chunk_ct += 1

    # Final formatting
    total_domain_df = pd.DataFrame(total_domain_list)
    total_ip_df = pd.DataFrame(total_ip_list)

    if not total_domain_df.empty:
        total_domain_df = total_domain_df.sort_values(
            by="last_observed", ascending=False
        )
        total_domain_df["first_observed"] = convert_ms_to_timestamp_str(
            total_domain_df["first_observed"]
        )
        total_domain_df["last_observed"] = convert_ms_to_timestamp_str(
            total_domain_df["last_observed"]
        )
        total_domain_df = total_domain_df.drop_duplicates(
            subset=["asset"], keep="first"
        ).reset_index(drop=True)

    if not total_ip_df.empty:
        total_ip_df = total_ip_df.sort_values(by="last_observed", ascending=False)
        total_ip_df["first_observed"] = convert_ms_to_timestamp_str(
            total_ip_df["first_observed"]
        )
        total_ip_df["last_observed"] = convert_ms_to_timestamp_str(
            total_ip_df["last_observed"]
        )
        total_ip_df = total_ip_df.drop_duplicates(
            subset=["asset"], keep="first"
        ).reset_index(drop=True)

    total_asset_df = pd.concat([total_domain_df, total_ip_df], axis=0).reset_index(
        drop=True
    )
    total_asset_list = total_asset_df.to_dict(orient="records")
    return total_asset_list


def get_xpanse_cve_chunk(bu_name, start_date, end_date, chunk_size, page_token=None):
    """Retrieve all services from Xpanse for the specifed business unit."""
    url = "https://api-cisa-xpanse.crtx.gv.paloaltonetworks.com/public_api/v1/assets/get_assets_internet_exposure/"
    headers = {
        "authorization": XPANSE_API_KEY,
        "x-xdr-auth-id": str(XPANSE_API_KEY_ID),
    }
    body = {
        "request_data": {
            "search_from": 0,
            "search_to": chunk_size,
            "filters": [
                {
                    "field": "business_units_list",
                    "operator": "in",
                    "value": [bu_name],
                },
                {
                    "field": "last_observed",
                    "operator": "range",
                    "value": {
                        "from": int(start_date.timestamp()) * 1000,
                        "to": int(end_date.timestamp()) * 1000,
                    },
                },
                {
                    "field": "externally_inferred_cves",
                    "operator": "not_contains",
                    "value": "",
                },
            ],
            "use_page_token": True,
        }
    }
    # Use page token if provided
    if page_token is not None:
        body["request_data"]["next_page_token"] = page_token
    response = requests.post(url=url, headers=headers, json=body, timeout=60)
    # Retry clause
    retry_count, max_retries, time_delay = 1, 10, 5
    while response.status_code != 200 and retry_count <= max_retries:
        print(
            f"Retrying Xpanse API get CVEs endpoint (code {response.status_code}), attempt {retry_count} of {max_retries} (url: {url})"
        )
        time.sleep(time_delay)
        response = requests.post(url=url, headers=headers, json=body, timeout=60)
        retry_count += 1
    # Return results
    if retry_count == max_retries:
        raise Exception("Error: Xpanse API get CVEs endpoint call failed")
    else:
        response = response.json()
        return response


def get_shodan_cve_info(cve_id):
    """Get additional CVE info from Shodan for a given CVE ID."""
    url = f"https://cvedb.shodan.io/cve/{cve_id}"
    response = requests.get(url, timeout=60)
    # Retry clause
    retry_count, max_retries, time_delay = 1, 10, 3
    while response.status_code != 200 and retry_count <= max_retries:
        print(
            f"Retrying Shodan CVE info API endpoint (code {response.status_code}), attempt {retry_count} of {max_retries} (url: {url})"
        )
        time.sleep(time_delay)
        response = requests.get(url, timeout=60)
        retry_count += 1
    # Return results
    if retry_count == max_retries:
        raise Exception("Error: Shodan CVE info API endpoint call failed")
    else:
        return response.json()


def determine_cve_severity(cvss_ver, cvss):
    """Determine severity of CVE based on CVSS version and score."""
    severity = ""
    if (cvss_ver == 4.0) or (cvss_ver == 3.1) or (cvss_ver == 3.0):
        if cvss == 0.0:
            severity = "NONE"
        elif cvss >= 0.1 and cvss <= 3.9:
            severity = "LOW"
        elif cvss >= 4.0 and cvss <= 6.9:
            severity = "MEDIUM"
        elif cvss >= 7.0 and cvss <= 8.9:
            severity = "HIGH"
        elif cvss >= 9.0:
            severity = "CRITICAL"
    elif cvss_ver == 2.0:
        if cvss <= 3.9:
            severity = "LOW"
        elif cvss >= 4.0 and cvss <= 6.9:
            severity = "MEDIUM"
        elif cvss >= 7.0:
            severity = "HIGH"
    else:
        severity = "UNKNOWN"
    return severity


def get_bu_vuln_stats(bu_name, start_date, end_date):
    """Retrieve vulnerability stats relevant to the Tier 0 score given a BU's xpanse ID."""
    total_results_list = []
    nxt_page_token = None
    total_ct = 0
    chunk_size = 100
    chunk_ct = 1
    # Make initial call
    ini_resp = get_xpanse_cve_chunk(bu_name, start_date, end_date, chunk_size)
    total_ct = ini_resp.get("reply").get("total_count")
    nxt_page_token = ini_resp.get("reply").get("next_page_token")
    print(f"\tWorking on BU CVE results {chunk_ct*chunk_size} of {total_ct}")
    chunk_ct += 1

    # If no results, move on
    if total_ct == 0:
        print(f"Error: No CVE results found for {bu_name}")
        return pd.DataFrame()

    # Parse relevant info
    asset_list = ini_resp.get("reply").get("assets_internet_exposure")
    cve_list = [
        {
            k: d[k]
            for k in [
                "domain",
                "ips",
                "open_ports",
                "externally_inferred_cves",
                "last_observed",
            ]
            if k in d
        }
        for d in asset_list
    ]
    cve_list = [{"business_unit_name": bu_name, **item} for item in cve_list]
    total_results_list.extend(cve_list)

    # If there are more results, keep retrieving
    while nxt_page_token is not None:
        print(f"\tWorking on BU CVE results {chunk_ct*chunk_size} of {total_ct}")
        resp = get_xpanse_cve_chunk(
            bu_name, start_date, end_date, chunk_size, nxt_page_token
        )
        nxt_page_token = resp.get("reply").get("next_page_token")
        # Parse relevant info
        curr_asset_list = resp.get("reply").get("assets_internet_exposure")
        curr_cve_list = [
            {
                k: d[k]
                for k in [
                    "domain",
                    "ips",
                    "open_ports",
                    "externally_inferred_cves",
                    "last_observed",
                ]
                if k in d
            }
            for d in curr_asset_list
        ]
        curr_cve_list = [
            {"business_unit_name": bu_name, **item} for item in curr_cve_list
        ]
        total_results_list.extend(curr_cve_list)
        chunk_ct += 1

    # Final formatting
    cve_df = pd.DataFrame(total_results_list)
    cve_df["last_observed"] = pd.to_datetime(cve_df["last_observed"], unit="ms")
    cve_df["last_observed"] = cve_df["last_observed"].dt.strftime("%Y-%m-%d %H:%M:%S")
    cve_df = (
        cve_df.explode("externally_inferred_cves")
        .sort_values(by="last_observed", ascending=False)
        .reset_index(drop=True)
    )
    cve_df = cve_df.rename(columns={"externally_inferred_cves": "cve_id"})
    result_list = cve_df.to_dict(orient="records")
    return result_list


def get_xpanse_service_chunk(
    bu_name, start_date, end_date, chunk_size, page_token=None
):
    """Retrieve all protocol data from Xpanse for the specifed business unit."""
    url = "https://api-cisa-xpanse.crtx.gv.paloaltonetworks.com/public_api/v1/assets/get_external_services/"
    headers = {
        "authorization": XPANSE_API_KEY,
        "x-xdr-auth-id": str(XPANSE_API_KEY_ID),
    }
    body = {
        "request_data": {
            "search_from": 0,
            "search_to": chunk_size,
            "filters": [
                {
                    "field": "business_units_list",
                    "operator": "in",
                    "value": [bu_name],
                },
                {
                    "field": "last_observed",
                    "operator": "range",
                    "value": {
                        "from": int(start_date.timestamp()) * 1000,
                        "to": int(end_date.timestamp()) * 1000,
                    },
                },
                {"field": "is_active", "operator": "in", "value": ["Active"]},
                # {
                #     "field": "protocol",
                #     "operator": "contains",
                #     "value": "UDP",
                # },
            ],
            "use_page_token": True,
        }
    }
    # Use page token if provided
    if page_token is not None:
        body["request_data"]["next_page_token"] = page_token
    response = requests.post(url=url, headers=headers, json=body, timeout=60)
    # Retry clause
    retry_count, max_retries, time_delay = 1, 10, 5
    while response.status_code != 200 and retry_count <= max_retries:
        print(
            f"Retrying Xpanse API get services endpoint (code {response.status_code}), attempt {retry_count} of {max_retries} (url: {url})"
        )
        time.sleep(time_delay)
        response = requests.post(url=url, headers=headers, json=body, timeout=60)
        retry_count += 1
    # Return results
    if retry_count == max_retries:
        raise Exception("Error: Xpanse API get services endpoint call failed")
    else:
        response = response.json()
        return response


def determine_protocol_insecure(protocol):
    """Determine if protocol is considered insecure."""
    insecure_protocols = [
        "FTP",
        "TFTP",  # ~= FTP
        "SQL",
        "MSSQL",  # ~= SQL
        "MYSQL",  # ~= SQL
        "POSTGRES" "NETBIOS",  # ~= SQL
        "LDAP",
        "RPC",
        "IRC",
        "KERBEROS",
    ]
    return protocol in insecure_protocols


def determine_protocol_nmi(protocol):
    """Determine if protocol is considered NMI."""
    nmi_protocols = [
        "RDP",
        "SMB",
        "TELNET",
    ]
    return protocol in nmi_protocols


def get_bu_service_stats(bu_name, start_date, end_date):
    """Retrieve service stats relevant to the Tier 0 score given a BU's xpanse ID."""
    total_results_list = []
    nxt_page_token = None
    total_ct = 0
    chunk_size = 100
    chunk_ct = 1
    # Make initial call
    ini_resp = get_xpanse_service_chunk(bu_name, start_date, end_date, chunk_size)
    total_ct = ini_resp.get("reply").get("total_count")
    nxt_page_token = ini_resp.get("reply").get("next_page_token")
    print(f"\tWorking on BU service results {chunk_ct*chunk_size} of {total_ct}")
    chunk_ct += 1

    # If no results, move on
    if total_ct == 0:
        print(f"Error: No service results found for {bu_name}")
        return pd.DataFrame()

    # Parse relevant info
    service_list = ini_resp.get("reply").get("external_services")
    service_list = [
        {
            k: d[k]
            for k in [
                "domain",
                "ip_address",
                "port",
                "protocol",
                "service_id",
                "service_name",
                "service_type",
                "last_observed",
            ]
            if k in d
        }
        for d in service_list
    ]
    service_list = [{"business_unit_name": bu_name, **item} for item in service_list]
    total_results_list.extend(service_list)

    # If there are more results, keep retrieving
    while nxt_page_token is not None:
        print(f"\tWorking on BU service results {chunk_ct*chunk_size} of {total_ct}")
        resp = get_xpanse_service_chunk(
            bu_name, start_date, end_date, chunk_size, nxt_page_token
        )
        nxt_page_token = resp.get("reply").get("next_page_token")
        # Parse relevant info
        curr_service_list = resp.get("reply").get("external_services")
        curr_service_list = [
            {
                k: d[k]
                for k in [
                    "domain",
                    "ip_address",
                    "port",
                    "protocol",
                    "service_id",
                    "service_name",
                    "service_type",
                    "last_observed",
                ]
                if k in d
            }
            for d in curr_service_list
        ]
        curr_service_list = [
            {"business_unit_name": bu_name, **item} for item in curr_service_list
        ]
        total_results_list.extend(curr_service_list)
        chunk_ct += 1

    # Final formatting
    service_df = pd.DataFrame(total_results_list)
    service_df["last_observed"] = pd.to_datetime(service_df["last_observed"], unit="ms")
    service_df["last_observed"] = service_df["last_observed"].dt.strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    # Fix protocol names
    service_df["service_type"] = service_df["service_type"].str.replace(
        "Server", "", regex=False
    )
    service_df["service_type"] = service_df["service_type"].str.replace(
        "Rpcbind", "Rpc", regex=False
    )
    service_df["service_type"] = service_df["service_type"].str.replace(
        "NetBiosName", "NetBios", regex=False
    )
    service_df["service_type"] = service_df["service_type"].str.upper()
    # Add insecure/NMI protocol status
    service_df["insecure"] = service_df["service_type"].apply(
        determine_protocol_insecure
    )
    service_df["nmi"] = service_df["service_type"].apply(determine_protocol_nmi)
    result_list = service_df.to_dict(orient="records")
    return result_list


def create_save_files(save_directory):
    """Given the name of a save directory, create all necessary save files if they don't already exist."""
    # Create directory to store results
    if not os.path.exists(save_directory):
        os.mkdir(save_directory)
    else:
        print(f"Directory '{save_directory}' already exists. No new directory created.")
    # Create empty files to incrementally write vuln/service/asset data to
    vuln_save_file = save_directory + "/vuln_save_file.csv"
    service_save_file = save_directory + "/service_save_file.csv"
    asset_save_file = save_directory + "/asset_save_file.csv"
    try:
        with open(vuln_save_file, "x", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "business_unit_name",
                    "domain",
                    "ips",
                    "open_ports",
                    "cve_id",
                    "last_observed",
                ]
            )
    except FileExistsError:
        print(f"File '{vuln_save_file}' already exists. No new file created.")
    try:
        with open(service_save_file, "x", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "business_unit_name",
                    "domain",
                    "ip_address",
                    "port",
                    "protocol",
                    "service_id",
                    "service_name",
                    "service_type",
                    "last_observed",
                    "insecure",
                    "nmi",
                ]
            )
    except FileExistsError:
        print(f"File '{service_save_file}' already exists. No new file created.")
    try:
        with open(asset_save_file, "x", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "business_unit_name",
                    "asset_type",
                    "asset",
                    "first_observed",
                    "last_observed",
                ]
            )
    except FileExistsError:
        print(f"File '{asset_save_file}' already exists. No new file created.")

    return vuln_save_file, service_save_file, asset_save_file


def write_to_save_files(
    vuln_list, service_list, asset_list, vuln_file, service_file, asset_file
):
    """Given vuln, service, and asset data lists, write to specified data files."""
    if len(vuln_list) > 0:
        with open(vuln_file, "a", newline="") as file:
            writer = csv.DictWriter(file, vuln_list[0].keys())
            writer.writerows(vuln_list)
    if len(service_list) > 0:
        with open(service_file, "a", newline="") as file:
            writer = csv.DictWriter(file, service_list[0].keys())
            writer.writerows(service_list)
    if len(asset_list) > 0:
        with open(asset_file, "a", newline="") as file:
            writer = csv.DictWriter(file, asset_list[0].keys())
            writer.writerows(asset_list)


def enrich_cve_data(cve_df):
    """Given a dataframe with a cve_id column, add cvss/severity/etc. info."""
    # Add CVSS/severity data to CVEs
    unique_cve_list = list(set(cve_df["cve_id"]))
    cve_info_list = []
    for cve_idx, cve in enumerate(unique_cve_list):
        try:
            print(f"\tWorking on CVE: {cve} ({cve_idx+1} of {len(unique_cve_list)})")
            curr_cve = get_shodan_cve_info(cve)
            curr_severity = determine_cve_severity(
                curr_cve.get("cvss_version"), curr_cve.get("cvss")
            )
            cve_dict = {
                "cve_id": cve,
                "cvss_version": curr_cve.get("cvss_version"),
                "cvss_score": curr_cve.get("cvss"),
                "cvss_severity": curr_severity,
                "kev": curr_cve.get("kev"),
            }
            cve_info_list.append(cve_dict)
        except Exception as e:
            print(f"Error: Failed to get info for {cve} - {e}")
    cve_info_df = pd.DataFrame(cve_info_list)
    full_cve_df = pd.merge(cve_df, cve_info_df, on="cve_id", how="left")
    return full_cve_df


def calculate_sector_summary_stats(bu_df, asset_df, vuln_df, service_df):
    """Given a dataframe of sector BUs, assets, vulns, and services, calculate summary statistics for tier 0 score."""
    # Aggregate asset stats by BU
    asset_groups_df = (
        asset_df.groupby("business_unit_name")
        .agg(
            total_asset=("asset", "count"),
            total_domains=("asset_type", lambda x: (x == "DOMAIN").sum()),
            total_ips=("asset_type", lambda x: (x == "IP").sum()),
        )
        .reset_index()
    )
    # Aggregate vuln stats by BU
    vuln_groups_df = (
        vuln_df.groupby("business_unit_name")
        .agg(
            total_vuln=("cve_id", "count"),
            crit_high_vuln=(
                "cvss_severity",
                lambda x: ((x == "CRITICAL") | (x == "HIGH")).sum(),
            ),
            kev_vuln=("kev", lambda x: (x).sum()),
            unique_vuln=("cve_id", "nunique"),
        )
        .reset_index()
    )
    # Aggregate service stats by BU
    service_groups_df = (
        service_df.groupby("business_unit_name")
        .agg(
            total_service=("service_id", "count"),
            insec_service=("insecure", lambda x: (x).sum()),
            nmi_service=("nmi", lambda x: (x).sum()),
        )
        .reset_index()
    )
    # Join aggregated stats together
    sector_df = pd.merge(bu_df, asset_groups_df, on="business_unit_name", how="left")
    sector_df = pd.merge(sector_df, vuln_groups_df, on="business_unit_name", how="left")
    sector_df = pd.merge(
        sector_df, service_groups_df, on="business_unit_name", how="left"
    )
    # Reduce to only orgs with assets
    sector_df.fillna(0.0, inplace=True)
    sector_df = sector_df.loc[
        (sector_df["total_asset"] != 0) & (sector_df["total_service"] != 0)
    ].reset_index(drop=True)
    # Compute additional rows
    sector_df["vuln_per_asset"] = sector_df["total_vuln"] / sector_df["total_asset"]
    sector_df["crit_high_vuln_per_asset"] = (
        sector_df["crit_high_vuln"] / sector_df["total_asset"]
    )
    sector_df["kev_vuln_per_asset"] = sector_df["kev_vuln"] / sector_df["total_asset"]
    sector_df["uniq_vuln_per_asset"] = (
        sector_df["unique_vuln"] / sector_df["total_asset"]
    )
    sector_df["percent_insec_service"] = (
        sector_df["insec_service"] / sector_df["total_service"]
    )
    sector_df["percent_nmi_service"] = (
        sector_df["nmi_service"] / sector_df["total_service"]
    )
    # Calculate final min/max stats
    vuln_per_asset_max = sector_df["vuln_per_asset"].max()
    vuln_per_asset_min = sector_df["vuln_per_asset"].min()
    crit_high_vuln_per_asset_max = sector_df["crit_high_vuln_per_asset"].max()
    crit_high_vuln_per_asset_min = sector_df["crit_high_vuln_per_asset"].min()
    kev_vuln_per_asset_max = sector_df["kev_vuln_per_asset"].max()
    kev_vuln_per_asset_min = sector_df["kev_vuln_per_asset"].min()
    uniq_vuln_per_asset_max = sector_df["uniq_vuln_per_asset"].max()
    uniq_vuln_per_asset_min = sector_df["uniq_vuln_per_asset"].min()
    percent_insec_service_max = sector_df["percent_insec_service"].max()
    percent_insec_service_min = sector_df["percent_insec_service"].min()
    percent_nmi_service_max = sector_df["percent_nmi_service"].max()
    percent_nmi_service_min = sector_df["percent_nmi_service"].min()
    print(
        f"Total vuln. per asset - max: {vuln_per_asset_max}, min: {vuln_per_asset_min}"
    )
    print(
        f"Total crit/high vuln. per asset - max: {crit_high_vuln_per_asset_max}, min: {crit_high_vuln_per_asset_min}"
    )
    print(
        f"Total kev vuln. per asset - max: {kev_vuln_per_asset_max}, min: {kev_vuln_per_asset_min}"
    )
    print(
        f"Total unique vuln. per asset - max: {uniq_vuln_per_asset_max}, min: {uniq_vuln_per_asset_min}"
    )
    print(
        f"Percent insecure service - max: {percent_insec_service_max}, min: {percent_insec_service_min}"
    )
    print(
        f"Percent NMI service - max: {percent_nmi_service_max}, min: {percent_nmi_service_min}"
    )
    return {
        "vuln_per_asset_max": vuln_per_asset_max,
        "vuln_per_asset_min": vuln_per_asset_min,
        "crit_high_vuln_per_asset_max": crit_high_vuln_per_asset_max,
        "crit_high_vuln_per_asset_min": crit_high_vuln_per_asset_min,
        "kev_vuln_per_asset_max": kev_vuln_per_asset_max,
        "kev_vuln_per_asset_min": kev_vuln_per_asset_min,
        "uniq_vuln_per_asset_max": uniq_vuln_per_asset_max,
        "uniq_vuln_per_asset_min": uniq_vuln_per_asset_min,
        "percent_insec_service_max": percent_insec_service_max,
        "percent_insec_service_min": percent_insec_service_min,
        "percent_nmi_service_max": percent_nmi_service_max,
        "percent_nmi_service_min": percent_nmi_service_min,
    }


def get_sector_t0_score_stats(
    sector_df, start_date, end_date, save_dir, start_idx=None
):
    """Given a dataframe of all organizations in a sector, retrieve T0 score related data for all of them."""
    # Create progress save directory and files
    vuln_file, service_file, asset_file = create_save_files(save_dir)

    # Iterate over each org in the sector
    total_vuln_list = []
    total_service_list = []
    total_asset_list = []
    for idx, row in sector_df.iterrows():
        # Ability to start at specific index
        if start_idx is not None:
            if idx < start_idx:
                continue

        bu_name = row["business_unit_name"]
        print(
            f"Retrieving Xpanse data for organization: {bu_name} ({idx+1} of {len(sector_df)})"
        )

        # Retrieve vuln stats
        print("\tRetrieving vulnerability data for organization")
        vuln_list = get_bu_vuln_stats(bu_name, start_date, end_date)
        total_vuln_list.extend(vuln_list)

        # Retrieve service stats
        print("\tRetrieving service data for organization")
        service_list = get_bu_service_stats(bu_name, start_date, end_date)
        total_service_list.extend(service_list)

        # Retrieve asset stats
        print("\tRetrieving asset data for organization")
        asset_list = get_bu_asset_stats(bu_name, start_date, end_date)
        total_asset_list.extend(asset_list)

        # Write stats to files to save progress
        print("\tWriting results to save files")
        write_to_save_files(
            vuln_list, service_list, asset_list, vuln_file, service_file, asset_file
        )

    # Convert overall lists to dataframe
    total_vuln_df = pd.DataFrame(total_vuln_list)
    total_service_df = pd.DataFrame(total_service_list)
    total_asset_df = pd.DataFrame(total_asset_list)

    # Add CVSS/severity data to CVEs
    unique_cves = list(total_vuln_df["cve_id"].unique())
    cve_info_list = []
    for cve_idx, cve in enumerate(unique_cves):
        try:
            print(f"\tWorking on CVE: {cve} ({cve_idx+1} of {len(unique_cves)})")
            curr_cve = get_shodan_cve_info(cve)
            curr_severity = determine_cve_severity(
                curr_cve.get("cvss_version"), curr_cve.get("cvss")
            )
            cve_dict = {
                "cve_id": cve,
                "cvss_version": curr_cve.get("cvss_version"),
                "cvss_score": curr_cve.get("cvss"),
                "cvss_severity": curr_severity,
                "kev": curr_cve.get("kev"),
            }
            cve_info_list.append(cve_dict)
        except Exception as e:
            print(f"Error: Failed to get info for {cve} - {e}")
    cve_info_df = pd.DataFrame(cve_info_list)
    total_vuln_df = pd.merge(total_vuln_df, cve_info_df, on="cve_id", how="left")

    # Calculate sector summary stats
    bu_df = sector_df[["business_unit_id", "business_unit_name"]].reset_index(drop=True)
    sector_t0_stats = calculate_sector_summary_stats(
        bu_df, total_asset_df, total_vuln_df, total_service_df
    )
    return sector_t0_stats


# --- Testing ---
# # Get list of all BUs (organizations) regardless of sector
# # all_bu_df = get_all_xpanse_bu()
# all_bu_df = pd.read_excel(
#     "./sector_data/bu_data/xpanse_all_bu_list_2025-04-23.xlsx", index_col=False
# )
# all_bu_df = all_bu_df.fillna("[]")
# # Narrow down list of BUs to specified CI sector
# sector_df = get_xpanse_sector_list(all_bu_df, "GOVERNMENT_FACILITIES")
# # Set parameters and run
# start_date = datetime.datetime(2025, 6, 16)
# end_date = datetime.datetime(2025, 6, 30)
# save_dir_name = "./sector_data/tzscore_data/2025-06-25_gov_fac_sector"
# start_idx = 14386  # index to resume retrieval if crash occurs
# sector_t0_results = get_sector_t0_score_stats(
#     sector_df, start_date, end_date, save_dir_name, start_idx
# )


# --- Manual Version Using Save Files ---
# # Enrich vuln data from save file
# # enriched_vuln_data = enrich_cve_data(vuln_data)
# # enriched_vuln_data.to_csv("./sector_data/tzscore_data/2025-06-25_gov_fac_sector/enriched_vuln_save_file.csv", index=False)
# # Load sector organization list from file
# all_sector_df = pd.read_excel("./sector_data/bu_data/xpanse_all_bu_list_2025-04-23.xlsx", index_col=False)
# all_sector_df["sectors"] = all_sector_df["sectors"].fillna("[]")
# bu_df = all_sector_df.loc[all_sector_df["sectors"].apply(lambda x: "GOVERNMENT_FACILITIES" in x)]
# bu_df = bu_df[["business_unit_id", "business_unit_name"]].reset_index(drop=True)
# # Load sector asset, vuln, and service data from file
# asset_data = pd.read_csv("./sector_data/tzscore_data/2025-06-25_gov_fac_sector/asset_save_file.csv")
# vuln_data = pd.read_csv("./sector_data/tzscore_data/2025-06-25_gov_fac_sector/enriched_vuln_save_file.csv")
# service_data = pd.read_csv("./sector_data/tzscore_data/2025-06-25_gov_fac_sector/service_save_file.csv")
# sector_stats = calculate_sector_summary_stats(bu_df, asset_data, vuln_data, service_data)
# pprint.pprint(sector_stats)


# --- Extra Code ---
# # Calculate Tier 0 score metrics for each organization
# print("Calculating Tier 0 score metrics for all oranizations")
# bu_t0_stats_list = []
# for idx, row in sector_df.iterrows():
#     bu_name = row["business_unit_name"]

#     # Ability to start at specific index
#     if start_idx is not None:
#         if idx < start_idx:
#             continue

#     # vuln data for this org
#     bu_vuln_df = total_vuln_df.loc[total_vuln_df["business_unit_name"] == bu_name]
#     # service data for this org
#     bu_service_df = total_service_df.loc[total_service_df["business_unit_name"] == bu_name]
#     # asset data for this org
#     bu_asset_df = total_asset_df.loc[total_asset_df["business_unit_name"] == bu_name]
#     # assemble tier 0 related metrics
#     vulns_total = len(bu_vuln_df)
#     vulns_crit_high = len(bu_vuln_df.loc[(bu_vuln_df["cvss_severity"] == "CRITICAL") | (bu_vuln_df["cvss_severity"] == "HIGH")])
#     vulns_kev = len(bu_vuln_df.loc[bu_vuln_df["kev"] == True])
#     vulns_unique = bu_vuln_df["cve_id"].nunique()
#     services_insec = len(bu_service_df.loc[bu_service_df["insecure"] == True])
#     services_nmi = len(bu_service_df.loc[bu_service_df["nmi"] == True])
#     assets_domains = len(bu_asset_df.loc[bu_asset_df["asset_type"] == "DOMAIN"])
#     assets_ips = len(bu_asset_df.loc[bu_asset_df["asset_type"] == "IP"])
#     assets_services = len(bu_service_df)
#     assets_total = assets_domains + assets_ips

#     t0_dict ={
#         "vulns_total": vulns_total,
#         "vulns_crit_high": vulns_crit_high,
#         "vulns_kev": vulns_kev,
#         "vulns_unique": vulns_unique,
#         "services_insec": services_insec,
#         "services_nmi": services_nmi,
#         "assets_domains": assets_domains,
#         "assets_ips": assets_ips,
#         "assets_services": assets_services,
#         "vulns_total_per_asset": vulns_total/assets_total,
#         "vulns_crit_high_per_asset": vulns_crit_high/assets_total,
#         "vulns_kev_per_asset": vulns_kev/assets_total,
#         "vulns_unique_per_asset": vulns_unique/assets_total,
#         "services_percent_insec": services_insec/assets_services,
#         "services_percent_nmi": services_nmi/assets_services,
#     }
#     bu_t0_stats_list.append(t0_dict)

# # Convert to dataframe and return
# sector_t0_stats_df = pd.DataFrame(bu_t0_stats_list)
