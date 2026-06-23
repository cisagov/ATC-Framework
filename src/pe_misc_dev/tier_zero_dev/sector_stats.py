"""Scripts to retrieve and calculate sector-wide stats for org comparison."""

# Standard Python Libraries
import csv
import datetime
import ipaddress
import os
import time

# Third-Party Libraries
import pandas as pd
import requests

XPANSE_API_KEY_ID = ""
XPANSE_API_KEY = ""


def get_xpanse_ip_ranges(bu_list, page_token=None):
    """Get all owned IP ranges for the specified business units."""
    url = "https://api-cisa-xpanse.crtx.gv.paloaltonetworks.com/public_api/v1/assets/get_external_ip_address_ranges/"
    headers = {
        "x-xdr-auth-id": str(XPANSE_API_KEY_ID),
        "authorization": XPANSE_API_KEY,
    }
    body = {
        "request_data": {
            "search_from": 0,
            "search_to": 10,
            "filters": [
                {"field": "business_units_list", "value": bu_list, "operator": "in"},
            ],
            "sort": {"field": "first_ip", "keyword": "desc"},
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
            f"Retrying Xpanse API IP range endpoint (code {response.status_code}), attempt {retry_count} of {max_retries} (url: {url})"
        )
        time.sleep(time_delay)
        response = requests.post(url=url, headers=headers, json=body, timeout=60)
        retry_count += 1
    # Return results
    if retry_count == max_retries:
        raise Exception("Error: Xpanse API IP range endpoint call failed")
    else:
        response = response.json()
        return response


# --- Retrieve Sector BU Lists ---
def get_xpanse_bu(page_token=None):
    """Get list of all business units and their info."""
    url = "https://api-cisa-xpanse.crtx.gv.paloaltonetworks.com/public_api/v1/assets/get_business_units"
    headers = {
        "x-xdr-auth-id": str(XPANSE_API_KEY_ID),
        "authorization": XPANSE_API_KEY,
    }
    body = {
        "request_data": {
            "search_from": 0,
            "search_to": 1000,
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
    total_ct = 0
    # Make initial call
    ini_resp = get_xpanse_bu()
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

    # If there are more results, keep retrieving
    chunk_ct = 2
    while nxt_page_token is not None:
        print(f"Working on BU chunk {chunk_ct} of {total_ct}")
        resp = get_xpanse_bu(nxt_page_token)
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
    # bu_df.to_excel("", index=False)
    # pprint.pprint(bu_list, sort_dicts=False)
    return bu_df


def get_xpanse_bu_by_name(bu_name):
    """Get list of all business units and their info."""
    url = "https://api-cisa-xpanse.crtx.gv.paloaltonetworks.com/public_api/v1/assets/get_business_units"
    headers = {
        "authorization": XPANSE_API_KEY,
        "x-xdr-auth-id": str(XPANSE_API_KEY_ID),
    }
    body = {
        "request_data": {
            "search_from": 0,
            "search_to": 10,
            "filters": [
                {
                    "field": "business_unit_name",
                    "operator": "eq",
                    "values": [bu_name],
                }
            ],
            "sort": {"field": "business_unit_name", "keyword": "asc"},
            "use_page_token": True,
        }
    }
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


def parse_xpanse_sectors(all_bu_df):
    """Given a datafrane of all BUs create sector lists."""
    all_bu_df = all_bu_df.explode("sectors")
    all_bu_df = all_bu_df.reset_index(drop=True)
    sector_name_dict = {
        "CHEMICAL": "CHEMICAL",
        "COMMERCIAL_FACILITIES": "CML_FAC",
        "COMMUNICATIONS": "COMMS",
        "CRITICAL_MANUFACTURING": "CRIT_MFG",
        "DAMS": "DAMS",
        "DEFENSE_INDUSTRIAL_BASE": "DEF_IND_BASE",
        "ELECTION_INFRASTRUCTURE": "ELECT",
        "EMERGENCY_SERVICES": "EMS",
        "ENERGY": "ENERGY",
        "FINANCIAL_SERVICES": "FIN_SERV",
        "FOOD_AND_AGRICULTURE": "FOOD_AG",
        "GOVERNMENT_FACILITIES": "GOV_FAC",
        "HEALTHCARE_AND_PUBLIC_HEALTH": "HEALTH",
        "INFORMATION_TECHNOLOGY": "INFO_TECH",
        # "NO_SECTOR": "NO_SECTOR",
        "NUCLEAR_REACTORS_MATERIALS_AND_WASTE": "NUCLEAR",
        "TRANSPORTATION_SYSTEMS": "TRANSP_SYS",
        "WATER_AND_WASTEWATER_SYSTEMS": "WATER_SYS",
    }
    # Save each sector to file
    for key in sector_name_dict.keys():
        sector_df = all_bu_df.loc[all_bu_df["sectors"] == key]
        sector_df = sector_df.reset_index(drop=True)
        sector_df.to_excel(
            f"./bu_data/xpanse_bu_list_{sector_name_dict.get(key)}_sector_2025-04-23.xlsx",
            index=False,
        )


# --- Get Xpanse BU sector lists ---
# import ast
# all_bu_df = pd.read_excel("")
# all_bu_df = all_bu_df.loc[:, ~all_bu_df.columns.str.startswith('Unnamed')]
# all_bu_df["entity_type"].fillna("NO_TYPE", inplace=True)
# all_bu_df["sectors"].fillna("['NO_SECTOR']", inplace=True)
# all_bu_df["sectors"] = all_bu_df["sectors"].replace("[]","['NO_SECTOR']")
# all_bu_df["sectors"] = all_bu_df["sectors"].apply(ast.literal_eval)
# parse_xpanse_sectors(all_bu_df)
# sector_files = []


# --- Retrieve Sector Vulnerability Info ---
def get_xpanse_cve_chunk(bu_name, start_date, end_date, page_token=None):
    """Retrieve all services from Xpanse for the specifed business unit."""
    url = "https://api-cisa-xpanse.crtx.gv.paloaltonetworks.com/public_api/v1/assets/get_assets_internet_exposure/"
    headers = {
        "authorization": XPANSE_API_KEY,
        "x-xdr-auth-id": str(XPANSE_API_KEY_ID),
    }
    body = {
        "request_data": {
            "search_from": 0,
            "search_to": 100,
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


def get_xpanse_cves_by_bu(bu_name, start_date, end_date):
    """Retrieve all externally inferred CVEs for the specified BU."""
    total_results_list = []
    nxt_page_token = None
    total_ct = 0
    # Make initial call
    ini_resp = get_xpanse_cve_chunk(bu_name, start_date, end_date)

    total_ct = ini_resp.get("reply").get("total_count")
    nxt_page_token = ini_resp.get("reply").get("next_page_token")
    print(f"Working on BU CVE chunk 1 of {total_ct}")

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
    chunk_ct = 2
    while nxt_page_token is not None:
        print(f"Working on BU CVE chunk {chunk_ct} of {total_ct}")
        resp = get_xpanse_cve_chunk(bu_name, start_date, end_date, nxt_page_token)
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
    return cve_df


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


def sector_stats_cves(sector_vuln_file, sector_org_file, start_idx=None):
    """Retrieve all CVEs for the specified sector."""
    # Create file to save to if it doesn't already exist
    if not os.path.exists(sector_vuln_file):
        print("Save file does not exist, creating it...")
        with open(sector_vuln_file, "w") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "business_unit_name",
                    "domain",
                    "ips",
                    "open_ports",
                    "cve_id",
                    "last_observed",
                    "cvss_version",
                    "cvss_score",
                    "cvss_severity",
                    "kev",
                ]
            )
    else:
        print("Save file already exists, appending data...")

    # Load sector org file
    sector_df = pd.read_excel(sector_org_file, index_col=False)
    if start_idx is not None:
        print(f"*Starting index specified, starting from {start_idx}")
        sector_df = sector_df.iloc[start_idx:]
    else:
        print("No starting index specified, starting from the beginning")

    # bu_cves_list = []
    # Iterate over all BU's in this sector
    for bu_idx, bu in sector_df.iterrows():
        # # testing
        # if bu_idx == 3:
        #     break

        bu_name = bu["business_unit_name"]
        print(
            f'Working on BU "{bu_name}" {bu_idx+1} of {len(sector_df)} (bu_idx={bu_idx})'
        )
        # Retrieve all externally inferred CVEs for this BU
        start_date = datetime.datetime(2025, 5, 1)
        end_date = datetime.datetime(2025, 5, 15)
        bu_cves = get_xpanse_cves_by_bu(
            bu.get("business_unit_name"), start_date, end_date
        )

        # Skip if no CVEs found
        if bu_cves.empty:
            print("*No CVEs found for BU, skipping")
            continue

        # Retrieve CVE info for this BU
        print("Retrieving CVE info for this BU's vulns")
        unique_cves = list(bu_cves["cve_id"].unique())
        cve_info_list = []
        for cve_idx, cve in enumerate(unique_cves):
            try:
                print(f"Working on CVE: {cve} ({cve_idx+1} of {len(unique_cves)})")
                # curr_cve = requests.get(f"https://cvedb.shodan.io/cve/{cve}").json()
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

        # Join BU CVEs DF and CVE info DF, save results
        bu_cve_df = pd.merge(bu_cves, cve_info_df, on="cve_id", how="left")
        bu_cve_df.to_csv(sector_vuln_file, mode="a", index=False, header=False)

    # bu_cves_df = pd.DataFrame(bu_cves_list)

    # # Look up CVSS info for the CVEs
    # unique_cves = list(bu_cves_df["cve_id"].unique())
    # cve_info_list = []
    # for cve_idx, cve in enumerate(unique_cves):
    #     try:
    #         print(f"Working on CVE: {cve} ({cve_idx+1} of {len(unique_cves)})")
    #         # curr_cve = requests.get(f"https://cvedb.shodan.io/cve/{cve}").json()
    #         curr_cve = get_shodan_cve_info(cve)
    #         curr_severity = determine_cve_severity(curr_cve.get("cvss_version"), curr_cve.get("cvss"))
    #         cve_dict = {
    #             "cve_id": cve,
    #             "cvss_version": curr_cve.get("cvss_version"),
    #             "cvss_score": curr_cve.get("cvss"),
    #             "cvss_severity": curr_severity,
    #             "kev": curr_cve.get("kev"),
    #         }

    #         print(type(curr_cve.get("cvss_version")))
    #         print(type(curr_cve.get("cvss")))

    #         cve_info_list.append(cve_dict)
    #     except Exception as e:
    #         print(f"Error: Failed to get info for {cve} - {e}")

    #     # NVD API version
    #     # try:
    #     #     print(f"Working on CVE: {cve} ({idx+1} of {len(unique_cves)})")
    #     #     curr_cve = nvdlib.searchCVE(cveId=cve)
    #     #     cve_dict = {
    #     #         "cve_id": cve,
    #     #         "cvss_version": curr_cve[0].score[0],
    #     #         "cvss_score": curr_cve[0].score[1],
    #     #         "cvss_severity": curr_cve[0].score[2]
    #     #     }
    #     #     cve_info_list.append(cve_dict)
    #     # except Exception as e:
    #     #     print(f"Error: Failed to get info for {cve} - {e}")

    # cve_info_df = pd.DataFrame(cve_info_list)

    # # Join BU CVEs DF and CVE info DF
    # sector_cve_df = pd.merge(bu_cves_df, cve_info_df, on="cve_id", how="left")
    # # Save results
    # # sector_cve_df.to_excel(sector_vuln_file, index=False)
    # sector_cve_df.to_csv(sector_vuln_file, index=False)


def agg_sector_vuln_stats(sector_vuln_file, sector_org_file):
    """Given sector vuln and org files, calculate sector-wide vuln stats."""
    # sector_vulns = pd.read_excel(sector_vuln_file, index_col=False)
    sector_vulns = pd.read_csv(sector_vuln_file, index_col=False)
    full_sector_org_list = pd.read_excel(sector_org_file, index_col=False)[
        ["business_unit_id", "business_unit_name"]
    ]
    # sector_vulns = pd.merge(full_sector_org_list, sector_vulns, on="business_unit_name", how="left")
    # print(sector_vulns["cvss_severity"].unique())
    # sector_vulns.loc[(sector_vulns["cvss_severity"] == "CRITICAL") | (sector_vulns["cvss_severity"] == "HIGH")]

    # total vulns
    sector_total_vulns = pd.merge(
        full_sector_org_list, sector_vulns, on="business_unit_name", how="left"
    )
    sector_total_vulns = (
        sector_total_vulns.groupby("business_unit_name")["cve_id"]
        .count()
        .reset_index(name="count")
    )
    sector_total_vulns = sector_total_vulns.sort_values(
        by="count", ascending=False
    ).reset_index(drop=True)
    avg_total_vulns = sector_total_vulns["count"].mean()
    med_total_vulns = sector_total_vulns["count"].median()
    max_total_vulns = sector_total_vulns["count"].max()
    min_total_vulns = sector_total_vulns["count"].min()
    print(
        f"""
        Total Vulnerabilities
        - Average: {avg_total_vulns}
        - Median: {med_total_vulns}
        - Max: {max_total_vulns}
        - Min: {min_total_vulns}
        """
    )
    # unique vulns
    sector_unique_vulns = pd.merge(
        full_sector_org_list, sector_vulns, on="business_unit_name", how="left"
    )
    sector_unique_vulns = (
        sector_unique_vulns.groupby("business_unit_name")["cve_id"]
        .nunique()
        .reset_index(name="count")
    )
    sector_unique_vulns = sector_unique_vulns.sort_values(
        by="count", ascending=False
    ).reset_index(drop=True)
    avg_unique_vulns = sector_unique_vulns["count"].mean()
    med_unique_vulns = sector_unique_vulns["count"].median()
    max_unique_vulns = sector_unique_vulns["count"].max()
    min_unique_vulns = sector_unique_vulns["count"].min()
    print(
        f"""
        Unique Vulnerabilities
        - Average: {avg_unique_vulns}
        - Median: {med_unique_vulns}
        - Max: {max_unique_vulns}
        - Min: {min_unique_vulns}
        """
    )
    # unique vulns crit/high
    sector_unique_crit_high = sector_vulns.loc[
        (sector_vulns["cvss_severity"] == "CRITICAL")
        | (sector_vulns["cvss_severity"] == "HIGH")
    ]
    sector_unique_crit_high = pd.merge(
        full_sector_org_list,
        sector_unique_crit_high,
        on="business_unit_name",
        how="left",
    )
    sector_unique_crit_high = (
        sector_unique_crit_high.groupby("business_unit_name")["cve_id"]
        .nunique()
        .reset_index(name="count")
    )
    avg_unique_crit_high = sector_unique_crit_high["count"].mean()
    med_unique_crit_high = sector_unique_crit_high["count"].median()
    max_unique_crit_high = sector_unique_crit_high["count"].max()
    min_unique_crit_high = sector_unique_crit_high["count"].min()
    print(
        f"""
        Unique Vulnerabilities CRITICAL/HIGH
        - Average: {avg_unique_crit_high}
        - Median: {med_unique_crit_high}
        - Max: {max_unique_crit_high}
        - Min: {min_unique_crit_high}
        """
    )
    # unique KEVs
    sector_unique_kevs = sector_vulns.loc[(sector_vulns["kev"] == True)]
    sector_unique_kevs = pd.merge(
        full_sector_org_list, sector_unique_kevs, on="business_unit_name", how="left"
    )
    sector_unique_kevs = (
        sector_unique_kevs.groupby("business_unit_name")["cve_id"]
        .nunique()
        .reset_index(name="count")
    )
    sector_unique_kevs = sector_unique_kevs.sort_values(
        by="count", ascending=False
    ).reset_index(drop=True)
    avg_unique_kevs = sector_unique_kevs["count"].mean()
    med_unique_kevs = sector_unique_kevs["count"].median()
    max_unique_kevs = sector_unique_kevs["count"].max()
    min_unique_kevs = sector_unique_kevs["count"].min()
    print(
        f"""
        Unique KEVs
        - Average: {avg_unique_kevs}
        - Median: {med_unique_kevs}
        - Max: {max_unique_kevs}
        - Min: {min_unique_kevs}
        """
    )


# --- Get CVEs for each sector ---
# test_org_list_file = ""
# test_vuln_list_file = ""
# sector_stats_cves(test_vuln_list_file, test_org_list_file)

# --- Aggregate sector vuln stats ---
# sector_vuln_file = ""
# sector_org_file = ""
# agg_sector_vuln_stats(sector_vuln_file, sector_org_file)


# --- Retrieve Sector Protocol Data from Xpanse ---
def get_xpanse_service_chunk(bu_name, start_date, end_date, page_token=None):
    """Retrieve all protocol data from Xpanse for the specifed business unit."""
    url = "https://api-cisa-xpanse.crtx.gv.paloaltonetworks.com/public_api/v1/assets/get_external_services/"
    headers = {
        "authorization": XPANSE_API_KEY,
        "x-xdr-auth-id": str(XPANSE_API_KEY_ID),
    }
    body = {
        "request_data": {
            "search_from": 0,
            "search_to": 100,
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


def get_xpanse_services_by_bu(bu_name, start_date, end_date):
    """Retrieve all protocol data for the specified BU."""
    total_results_list = []
    nxt_page_token = None
    total_ct = 0
    # Make initial call
    ini_resp = get_xpanse_service_chunk(bu_name, start_date, end_date)
    total_ct = ini_resp.get("reply").get("total_count")
    nxt_page_token = ini_resp.get("reply").get("next_page_token")
    print(f"Working on BU service chunk 1 of {total_ct}")

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
    chunk_ct = 2
    while nxt_page_token is not None:
        print(f"Working on BU service chunk {chunk_ct} of {total_ct}")
        resp = get_xpanse_service_chunk(bu_name, start_date, end_date, nxt_page_token)
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

        # if chunk_ct == 3:
        #     break

    # Final formatting
    service_df = pd.DataFrame(total_results_list)
    service_df["last_observed"] = pd.to_datetime(service_df["last_observed"], unit="ms")
    service_df["last_observed"] = service_df["last_observed"].dt.strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    return service_df


def sector_stats_services(sector_service_file, sector_org_file, start_idx=None):
    """Retrieve all service data for the specified sector."""
    # Create file to save to if it doesn't already exist
    if not os.path.exists(sector_service_file):
        print("Save file does not exist, creating it...")
        with open(sector_service_file, "w") as f:
            # read_file = csv.writer(f)
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
                ]
            )
    else:
        print("Save file already exists, appending data...")

    # load sector org file
    sector_df = pd.read_excel(sector_org_file, index_col=False)
    if start_idx is not None:
        print(f"*Starting index specified, starting from {start_idx}")
        sector_df = sector_df.iloc[start_idx:]
    else:
        print("No starting index specified, starting from the beginning")

    # bu_services_list = []
    # Iterate over all BU's in this sector
    for bu_idx, bu in sector_df.iterrows():
        bu_name = bu["business_unit_name"]
        print(
            f'Working on BU "{bu_name}" {bu_idx+1} of {len(sector_df)} (bu_idx={bu_idx})'
        )
        # Retrieve all service data for this BU
        start_date = datetime.datetime(2025, 5, 1)
        end_date = datetime.datetime(2025, 5, 15)
        bu_services = get_xpanse_services_by_bu(
            bu.get("business_unit_name"), start_date, end_date
        )

        # Append this BU's results to file
        if not bu_services.empty:
            # bu_services_list.extend(bu_services.to_dict("records"))
            bu_services.to_csv(sector_service_file, mode="a", index=False, header=False)

    # bu_services_df = pd.DataFrame(bu_services_list)
    # # Save results
    # bu_services_df.to_csv(sector_service_file, index=False)


def agg_sector_service_stats(sector_service_file, sector_org_file):
    """Given sector vuln and org files, calculate sector-wide vuln stats."""
    sector_services = pd.read_csv(sector_service_file, index_col=False)
    full_sector_org_list = pd.read_excel(sector_org_file, index_col=False)[
        ["business_unit_id", "business_unit_name"]
    ]

    # Fix protocol names
    sector_services["service_type"] = sector_services["service_type"].str.replace(
        "Server", "", regex=False
    )
    sector_services["service_type"] = sector_services["service_type"].str.replace(
        "Rpcbind", "Rpc", regex=False
    )
    sector_services["service_type"] = sector_services["service_type"].str.replace(
        "NetBiosName", "NetBios", regex=False
    )
    sector_services["service_type"] = sector_services["service_type"].str.upper()

    # Combine different versions of protocols?

    # distinct_proto = list(sector_services["service_type"].unique())
    # distinct_proto.sort()
    # pprint.pprint(distinct_proto)

    risky_services = {
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
    }
    nmi_services = {
        "RDP",
        "SMB",
        "TELNET",
    }

    # total risky services
    sector_total_risky = sector_services.loc[
        sector_services["service_type"].isin(risky_services)
    ]
    sector_total_risky = pd.merge(
        full_sector_org_list, sector_total_risky, on="business_unit_name", how="left"
    )
    sector_total_risky = (
        sector_total_risky.groupby("business_unit_name")["service_type"]
        .count()
        .reset_index(name="count")
    )
    sector_total_risky = sector_total_risky.sort_values(
        by="count", ascending=False
    ).reset_index(drop=True)
    avg_total_risky = sector_total_risky["count"].mean()
    med_total_risky = sector_total_risky["count"].median()
    max_total_risky = sector_total_risky["count"].max()
    min_total_risky = sector_total_risky["count"].min()
    print(
        f"""
        Total Risky Services
        - Average: {avg_total_risky}
        - Median: {med_total_risky}
        - Max: {max_total_risky}
        - Min: {min_total_risky}
        """
    )

    # unique risky services
    sector_unique_risky = sector_services.loc[
        sector_services["service_type"].isin(risky_services)
    ]
    sector_unique_risky = pd.merge(
        full_sector_org_list, sector_unique_risky, on="business_unit_name", how="left"
    )
    sector_unique_risky = (
        sector_unique_risky.groupby("business_unit_name")["service_type"]
        .nunique()
        .reset_index(name="count")
    )
    sector_unique_risky = sector_unique_risky.sort_values(
        by="count", ascending=False
    ).reset_index(drop=True)
    avg_unique_risky = sector_unique_risky["count"].mean()
    med_unique_risky = sector_unique_risky["count"].median()
    max_unique_risky = sector_unique_risky["count"].max()
    min_unique_risky = sector_unique_risky["count"].min()
    print(
        f"""
        Unique Risky Services
        - Average: {avg_unique_risky}
        - Median: {med_unique_risky}
        - Max: {max_unique_risky}
        - Min: {min_unique_risky}
        """
    )

    # total NMI services
    sector_total_nmi = sector_services.loc[
        sector_services["service_type"].isin(nmi_services)
    ]
    sector_total_nmi = pd.merge(
        full_sector_org_list, sector_total_nmi, on="business_unit_name", how="left"
    )
    sector_total_nmi = (
        sector_total_nmi.groupby("business_unit_name")["service_type"]
        .count()
        .reset_index(name="count")
    )
    sector_total_nmi = sector_total_nmi.sort_values(
        by="count", ascending=False
    ).reset_index(drop=True)
    avg_total_nmi = sector_total_nmi["count"].mean()
    med_total_nmi = sector_total_nmi["count"].median()
    max_total_nmi = sector_total_nmi["count"].max()
    min_total_nmi = sector_total_nmi["count"].min()
    print(
        f"""
        Total NMI Services
        - Average: {avg_total_nmi}
        - Median: {med_total_nmi}
        - Max: {max_total_nmi}
        - Min: {min_total_nmi}
        """
    )

    # unique NMI services
    sector_unique_nmi = sector_services.loc[
        sector_services["service_type"].isin(nmi_services)
    ]
    sector_unique_nmi = pd.merge(
        full_sector_org_list, sector_unique_nmi, on="business_unit_name", how="left"
    )
    sector_unique_nmi = (
        sector_unique_nmi.groupby("business_unit_name")["service_type"]
        .nunique()
        .reset_index(name="count")
    )
    sector_unique_nmi = sector_unique_nmi.sort_values(
        by="count", ascending=False
    ).reset_index(drop=True)
    avg_unique_nmi = sector_unique_nmi["count"].mean()
    med_unique_nmi = sector_unique_nmi["count"].median()
    max_unique_nmi = sector_unique_nmi["count"].max()
    min_unique_nmi = sector_unique_nmi["count"].min()
    print(
        f"""
        Unique NMI Services
        - Average: {avg_unique_nmi}
        - Median: {med_unique_nmi}
        - Max: {max_unique_nmi}
        - Min: {min_unique_nmi}
        """
    )


# --- Get services for each sector ---
# test_org_list_file = ""
# test_service_list_file = ""
# sector_stats_services(test_service_list_file, test_org_list_file)

# --- Aggregate sector service stats ---
# sector_service_file = ("")
# sector_org_file = ("")
# agg_sector_service_stats(sector_service_file, sector_org_file)


# --- Retrieve Sector IP Data from Xpanse ---
def get_xpanse_ip_chunk(bu_name, start_date, end_date, page_token=None):
    """Retrieve all owned IP range data from Xpanse for the specifed business unit."""
    url = "https://api-cisa-xpanse.crtx.gv.paloaltonetworks.com/public_api/v1/assets/get_external_ip_address_ranges/"
    headers = {
        "authorization": XPANSE_API_KEY,
        "x-xdr-auth-id": str(XPANSE_API_KEY_ID),
    }
    body = {
        "request_data": {
            "search_from": 0,
            "search_to": 100,
            "filters": [
                {
                    "field": "business_units_list",
                    "operator": "in",
                    "value": [bu_name],
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
            f"Retrying Xpanse API get owned IP ranges endpoint (code {response.status_code}), attempt {retry_count} of {max_retries} (url: {url})"
        )
        time.sleep(time_delay)
        response = requests.post(url=url, headers=headers, json=body, timeout=60)
        retry_count += 1
    # Return results
    if retry_count == max_retries:
        raise Exception("Error: Xpanse API get owned IP ranges endpoint call failed")
    else:
        response = response.json()
        return response


def get_xpanse_ips_by_bu(bu_name, start_date, end_date):
    """Retrieve all owned IP range data for the specified BU."""
    total_results_list = []
    nxt_page_token = None
    total_ct = 0
    # Make initial call
    ini_resp = get_xpanse_ip_chunk(bu_name, start_date, end_date)
    total_ct = ini_resp.get("reply").get("total_count")
    nxt_page_token = ini_resp.get("reply").get("next_page_token")
    print(f"Working on BU IP chunk 1 of {total_ct}")

    # If no results, move on
    if total_ct == 0:
        print(f"Error: No IP results found for {bu_name}")
        return pd.DataFrame()

    # Parse relevant info
    ip_range_list = ini_resp.get("reply").get("external_ip_address_ranges")
    ip_range_list = [
        {
            k: d[k]
            for k in [
                "range_id",
                "ips_count",
                "active_responsive_ips_count",
                "ipaddress_version",
                "first_ip",
                "last_ip",
                "first_ipv6",
                "last_ipv6",
                "date_added",
            ]
            if k in d
        }
        for d in ip_range_list
    ]
    ip_range_list = [{"business_unit_name": bu_name, **item} for item in ip_range_list]
    total_results_list.extend(ip_range_list)

    # If there are more results, keep retrieving
    chunk_ct = 2
    while nxt_page_token is not None:
        print(f"Working on BU IP chunk {chunk_ct} of {total_ct}")
        resp = get_xpanse_ip_chunk(bu_name, start_date, end_date, nxt_page_token)
        nxt_page_token = resp.get("reply").get("next_page_token")
        # Parse relevant info
        curr_ip_list = resp.get("reply").get("external_ip_address_ranges")
        curr_ip_list = [
            {
                k: d[k]
                for k in [
                    "range_id",
                    "ips_count",
                    "active_responsive_ips_count",
                    "ipaddress_version",
                    "first_ip",
                    "last_ip",
                    "first_ipv6",
                    "last_ipv6",
                    "date_added",
                ]
                if k in d
            }
            for d in ip_range_list
        ]
        curr_ip_list = [
            {"business_unit_name": bu_name, **item} for item in curr_ip_list
        ]
        total_results_list.extend(curr_ip_list)
        chunk_ct += 1

        # if chunk_ct == 3:
        #     break

    # Final formatting
    ip_df = pd.DataFrame(total_results_list)
    ip_df["date_added"] = pd.to_datetime(ip_df["date_added"], unit="ms")
    ip_df["date_added"] = ip_df["date_added"].dt.strftime("%Y-%m-%d %H:%M:%S")
    return ip_df


def sector_stats_ips(sector_ip_file, sector_org_file):
    """Retrieve all IP data for the specified sector."""
    # load sector org file
    sector_df = pd.read_excel(sector_org_file, index_col=False)

    bu_ips_list = []
    # Iterate over all BU's in this sector
    for bu_idx, bu in sector_df.iterrows():
        print(f"Working on BU {bu_idx+1} of {len(sector_df)}")
        # Retrieve all service data for this BU
        start_date = datetime.datetime(2025, 4, 16)
        end_date = datetime.datetime(2025, 4, 30)
        bu_ips = get_xpanse_ips_by_bu(
            bu.get("business_unit_name"), start_date, end_date
        )

        if not bu_ips.empty:
            bu_ips_list.extend(bu_ips.to_dict("records"))

    bu_ips_df = pd.DataFrame(bu_ips_list)

    # Save results
    bu_ips_df.to_csv(sector_ip_file, index=False)


def ip_range_to_list(start_ip, end_ip):
    """Take a start and end IP and generate list of IPs."""
    start = ipaddress.ip_address(start_ip)
    end = ipaddress.ip_address(end_ip)
    result = []
    while start <= end:
        result.append(str(start))
        start += 1
    return result


def ip_range_to_list_row(row):
    """Take a row and convert IP range into list of IPs."""
    start = ipaddress.ip_address(row["start_ip"])
    end = ipaddress.ip_address(row["end_ip"])
    result = []
    while start <= end:
        result.append(str(start))
        start += 1
    return result


def agg_sector_ip_stats(sector_service_file, sector_org_file):
    """Given sector vuln and org files, calculate sector-wide vuln stats."""
    sector_ips = pd.read_csv(sector_service_file, index_col=False)
    full_sector_org_list = pd.read_excel(sector_org_file, index_col=False)[
        ["business_unit_id", "business_unit_name"]
    ]
    print(full_sector_org_list)
    # Convert first/last IPs into IP lists
    test_df = sector_ips.loc[
        sector_ips["business_unit_name"]
        == "Agricultural Research Service - NAL MD [USDA_ARS_NALMD]"
    ]
    print(test_df)
    test_df["ip"] = test_df.apply(ip_range_to_list_row, axis=1)


# --- Get IPs for each sector ---
# test_org_list_file = ""
# test_service_list_file = ""
# sector_stats_ips(test_service_list_file, test_org_list_file)

# --- Aggregate sector IP stats ---
# sector_ip_file = ""
# sector_org_file = ""
# agg_sector_ip_stats(sector_ip_file, sector_org_file)

# test_start = datetime.datetime(2025, 4, 16)
# test_end = datetime.datetime(2025, 4, 30)
# test_ip_df = get_xpanse_ips_by_bu("", test_start, test_end)

# --- Fix Severity Rating in Vuln. Files ---
# def fix_severity_rating(old_file, new_file):
#     """Given the specified vuln file, go back and fix severity ratings."""
#     old_vuln_df = pd.read_excel(old_file)
#     # old_vuln_df = pd.read_csv(old_file)
#     for idx, row in old_vuln_df.iterrows():
#         cvss_ver = row["cvss_version"]
#         cvss_score = row["cvss_score"]
#         old_sev_rting = row["cvss_severity"]
#         new_sev_rting = determine_cve_severity(cvss_ver, cvss_score)
#         print(f"cvss_ver: {cvss_ver}, cvss_score: {cvss_score}")
#         print(f"\told severity: {old_sev_rting}, new severity: {new_sev_rting}")
#         old_vuln_df.at[idx, "cvss_severity"] = new_sev_rting

#     # save results
#     old_vuln_df.to_csv(new_file, index=False)

# old_file = ""
# new_file = ""
# fix_severity_rating(old_file, new_file)
