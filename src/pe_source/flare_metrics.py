"""Scripts to calculate summary metrics for Flare.io."""
# Standard Python Libraries
import datetime
import logging
import os
import pprint
import socket
import time

# Third-Party Libraries
import openpyxl
from openpyxl import load_workbook
import pandas as pd
import platform
import requests
import subprocess
from requests.auth import HTTPBasicAuth
from requests.adapters import HTTPAdapter
import traceback
from urllib3.util.retry import Retry


# cisagov Libraries
# from pe_source.data.flare.flare_helpers import ( 
#     # get_flare_token,
#     get_ident_group_info,
# )
from pe_source.data.pe_db.db_query_source import (
    get_orgs,
)

# Set up logging
LOGGER = logging.getLogger(__name__)

# --- Temporary get_flare_token() funciton For testing purposes ---
API_KEY = ""
API_AUTH = HTTPBasicAuth("", API_KEY)
def get_flare_token():
    """Testing ver of get Flare API authentication token."""
    # Get API token
    token_url = "https://api.flare.io/tokens/generate"  # nosec
    headers = {
        "Content-Type": "application/json",
    }
    data = f'{{"tenant_id": 260075}}'
    resp = requests.post(
        token_url, data=data, headers=headers, auth=API_AUTH, timeout=60
    )
    # Retry clause in case API falters
    retry_count, max_retries, time_delay = 1, 5, 3
    while resp.status_code != 200 and retry_count <= max_retries:
        LOGGER.warning(
            f"\tRetrying Flare token API endpoint (code {resp.status_code}), attempt {retry_count} of {max_retries}"
        )
        time.sleep(time_delay)
        resp = requests.post(
            token_url, data=data, headers=headers, auth=API_AUTH, timeout=60
        )
        retry_count += 1
    # Return results
    if retry_count == max_retries + 1:
        LOGGER.error("Error: Failed to retrieve Flare auth token")
        return None
    else:
        resp = resp.json()
        return resp.get("token")
# --- Temporary get_flare_token() funciton For testing purposes ---


def create_retry_session(retries=5, backoff_factor=1, status_forcelist=(429, 500, 502, 503, 504)):
    """Create a requests Session with automatic retry and backoff logic."""
    session = requests.Session()
    retry_strategy = Retry(
        total=retries, # Max retries across all failure types
        read=retries, # Max retries for read errors
        connect=retries, # Max retries for connection errors
        backoff_factor=backoff_factor, # Delay grows exponentially: <backoff_factor> x 2^(<num_total_retries> - 1))
        status_forcelist=status_forcelist, # Retry on these specific status codes
        allowed_methods=["GET", "POST", "PUT"] # Methods to retry
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

def get_ident_group_info(org_name):
    """Retrieve identifier group info for the specified organization."""
    flare_token = get_flare_token()
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {flare_token}",
    }
    # PE&T parent group id
    group_id = 191286
    # Get the group id for the specified organization
    orgs_url = "https://api.flare.io/firework/v2/assets/groups/"
    orgs_resp = requests.get(orgs_url, headers=headers, timeout=60)
    # Retry clause in case API falters
    retry_count, max_retries, time_delay = 1, 10, 5
    while orgs_resp.status_code != 200 and retry_count <= max_retries:
        LOGGER.warning(
            f"\tRetrying Flare identifier group info API endpoint (code {orgs_resp.status_code}), attempt {retry_count} of {max_retries}"
        )
        time.sleep(time_delay)
        orgs_resp = requests.get(orgs_url, headers=headers, timeout=60)
        retry_count += 1
    # Return results
    if retry_count == max_retries + 1:
        LOGGER.error("Error: Failed to retrieve Flare identifier group info")
        return None
    else:
        orgs_resp = orgs_resp.json()
        orgs_list = orgs_resp.get("assets_groups")
        org_id = [
            o
            for o in orgs_list
            if o["name"] == org_name and o["parent_group_id"] == group_id
        ][0].get("id")
        # Return results
        return {
            "name": org_name,
            "id": org_id,
        }
    
def flare_identifiers_endpoint(token, params):
    """Call the Flare get identifiers endpoint with the specified parameters."""
    # Setup API call
    session = create_retry_session()
    url = "https://api.flare.io/firework/v3/identifiers/"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    # Make API Call
    try:
        response = session.get(url, headers=headers, params=params, timeout=60)
        response.raise_for_status()
        return token, response
    except requests.exceptions.HTTPError as http_err:
        # Catch special token expiry scenario
        if response.status_code == 401:
            return token, response
        print(f"HTTP error occurred: {http_err}")
    except requests.exceptions.ConnectionError as conn_err:
        print(f"Connection error occurred: {conn_err}")
    except requests.exceptions.Timeout as timeout_err:
        print(f"Timeout error occurred: {timeout_err}")
    except requests.exceptions.RequestException as err:
        print(f"Unexpected error occurred: {err}")
    return token, None

def parse_idents(raw_resp):
    """Parse out domain identifiers given raw API response."""
    resp = raw_resp.json()
    # get next token
    next = resp.get("next")
    # get total count
    total_ct = resp.get("total_count")
    # get domains
    ident_list = []
    resp_list = resp.get("items")
    for ident in resp_list:
        domain_dict = {
            "id": ident.get("id"),
            "type": ident.get("type"),
            "value": ident.get("name"),
            "source": ident.get("source"),
            "group_id": ident.get("identifier_group_id"),
            "is_disabled": ident.get("is_disabled"),
            "detected_resolvable": False,
            "detected_reachable": False,
            "detected_responsive": False,
            "required_action": None,
        }
        ident_list.append(domain_dict)
    # Return parsed results
    return {
        "idents": ident_list,
        "next": next,
        "total_count": total_ct,
    }

def get_all_user_assets(group_id):
    """Get Flare user-added assets across all organizations."""
    all_ident_list = []
    chunk_size = 10
    flare_token = get_flare_token()
    next = None
    # Make initial API call
    params = {
        "source_group": "USER",
        "parent_group_id": group_id,
        "size": chunk_size,
    }
    flare_token, ini_resp = flare_identifiers_endpoint(flare_token, params)
    # Parse domain identifiers
    ini_resp_dict = parse_idents(ini_resp)
    next = ini_resp_dict.get("next")
    all_ident_list.extend(ini_resp_dict.get("idents"))
    total_ident_count = ini_resp_dict.get("total_count")
    print(f"Retrieved {len(all_ident_list)} of {total_ident_count} user identifiers")
    # If there's a next value, continue retrieval
    while next is not None:
        # Make API call for this chunk
        curr_params = {
            "from": next,
            "source_group": "USER",
            "parent_group_id": group_id,
            "size": chunk_size,
        }
        flare_token, curr_resp = flare_identifiers_endpoint(flare_token, curr_params)
        # 401 token refresh check
        if curr_resp.status_code == 401:
            LOGGER.warning("401 code encountered, refreshing token")
            flare_token = get_flare_token()
            flare_token, curr_resp = flare_identifiers_endpoint(flare_token, curr_params)
        # Parse domain identifiers
        curr_resp_dict = parse_idents(curr_resp)
        next = curr_resp_dict.get("next")
        all_ident_list.extend(curr_resp_dict.get("idents"))
        print(f"Retrieved {len(all_ident_list)} of {total_ident_count} user identifiers")

        # # TESTING
        # if len(all_ident_list) >= 20:
        #     next = None

    # Return results
    print("All user identifiers retrieved")
    return all_ident_list


def get_all_sys_assets():
    """Get Flare user-added assets across all organizations."""
    all_ident_list = []
    chunk_size = 100
    flare_token = get_flare_token()
    next = None
    # Make initial API call
    params = {
        "source_group": "SYSTEM",
        "size": chunk_size,
    }
    flare_token, ini_resp = flare_identifiers_endpoint(flare_token, params)
    # Parse domain identifiers
    ini_resp_dict = parse_idents(ini_resp)
    next = ini_resp_dict.get("next")
    all_ident_list.extend(ini_resp_dict.get("idents"))
    total_ident_count = ini_resp_dict.get("total_count")
    print(f"Retrieved {len(all_ident_list)} of {total_ident_count} system identifiers")
    # If there's a next value, continue retrieval
    while next is not None:
        # Make API call for this chunk
        curr_params = {
            "from": next,
            "source_group": "SYSTEM",
            "size": chunk_size,
        }
        flare_token, curr_resp = flare_identifiers_endpoint(flare_token, curr_params)
        # 401 token refresh check
        if curr_resp.status_code == 401:
            LOGGER.warning("401 code encountered, refreshing token")
            flare_token = get_flare_token()
            flare_token, curr_resp = flare_identifiers_endpoint(flare_token, curr_params)
        # Parse domain identifiers
        curr_resp_dict = parse_idents(curr_resp)
        next = curr_resp_dict.get("next")
        all_ident_list.extend(curr_resp_dict.get("idents"))
        print(f"Retrieved {len(all_ident_list)} of {total_ident_count} system identifiers")

        # # TESTING
        # if len(all_ident_list) >= 100:
        #     next = None

    # Return results
    print("All system identifiers retrieved")
    return all_ident_list


def calc_pe_org_metrics():
    """Calculate flare metrics for all P&E orgs."""
    # Retrieve list of all orgs
    all_orgs = get_orgs()
    pe_orgs = [d for d in all_orgs if d["report_on"] == True]
    pe_orgs.sort(key=lambda x: x["cyhy_db_name"])
    # Iterate over each org
    results = []
    for idx, org in enumerate(pe_orgs):
        org_abbrv = org.get("cyhy_db_name")
        print(f"Retrieving user ident count for {org_abbrv}")
        curr_org_info = get_ident_group_info(org_abbrv)
        # Get user idents for this org
        curr_user_assets = get_all_user_assets(curr_org_info.get("id"))
        # Parse metrics
        user_df = pd.DataFrame(curr_user_assets)

        org_dict = {
            "organization": org_abbrv,
            "total_user_assets": len(user_df),
            "user_domain_assets": len(user_df.loc[user_df["type"] == "domain"]),
            "user_ip_assets": len(user_df.loc[user_df["type"] == "ip"]),
            "user_keyword_assets": len(user_df.loc[user_df["type"] == "keyword"]),
            "user_person_assets": len(user_df.loc[user_df["type"] == "identity"]),
        }
        results.append(org_dict)
        # if idx == 10:
        #     break

    # Add summary row
    results_df = pd.DataFrame(results)
    summary_dict = {
        "organization": "ALL_ORGS",
        "total_user_assets": results_df["total_user_assets"].sum(),
        "user_domain_assets": results_df["user_domain_assets"].sum(),
        "user_ip_assets": results_df["user_ip_assets"].sum(),
        "user_keyword_assets": results_df["user_keyword_assets"].sum(),
        "user_person_assets": results_df["user_person_assets"].sum(),
    }
    results_df = pd.concat([results_df, pd.DataFrame([summary_dict])], ignore_index=True)
    print(results_df.to_string())
    results_df.to_excel("./src/pe_source/flare_user_assets_breakdown_2026-05-14.xlsx", index=False)
    # total_usr_assets = results_df["num_user_assets"].sum()
    # print(f"Total User Assets in Flare: {total_usr_assets}")


def calc_all_sys_metrics():
    """Calculate flare metrics for all system assets."""
    # sys_asset_list = get_all_sys_assets()
    # sys_asset_df = pd.DataFrame(sys_asset_list)
    # print(sys_asset_df)
    # sys_asset_df.to_excel("./src/pe_source/flare_sys_assets_raw_2026-05-14.xlsx", index=False)

    # Calculate metrics about system assets
    sys_assets_df = pd.read_excel("./src/pe_source/flare_sys_assets_raw_2026-05-14.xlsx", index_col=False, engine="openpyxl")
    sys_assets_df.insert(2, "root_domain", sys_assets_df["value"].str.split(".").str[-2:].str.join("."))
    sys_assets_df.rename(
        columns={
            "id": "asset_id",
            "type": "asset_type",
            "value": "domain",
            "source": "asset_source",
        },
        inplace=True
    )
    sys_assets_df = sys_assets_df[
        [
            "asset_id",
            "asset_type",
            "root_domain",
            "domain",
            "asset_source",
            "group_id",
        ]
    ]
    print(sys_assets_df)
    # print(sys_assets_df["root_domain"].nunique())
    # x=5/0

    agg_df = sys_assets_df.groupby("root_domain").size().reset_index(name="num_auto_enum_subdomains")
    print(agg_df.to_string())
    print(agg_df["num_auto_enum_subdomains"].sum())
    # print(sys_assets_df["source"].unique())


def calc_resp_test_metrics():
    """Caculate metrics for responsiveness test results."""
    test_df = pd.read_csv("./flare_FULL_total_assets_2026-05-19.csv", index_col=False)
    test_df.insert(2, "root_domain", test_df["value"].str.split(".").str[-2:].str.join("."))
    test_df.rename(columns={"value": "domain"}, inplace=True)
    test_df = test_df[[
        "id",
        "source",
        "type",
        "root_domain",
        "domain",
        "ip",
        "curr_enabled",
        "detected_resolvable",
        "detected_reachable",
        "detected_responsive",
        "required_action",
    ]]
    print(test_df[:10].to_string())
    # test_df.to_excel("./flare_sys_assets_responsive_results_2026-05-19.xlsx", index=False)


# calc_resp_test_metrics()
# calc_pe_org_metrics()
# calc_all_sys_metrics()