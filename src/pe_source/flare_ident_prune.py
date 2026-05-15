"""Scripts to prune auto-enumerated Flare assets."""

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
from pe_source.data.flare.flare_helpers import ( 
    # get_flare_token,
    get_ident_group_info,
)
from pe_source.data.pe_db.db_query_source import (
    get_orgs,
)

# Set up logging
LOGGER = logging.getLogger(__name__)

# --- Temporary get_flare_token() funciton For testing purposes ---
API_KEY = "fw_hXXnnrBSVLXJCCnZZnsBjenazgLrMNTYqyOXxRlz"
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


def parse_domain_idents(raw_resp):
    """Parse out domain identifiers given raw API response."""
    resp = raw_resp.json()
    # get next token
    next = resp.get("next")
    # get total count
    total_ct = resp.get("total_count")
    # get domains
    domain_list = []
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
        domain_list.append(domain_dict)
    # Return parsed results
    return {
        "domains": domain_list,
        "next": next,
        "total_count": total_ct,
    }


def get_all_autoenum_domains():
    """Get Flare auto-enumerated subdomains across all organizations."""
    all_domain_list = []
    chunk_size = 10 # Max is 100
    flare_token = get_flare_token()
    next = None
    # Make initial API call
    params = {
        "source_group": "SYSTEM",
        "types": ["domain"],
        "size": chunk_size,
    }
    flare_token, ini_resp = flare_identifiers_endpoint(flare_token, params)
    # Parse domain identifiers
    ini_resp_dict = parse_domain_idents(ini_resp)
    next = ini_resp_dict.get("next")
    all_domain_list.extend(ini_resp_dict.get("domains"))
    total_ident_count = ini_resp_dict.get("total_count")
    print(f"Retrieved {len(all_domain_list)} of {total_ident_count} auto-enum identifiers")
    # If there's a next value, continue retrieval
    while next is not None:
        # Make API call for this chunk
        curr_params = {
            "from": next,
            "source_group": "SYSTEM",
            "types": ["domain"],
            "size": chunk_size,
        }
        flare_token, curr_resp = flare_identifiers_endpoint(flare_token, curr_params)
        # 401 token refresh check
        if curr_resp.status_code == 401:
            LOGGER.warning("401 code encountered, refreshing token")
            flare_token = get_flare_token()
            flare_token, curr_resp = flare_identifiers_endpoint(flare_token, curr_params)
        # Parse domain identifiers
        curr_resp_dict = parse_domain_idents(curr_resp)
        next = curr_resp_dict.get("next")
        all_domain_list.extend(curr_resp_dict.get("domains"))
        print(f"Retrieved {len(all_domain_list)} of {total_ident_count} auto-enum identifiers")

        # TESTING
        if len(all_domain_list) >= 20:
            next = None

    # Return results
    print("All auto-enum identifiers retrieved")
    return all_domain_list


def check_domains_responsive(domain_list):
    """Check each domain in list to see if it's resolvable/reachable."""
    results = []
    # Iterate over each domain
    for idx, domain_dict in enumerate(domain_list):
        domain = domain_dict.get("value")
        ident_id = domain_dict.get("id")
        curr_is_disabled = domain_dict.get("is_disabled")
        resolvable = False
        reachable = False
        print(f"Checking responsiveness of domain \"{domain}\" ({idx+1} of {len(domain_list)})")
        # Test if domain has an IP associated with it (resolvable)
        try:
            domain_ip = socket.gethostbyname(domain)
            resolvable = True
        except socket.gaierror:
            domain_ip = None
        # Test if the domain's IP can be connected to (reachable)
        if domain_ip is not None:
            ping_ct = 3
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, str(ping_ct), domain_ip]
            # Attempt to ping IP address
            if subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT) == 0:
                reachable = True
        responsive = resolvable and reachable
        # Calculate if enable/disable action needed
        curr_enabled = not curr_is_disabled
        if curr_enabled and (not responsive):
            # If currently enabled, but detected unresponsive, mark for disabling
            req_action = "DISABLE"
        elif (not curr_enabled) and responsive:
            # If currently disabled, but detected responsive, mark for enabling
            req_action = "ENABLE"
        else:
            req_action = None
        # Update results for this domain
        domain_dict.update(
            {
                "detected_resolvable": resolvable,
                "detected_reachable": reachable,
                "detected_responsive": responsive,
                "required_action": req_action,
            }
        )
    # Return results
    enable_list = [x for x in domain_list if x.get("required_action") == "ENABLE"]
    disable_list = [x for x in domain_list if x.get("required_action") == "DISABLE"]
    return enable_list, disable_list


def toggle_ident(token, ident_id, active=True):
    """Enable or disable the Flare identifier based on specified ID."""
    # Setup API call
    session = create_retry_session()
    url = f"https://api.flare.io/firework/v2/assets/{ident_id}/toggle"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    payload = {"is_disabled": not active}
    # Make API Call
    try:
        response = session.post(url, json=payload, headers=headers, timeout=60)
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


def update_ident_lists(enable_list, disable_list):
    """Enable/Disable the provided lists of Flare identifiers."""
    # Iterate over each identifier in enable list
    if len(enable_list) > 0:
        token = get_flare_token()
        for idx, ident in enumerate(enable_list):
            # Call endpoint to enable indentifier
            curr_ident_id = ident.get("id")
            curr_ident_name = ident.get("value")
            token, resp = toggle_ident(token, curr_ident_id, active=True)
            # 401 token refresh check
            if resp.status_code == 401:
                LOGGER.warning("401 code encountered, refreshing token")
                token = get_flare_token()
                token, resp = toggle_ident(token, curr_ident_id, active=True)
            print(f"Enabled identifier \"{curr_ident_name}\" ({curr_ident_id}) {idx+1} of {len(enable_list)}")
        LOGGER.info("All identifiers marked for re-enabling have been re-enabled")
    else:
        LOGGER.info("No disabled identifiers to re-enable, continuing")
    # Iterate over each identifier in disable list
    if len(disable_list) > 0:
        token = get_flare_token()
        for idx, ident in enumerate(disable_list):
            curr_ident_id = ident.get("id")
            curr_ident_name = ident.get("value")
            # Call endpoint to disable indentifier
            token, resp = toggle_ident(token, curr_ident_id, active=False)
            # 401 token refresh check
            if resp.status_code == 401:
                LOGGER.warning("401 code encountered, refreshing token")
                token = get_flare_token()
                token, resp = toggle_ident(token, curr_ident_id, active=False)
            print(f"Disabled identifier \"{curr_ident_name}\" ({curr_ident_id}) {idx+1} of {len(disable_list)}")
        LOGGER.info("All identifiers marked for disabling have been disabled")
    else:
        LOGGER.info("No enabled identifiers to disable, continuing")


def run_flare_ident_prune(orgs_list):
    """Prune flare auto-enumerated assets."""
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
        for org in orgs_list:
            org_dict = next((d for d in pe_orgs if d["cyhy_db_name"] == org), None)
            pe_orgs_final.append(org_dict)
    # Alphabetize org list for consistent order
    pe_orgs_final = sorted(pe_orgs_final, key=lambda d: d["cyhy_db_name"])

    # Create file for exe time performance logging
    pe_orgs_final_df = pd.DataFrame(pe_orgs_final)
    current_date = datetime.date.today().strftime("%Y-%m-%d")
    first_org = pe_orgs_final_df.iloc[0]["cyhy_db_name"]
    last_org = pe_orgs_final_df.iloc[-1]["cyhy_db_name"]
    exe_time_file = (
        os.path.dirname(os.path.abspath(__file__))
        + f"/exe_time_logs/flare_prune_logs/flare_prune_{current_date}_{first_org}-{last_org}_exe_times.xlsx"
    )
    if not os.path.exists(exe_time_file):
        workbook = openpyxl.Workbook()
        sheet = workbook["Sheet"]
        sheet.append(
            [
                "timestamp",
                "org_abbrv",
                "exe_time",
            ]
        )
        workbook.save(exe_time_file)

    # Begin Flare asset prune
    time_start = time.time()
    try:
        # Retrieve list of all auto-enum assets in Flare
        LOGGER.info("Retrieving all auto-enumerated assets within Flare")

        auto_enum_domains = get_all_autoenum_domains() # actual function

        # For testing purposes:
        # test_domains_df = pd.read_csv("./src/pe_source/flare_test_org_sys_assets_2026-05-08.csv", index_col=False)
        # auto_enum_domains = test_domains_df.to_dict(orient="records")


        LOGGER.info("All auto-enumerated assets retrieved")
        # Check which domains are responsive
        LOGGER.info("Checking which auto-enumerated assets are responsive")
        enable_list, disable_list = check_domains_responsive(auto_enum_domains)

        print(pd.DataFrame(enable_list))
        print(pd.DataFrame(disable_list))
        enable_df = pd.DataFrame(enable_list)
        disable_df = pd.DataFrame(disable_list)
        enable_df.to_csv("./src/pe_source/flare_FULL_enable_assets_2026-05-14.csv", index=False)
        disable_df.to_csv("./src/pe_source/flare_FULL_disable_assets_2026-05-14.csv", index=False)
        # # pprint.pprint(enable_list, sort_dicts=False)
        # # pprint.pprint(disable_list, sort_dicts=False)
        # x=5/0

        # # --- TESTING ---
        # # Testing assets:
        # test_dict = {
        #     "23764933": "dcps.dc.gov",
        #     "23764934": "sso.dc.gov",
        #     "23764935": "osse.dc.gov",
        #     "23764936": "dcratransition.dc.gov",
        #     "23764937": "oig.dc.gov",
        #     "23764939": "ddoe.dc.gov",
        #     "23764940": "microstrategy.dc.gov",
        #     "23764941": "opendata.dc.gov",
        #     "23764942": "joindcps.dc.gov",
        #     "23764944": "cap.dhs.dc.gov",
        # }
        # test_results = []
        # for test_id in list(test_dict.keys()):
        #     test_results.append(get_ident_info(test_id))

        # # Print asset status
        # print(pd.DataFrame(test_results))
        # x=5/0

        # # test demo
        # # demo_issue("TEST_ORG")

        # # test enable/disable
        # test_enable_list = test_results
        # test_disable_list = [] # test_results
        # update_ident_lists(test_enable_list, test_disable_list)
        # x=5/0

        # --- TESTING ---


        LOGGER.info("Auto-enumerated assets have been checked for responsiveness")
        # Enable/Disable the appropriate domains
        LOGGER.info("Enabling/Disabling auto-enumerated assets based on responsiveness")
        print("NOT ACTUALLY UPDATING ASSETS, TESTING ONLY")
        # update_ident_lists(enable_list, disable_list)
        LOGGER.info("Auto-enumerated assets have been enabled/disabled based on responsiveness")
    except Exception as e:
        LOGGER.error(f"Error encountered during Flare pruning script - {e}")
        traceback.print_exc()

    # Write exe time to file
    time_end = time.time()
    org_exe_time = "{:.5f}".format(
        datetime.timedelta(seconds=(time_end - time_start)).total_seconds()
    )
    org_exe_stats = [
        str(datetime.datetime.now()),
        "ALL ORGS",
        org_exe_time,
    ]
    workbook = load_workbook(exe_time_file)
    sheet = workbook["Sheet"]
    sheet.append(org_exe_stats)
    workbook.save(exe_time_file)



# --- TESTING ---
# get_all_autoenum_domains()
# x=5/0

# dc.gov = 23764832
# prune_assets()
# demo_issue(None)
# domain_resp = check_domain_responsive("nasa.gov")
# pprint.pprint(domain_resp, sort_dicts=False)
#
# test_token = get_flare_token()
# test_token = "asdf"
# test_token, test_resp = test_api_handling(test_token, "chat_message/telegram/-1003080746406/245533507584")

# # Check dc.gov status
# test_token = get_flare_token()
# test_token, test_resp = test_api_handling(test_token, "23764832")
# pprint.pprint(test_resp.json())


# test_ident_list = [
#     {
#         "ident_id": "23764832",
#         "domain": "dc.gov",
#         "domain_ip": "123.456.789.1011",
#         "resolvable": False,
#         "reachable": False,
#     }
# ]
# disable_ident_list(test_ident_list)


# 187,608
# 188,230



def get_testing_idents():
    """Get a list of identifier to be used for testing."""
    time_start = time.time()
    test_org_group_id = "586786"
    all_domain_list = []
    chunk_size = 50
    flare_token = get_flare_token()
    next = None
    # Make initial API call
    params = {
        "source_group": "USER",
        "types": ["domain"],
        "size": chunk_size,
        "parent_group_id": test_org_group_id,
    }
    flare_token, ini_resp = flare_identifiers_endpoint(flare_token, params)
    # Parse domain identifiers
    ini_resp_dict = parse_domain_idents(ini_resp)
    next = ini_resp_dict.get("next")
    all_domain_list.extend(ini_resp_dict.get("domains"))
    total_ident_count = ini_resp_dict.get("total_count")
    print(f"Retrieved {len(all_domain_list)} of {total_ident_count} auto-enum identifiers")
    # If there's a next value, continue retrieval
    while next is not None:
        # Make API call for this chunk
        curr_params = {
            "from": next,
            # "source_group": "USER",
            # "types": ["domain"],
            "size": chunk_size,
            # "parent_group_id": test_org_group_id,
        }
        flare_token, curr_resp = flare_identifiers_endpoint(flare_token, curr_params)
        # 401 token refresh check
        if curr_resp.status_code == 401:
            LOGGER.warning("401 code encountered, refreshing token")
            flare_token = get_flare_token()
            flare_token, curr_resp = flare_identifiers_endpoint(flare_token, curr_params)
        # Parse domain identifiers
        curr_resp_dict = parse_domain_idents(curr_resp)
        next = curr_resp_dict.get("next")
        all_domain_list.extend(curr_resp_dict.get("domains"))
        print(f"Retrieved {len(all_domain_list)} of {total_ident_count} auto-enum identifiers")

        # TESTING
        if len(all_domain_list) >= 800:
            next = None

    test_asset_df = pd.DataFrame(all_domain_list)
    test_asset_df = test_asset_df.loc[test_asset_df["source"].isin(["SYSTEM_RELATION"])]
    test_asset_df = test_asset_df.loc[test_asset_df["value"].str.contains("dc.gov")]
    test_asset_df.reset_index(drop=True, inplace=True)
    test_asset_df = test_asset_df[
        [
            "id",
            "type",
            "value",
            "source",
            "group_id",
            "is_disabled",
            
        ]
    ]
    test_asset_df["detected_resolvable"] = False
    test_asset_df["detected_reachable"] = False
    test_asset_df["detected_responsive"] = False
    test_asset_df["required_action"] = None
    # test_asset_df.to_csv("./flare_test_org_sys_assets_2026-05-08.csv", index=False)
    print(test_asset_df)
    time_end = time.time()
    org_exe_time = "{:.5f}".format(
        datetime.timedelta(seconds=(time_end - time_start)).total_seconds()
    )
    print(org_exe_time)
    x=5/0

    

def demo_issue(ident_group_name):
    """Demonstrate issue with Flare identifiers endpoint."""
    # Use API key
    api_key = "fw_hXXnnrBSVLXJCCnZZnsBjenazgLrMNTYqyOXxRlz"
    api_auth = HTTPBasicAuth("", api_key)

    # Retrieve API token
    token_url = "https://api.flare.io/tokens/generate"
    token_headers = {
        "Content-Type": "application/json",
    }
    token_data = f'{{"tenant_id": "260075"}}'
    token_resp = requests.post(
        url=token_url, data=token_data, headers=token_headers, auth=api_auth, timeout=60
    )
    api_token = token_resp.json().get("token")

    # Retrieve identifer group ID
    # ident_group_name = "TEST_ORG"
    ident_group_url = "https://api.flare.io/firework/v2/assets/groups/"
    ident_group_headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_token}",
    }
    ident_group_resp = requests.get(ident_group_url, headers=ident_group_headers, timeout=60)
    ident_group_list = ident_group_resp.json().get("assets_groups")
    ident_group_id = [o for o in ident_group_list if o["name"] == ident_group_name][0].get("id")

    # Retrieve identifiers for the group ID
    ident_url = "https://api.flare.io/firework/v3/identifiers/"
    ident_params = {
        # "source_group": "USER",
        # "types": "domain",
        # "size": 10,
        # "parent_group_id": ident_group_id,
        #
        "from": "WzIzNzY0ODMyXQ",
    }
    ident_headers = {"Authorization": f"Bearer {api_token}"}
    ident_resp = requests.get(ident_url, headers=ident_headers, params=ident_params, timeout=60).json()

    # Print identifiers belonging to the group
    # pprint.pprint(type(ident_resp.get("items")))
    for ident in  ident_resp.get("items"):
        curr_id = ident.get("id")
        curr_name = ident.get("name")
        curr_isdisabled = ident.get("is_disabled")
        print(f"\"{curr_id}\": \"{curr_name}\",")


def get_ident_info(ident_id):
    """Get basic info about an identifier by its ID."""
    # Setup API call
    token = get_flare_token()
    session = create_retry_session()
    url = f"https://api.flare.io/firework/v3/identifiers/{ident_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    # Make API Call
    try:
        response = session.get(url, headers=headers, timeout=60)
        response.raise_for_status()

        pprint.pprint(response.json(), sort_dicts=False)
        x=5/0

        resp = response.json().get("identifier")
        return {
            "ident_id": resp.get("id"),
            "type": resp.get("type"),
            "value": resp.get("name"),
            "source": resp.get("source"),
            "ident_group_id": resp.get("identifier_group_id"),
            "is_disabled": resp.get("is_disabled"),
            "asset_uuid": resp.get("asset_uuid"),
        }
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
    except requests.exceptions.ConnectionError as conn_err:
        print(f"Connection error occurred: {conn_err}")
    except requests.exceptions.Timeout as timeout_err:
        print(f"Timeout error occurred: {timeout_err}")
    except requests.exceptions.RequestException as err:
        print(f"Unexpected error occurred: {err}")
    return None




# test orgs:
# TEST_ORG = 586786
# TEST_ORG_2 = 751677


# test assets:
# test365.cisa.dhs.gov = 8013420
# dc.gov = 23764832
# cap.dhs.dc.gov = 23764944



