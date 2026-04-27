"""Scripts to add new organizations to Flare or refresh existing ones so they match the PE DB."""

# Standard Python Libraries
import logging
import os
import string
import time

# Third-Party Libraries
import pandas as pd
import requests
from requests.auth import HTTPBasicAuth

# cisagov Libraries
from pe_source.data.pe_db.config import get_params
from pe_source.data.pe_db.db_query_source import (
    get_execs_by_org_uid,
    get_orgs,
    org_root_domains,
)

# Set up logging
LOGGER = logging.getLogger(__name__)

# Retrieve Flare API credentials
params_section = "flare"
params = get_params(params_section)
tenant_id = params[0][1]
api_key = params[1][1]
api_auth = HTTPBasicAuth("", api_key)


def get_flare_token():
    """Get Flare API authentication token."""
    url = "https://api.flare.io/tokens/generate"
    headers = {
        "Content-Type": "application/json",
    }
    data = f'{{"tenant_id": {tenant_id}}}'
    resp = requests.post(url, data=data, headers=headers, auth=api_auth, timeout=60)
    # Retry clause in case API falters
    retry_count, max_retries, time_delay = 1, 5, 3
    while resp.status_code != 200 and retry_count <= max_retries:
        LOGGER.warning(
            f"\tRetrying Flare token API endpoint (code {resp.status_code}), attempt {retry_count} of {max_retries}"
        )
        time.sleep(time_delay)
        resp = requests.post(url, data=data, headers=headers, auth=api_auth, timeout=60)
        retry_count += 1
    # Return results
    if retry_count == max_retries + 1:
        LOGGER.error("Error: Failed to retrieve Flare token")
        return None
    else:
        resp = resp.json()
        return resp.get("token")


def get_ident_group_info(org_name):
    """Retrieve identifier group info for the specified organization."""
    flare_token = get_flare_token()
    url = "https://api.flare.io/firework/v2/assets/groups/"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {flare_token}",
    }
    resp = requests.get(url, headers=headers, timeout=60)
    # Retry clause in case API falters
    retry_count, max_retries, time_delay = 1, 5, 3
    while resp.status_code != 200 and retry_count <= max_retries:
        LOGGER.warning(
            f"\tRetrying Flare identifier group info API endpoint (code {resp.status_code}), attempt {retry_count} of {max_retries}"
        )
        time.sleep(time_delay)
        resp = requests.get(url, headers=headers, timeout=60)
        retry_count += 1
    # Return results
    if retry_count == max_retries + 1:
        LOGGER.error("Error: Failed to retrieve Flare identifier group info")
        return None
    else:
        # PE&T parent group id
        resp = resp.json()
        group_id = 191286
        orgs_list = resp.get("assets_groups")
        org_id = [
            o
            for o in orgs_list
            if o["name"] == org_name and o["parent_group_id"] == group_id
        ][0].get("id")
        return {
            "name": org_name,
            "id": org_id,
        }


def check_ident_group_exists(org_abbrv):
    """Check if an identifier group already exists for the specified org."""
    flare_token = get_flare_token()
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {flare_token}",
    }
    # PE&T parent group id
    group_id = 191286
    # Check if ident group exists for the specified organization
    orgs_url = "https://api.flare.io/firework/v2/assets/groups/"
    orgs_resp = requests.get(orgs_url, headers=headers, timeout=60)
    # Retry clause in case API falters
    retry_count, max_retries, time_delay = 1, 5, 3
    while orgs_resp.status_code != 200 and retry_count <= max_retries:
        LOGGER.warning(
            f"\tRetrying Flare identifier group exists check API endpoint (code {orgs_resp.status_code}), attempt {retry_count} of {max_retries}"
        )
        time.sleep(time_delay)
        orgs_resp = requests.get(orgs_url, headers=headers, timeout=60)
        retry_count += 1
    # Return results
    if retry_count == max_retries + 1:
        LOGGER.error("Error: Failed to check if Flare identifier group exists")
        return None
    else:
        orgs_resp = orgs_resp.json()
        orgs_list = orgs_resp.get("assets_groups")
        ident_group_results = [
            o
            for o in orgs_list
            if o["name"] == org_abbrv and o["parent_group_id"] == group_id
        ]
        if len(ident_group_results) == 0:
            return False
        else:
            return True


def create_ident_group(org_abbrv):
    """Create a new identifier group for the specified org."""
    flare_token = get_flare_token()
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {flare_token}",
    }
    # PE&T parent group id
    group_id = 191286
    payload = {
        "parent_group_id": group_id,
        "name": org_abbrv,
    }
    # Call endpoint to create identifier group for the org under PE&T
    url = "https://api.flare.io/firework/v2/assets/groups/"
    resp = requests.post(url, json=payload, headers=headers, timeout=60)
    # Retry clause in case API falters
    retry_count, max_retries, time_delay = 1, 5, 3
    while resp.status_code != 200 and retry_count <= max_retries:
        LOGGER.warning(
            f"\tRetrying create Flare identifier group API endpoint (code {resp.status_code}), attempt {retry_count} of {max_retries}"
        )
        time.sleep(time_delay)
        resp = requests.post(url, json=payload, headers=headers, timeout=60)
        retry_count += 1
    if retry_count == max_retries + 1:
        LOGGER.error("Error: Failed to create Flare identifier group")
        return None
    else:
        return resp


def get_ident_by_group_id(ident_group_id):
    """Retrieve all identifiers for the specified group ID."""
    flare_token = get_flare_token()
    url = "https://api.flare.io/firework/v3/identifiers/"
    params = {
        "parent_group_id": ident_group_id,
    }
    headers = {"Authorization": f"Bearer {flare_token}"}
    resp = requests.get(url, headers=headers, params=params, timeout=60)
    # Retry clause in case API falters
    retry_count, max_retries, time_delay = 1, 5, 3
    while resp.status_code != 200 and retry_count <= max_retries:
        LOGGER.warning(
            f"\tRetrying org Flare identifiers API endpoint (code {resp.status_code}), attempt {retry_count} of {max_retries}"
        )
        time.sleep(time_delay)
        resp = requests.get(url, headers=headers, params=params, timeout=60)
        retry_count += 1
    # Return results
    if retry_count == max_retries + 1:
        LOGGER.error("Error: Failed to retrieve org Flare identifiers")
        return None
    else:
        resp = resp.json()
        # Format identifier info
        ident_list = []
        for ident in resp.get("items"):
            ident_id = ident.get("id")
            ident_value = ident.get("name")
            ident_type = ident.get("type")
            ident_dict = {"id": ident_id, "value": ident_value, "type": ident_type}
            ident_list.append(ident_dict)
        if len(ident_list) == 0:
            return [
                {
                    "id": None,
                    "value": None,
                    "type": None,
                }
            ]
        else:
            return ident_list


def get_resp_ips_by_org_abbrv(org_abbrv):
    """Retrieve all responsive attested IPs for the specified organization."""
    # WIP: This info will eventually be stored in the database, not csv
    file_path = os.getcwd() + "/src/pe_source/flare_responsive_ips_2025-08-25.csv"
    resp_ip_df = pd.read_csv(file_path, index_col=False)
    # Locate responsive IPs for this org
    resp_ip_df = resp_ip_df.loc[resp_ip_df["cyhy_db_name"] == org_abbrv].reset_index(
        drop=True
    )
    return resp_ip_df


def format_exec_data(exec_list):
    """Perform additional formatting for executive data for Flare registration."""
    formatted_list = []
    # Iterate over each executive in list
    for exec in exec_list:
        # Split into first and last names
        name_parts = exec.split()
        # Parse first/last name
        name_dict = {
            "first_name": string.capwords(name_parts[0].replace("-", " ")),
            "last_name": string.capwords(name_parts[1].replace("-", " ")),
        }
        formatted_list.append(name_dict)
    # Return formatted executive list
    return formatted_list


def create_flare_identifer(payload):
    """Create an identifier within Flare given the specified payload."""
    flare_token = get_flare_token()
    create_ident_url = "https://api.flare.io/firework/v2/assets/"
    headers = {
        "Authorization": f"Bearer {flare_token}",
        "Content-Type": "application/json",
    }
    resp = requests.post(create_ident_url, json=payload, headers=headers, timeout=60)
    # Retry clause in case API falters
    retry_count, max_retries, time_delay = 1, 5, 3
    while resp.status_code != 200 and retry_count <= max_retries:
        LOGGER.warning(
            f"\tRetrying create Flare identifier API endpoint (code {resp.status_code}), attempt {retry_count} of {max_retries}"
        )
        time.sleep(time_delay)
        resp = requests.post(
            create_ident_url, json=payload, headers=headers, timeout=60
        )
        retry_count += 1
    # Return results
    if retry_count == max_retries + 1:
        LOGGER.error(f"Error: Failed to create Flare identifier - {payload}")


def create_keyword_ident(keyword_list, ident_group_id):
    """Create a new keyword Flare identifier and add it to the specified group."""
    # Iterate over each keyword
    for keyword in keyword_list:
        payload = {
            "assets_group_id": ident_group_id,
            "data": {"keyword": keyword},
            "name": keyword,
            "search_types": ["illicit_networks", "open_web"],
            "type": "keyword",
        }
        # Add keyword to flare
        create_flare_identifer(payload)


def create_domain_ident(domain_list, ident_group_id):
    """Create a new domain Flare identifier and add it to the specified group."""
    # Iterate over each domain
    for domain in domain_list:
        payload = {
            "assets_group_id": ident_group_id,
            "data": {"fqdn": domain},
            "name": domain,
            "search_types": ["illicit_networks", "open_web", "domain", "leak"],
            "type": "domain",
        }
        # Add domain to flare
        create_flare_identifer(payload)


def create_exec_ident(exec_list, ident_group_id):
    """Create a new executive Flare identifier and add it to the specified group."""
    # Iterate over each executive
    for exec in exec_list:
        first_name = exec.get("first_name")
        last_name = exec.get("last_name")
        payload = {
            "assets_group_id": ident_group_id,
            "data": {
                "first_name": first_name,
                "last_name": last_name,
                "is_strict": True,
            },
            "name": f"{first_name} {last_name}",
            "search_types": ["illicit_networks", "open_web"],
            "type": "name",
        }
        # Add executive to flare
        create_flare_identifer(payload)


def create_ip_ident(ip_list, ident_group_id):
    """Create a new IP address Flare identifier and add it to the specified group."""
    # Iterate over each IP
    for ip in ip_list:
        payload = {
            "assets_group_id": ident_group_id,
            "data": {"ip": ip},
            "name": ip,
            "search_types": ["illicit_networks", "open_web"],
            "type": "ip",
        }
        # Add IP to flare
        create_flare_identifer(payload)


def delete_flare_identifier(ident_id):
    """Delete the Flare identifier with the specified id."""
    delete_ident_url = f"https://api.flare.io/firework/v2/assets/{ident_id}"
    flare_token = get_flare_token()
    headers = {
        "Authorization": f"Bearer {flare_token}",
        "Content-Type": "application/json",
    }
    resp = requests.delete(delete_ident_url, headers=headers, timeout=60)
    # Retry clause in case API falters
    retry_count, max_retries, time_delay = 1, 5, 3
    while resp.status_code != 200 and retry_count <= max_retries:
        LOGGER.warning(
            f"\tRetrying delete Flare identifier API endpoint (code {resp.status_code}), attempt {retry_count} of {max_retries}"
        )
        time.sleep(time_delay)
        resp = requests.delete(delete_ident_url, headers=headers, timeout=60)
        retry_count += 1
    # Return results
    if retry_count == max_retries + 1:
        LOGGER.error(f"Error: Failed to delete Flare identifier - {ident_id}")


def delete_ident_list(ident_value_list, ident_df):
    """Delete the specified identifiers from Flare."""
    # Iterate over each identifier
    for val in ident_value_list:
        del_id = ident_df.loc[ident_df["value"] == val, "id"].item()
        # Delete identifier from Flare
        delete_flare_identifier(del_id)


def run_flare_ident_refresh(orgs_list):
    """Update Flare identifiers for the specified new/existing orgs."""
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

    # Update identifiers for each org
    success = 0
    failed = 0
    for org_idx, org in enumerate(pe_orgs_final):
        try:
            org_abbrv = org["cyhy_db_name"]
            org_uid = org["organizations_uid"]
            LOGGER.info(
                f'Updating Flare identifiers for "{org_abbrv}" ({org_idx + 1} of {len(pe_orgs_final)})'
            )

            LOGGER.info("Checking if organization has an identifier group in Flare")
            # Check if org has a folder/identifier group in Flare already
            if not check_ident_group_exists(org_abbrv):
                # If not, create new identifier group folder for the org
                create_ident_group(org_abbrv)
                LOGGER.info(
                    f"New Flare identifier group has been created for {org_abbrv}"
                )
            else:
                LOGGER.info(f"{org_abbrv} already has an identifier group, proceeding")
            # Retrieve this org's identifier group details
            ident_group_info = get_ident_group_info(org_abbrv)

            # Retrieve org's current assets that are in the PE DB
            LOGGER.info(f"Retrieving current PE DB assets for {org_abbrv}")
            org_name = org["name"]
            roots_resp = org_root_domains(org_uid)
            roots_df = pd.DataFrame(roots_resp)
            execs_df = get_execs_by_org_uid(org_uid)
            ips_df = get_resp_ips_by_org_abbrv(
                org_abbrv
            )  # WIP, pulling from CSV currently

            # Retrieve org's current identifiers in Flare
            LOGGER.info(f"Retrieving current flare identifiers for {org_abbrv}")
            group_idents = get_ident_by_group_id(ident_group_info.get("id"))
            group_idents_df = pd.DataFrame(group_idents)

            # Calculating difference between PE DB assets and Flare identifiers
            LOGGER.info("Calculating identifiers that need to be updated")
            # Calculating which keywords (org names) to create/delete
            pe_keywords = {org_name.lower().strip()}
            flare_keywords = group_idents_df[group_idents_df["type"] == "keyword"][
                "value"
            ].to_list()
            flare_keywords = {item.lower().strip() for item in flare_keywords}
            keywords_create = list(pe_keywords - flare_keywords)
            keywords_delete = list(flare_keywords - pe_keywords)
            # Calculating which root domains to create/delete
            pe_roots = roots_df["root_domain"].to_list()
            pe_roots = {item.lower().strip() for item in pe_roots}
            flare_roots = group_idents_df[group_idents_df["type"] == "domain"][
                "value"
            ].to_list()
            flare_roots = {item.lower().strip() for item in flare_roots}
            roots_create = list(pe_roots - flare_roots)
            roots_delete = list(flare_roots - pe_roots)
            # Keep track of multi-part hyphenated first/last executive names
            hyph_dict = {}
            for idx, exec in execs_df.iterrows():
                if ("-" in exec["first_name"]) or ("-" in exec["last_name"]):
                    name_hyphen = exec["first_name"] + " " + exec["last_name"]
                    name_no_hyphen = (
                        exec["first_name"].replace("-", " ")
                        + " "
                        + exec["last_name"].replace("-", " ")
                    )
                    hyph_dict[name_no_hyphen.lower()] = name_hyphen.lower()
            # Calculating which executive names to create/delete
            execs_df["full_name"] = (
                execs_df["first_name"].replace("-", " ", regex=True)
                + " "
                + execs_df["last_name"].replace("-", " ", regex=True)
            ).str.strip()
            pe_execs = execs_df["full_name"].to_list()
            pe_execs = {item.lower().strip() for item in pe_execs}
            flare_execs = group_idents_df[group_idents_df["type"] == "name"][
                "value"
            ].to_list()
            flare_execs = {item.lower().strip() for item in flare_execs}
            execs_create = list(pe_execs - flare_execs)
            execs_delete = list(flare_execs - pe_execs)
            # Replace hyphens for Flare API formatting
            execs_create = [hyph_dict.get(item, item) for item in execs_create]
            execs_delete = [hyph_dict.get(item, item) for item in execs_delete]
            # Calculating which IPs to create/delete
            pe_ips = ips_df["ip"].to_list()  # WIP
            pe_ips = {item.lower().strip() for item in pe_ips}
            flare_ips = group_idents_df[group_idents_df["type"] == "ip"][
                "value"
            ].to_list()
            flare_ips = {item.lower().strip() for item in flare_ips}
            ips_create = list(pe_ips - flare_ips)
            ips_delete = list(flare_ips - pe_ips)

            # Print change summary
            print(f"> Registering {org_abbrv} with Flare. identifier summary:")
            print(f"pe_keywords: {pe_keywords}")
            print(f"flare_keywords: {flare_keywords}")
            print(f"keywords to create: {keywords_create}")
            print(f"keywords to delete: {keywords_delete}\n")
            print(f"pe_roots: {pe_roots}")
            print(f"flare_roots: {flare_roots}")
            print(f"roots to create: {roots_create}")
            print(f"roots to delete: {roots_delete}\n")
            print(f"pe_execs: {pe_execs}")
            print(f"flare_execs: {flare_execs}")
            print(f"execs to create: {execs_create}")
            print(f"execs to delete: {execs_delete}\n")
            print(f"pe_ips (responsive): {pe_ips}")
            print(f"flare_ips: {flare_ips}")
            print(f"ips to create: {ips_create}")
            print(f"ips to delete: {ips_delete}\n")

            # Optional manual input to approve asset refresh before execution
            user_resp = input(
                f"Do you want to continue with asset refresh for {org_abbrv} Y/N?\n"
            )
            if user_resp != "Y":
                print(
                    f"User input: {user_resp}, skipping asset refresh for {org_abbrv}\n"
                )
                continue
            print(
                f"User input: {user_resp}, proceeding with asset refresh for {org_abbrv}\n"
            )

            # Create new identifiers for any assets that need to be added to Flare
            LOGGER.info(
                "Creating identifiers for any assets that need to be added to Flare"
            )
            if len(keywords_create) > 0:
                create_keyword_ident(keywords_create, ident_group_info.get("id"))
            if len(roots_create) > 0:
                create_domain_ident(roots_create, ident_group_info.get("id"))
            if len(execs_create) > 0:
                # Extra formatting for executive data
                execs_create = format_exec_data(execs_create)
                create_exec_ident(execs_create, ident_group_info.get("id"))
            if len(ips_create) > 0:
                create_ip_ident(ips_create, ident_group_info.get("id"))

            # Delete identifiers for any assets that need to be removed from Flare
            LOGGER.info(
                "Deleting identifiers for any assets that need to be removed to Flare"
            )
            if len(keywords_delete) > 0:
                delete_ident_list(keywords_delete, group_idents_df)
            if len(roots_delete) > 0:
                delete_ident_list(roots_delete, group_idents_df)
            if len(execs_delete) > 0:
                delete_ident_list(execs_delete, group_idents_df)
            if len(ips_delete) > 0:
                delete_ident_list(ips_delete, group_idents_df)

            success += 1
            time.sleep(3)
        except Exception as e:
            LOGGER.error(
                f"Error encountered while updating Flare identifiers for {org_abbrv} - {e}"
            )
            failed += 1
            time.sleep(3)

    # Log final summary success/fail statistics
    LOGGER.info(
        f"{success}/{len(pe_orgs_final)} organizations successfully updated Flare identifiers"
    )
    LOGGER.info(
        f"{failed}/{len(pe_orgs_final)} organizations encountered an error while updating Flare identifiers"
    )
