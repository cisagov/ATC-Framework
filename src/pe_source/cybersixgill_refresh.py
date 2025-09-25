"""Scripts to refresh the stakeholder assets registered with CyberSixGill."""

import logging
import pandas as pd
import pprint
import requests
import time

from .data.pe_db.db_query_source import (
    get_orgs,
    get_pe_aliases,
    get_pe_cidrs,
    get_pe_execs,
    get_pe_roots,
)

# Cybersixgill API auth
from pe_source.data.pe_db.config import cybersix_token

# Set up logging
LOGGER = logging.getLogger(__name__)

def get_sixgill_id(org_abbrv):
    """Get the cybersixgill ID for the specified organization."""
    # Call Cybersixgill's /organization endpoint to get all organizations
    url = "https://api.cybersixgill.com/multi-tenant/organization"
    auth = cybersix_token()
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": "Bearer " + auth,
    }
    orgs = requests.get(url, headers=headers)
    # Retry clause in case Cybersixgill's API falters
    retry_count, max_retries, time_delay = 0, 10, 3
    while orgs.status_code != 200 and retry_count < max_retries:
        endpoint_name = url.split('/')[-1]
        print(f"Retrying Cybersixgill /{endpoint_name} endpoint (code {orgs.status_code}), attmept {retry_count+1} of {max_retries}")
        time.sleep(time_delay)
        orgs = requests.get(url, headers=headers)
        retry_count += 1
    if orgs.status_code != 200 and retry_count >= max_retries:
        print(f"ERROR: failed calling {endpoint_name}, max retries reached")
        return None
    else:
        orgs = orgs.json()
        df_orgs = pd.DataFrame(orgs)
        df_orgs = df_orgs.loc[df_orgs["name"] == org_abbrv]
        # Return results
        return df_orgs["organization_id"].iloc[0]

def get_sixgill_assets(org_sixgill_id):
    """Get all cybersixgill assets for the specified organization."""
    # Call Cybersixgill's /organization assets endpoint to get all registered assets for an org
    url = f"https://api.cybersixgill.com/multi-tenant/organization/{org_sixgill_id}/assets"
    auth = cybersix_token()
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": "Bearer " + auth,
    }
    assets = requests.get(url, headers=headers)
    # Retry clause in case Cybersixgill's API falters
    retry_count, max_retries, time_delay = 0, 10, 3
    while assets.status_code != 200 and retry_count < max_retries:
        endpoint_name = url.split('/')[-1]
        print(f"Retrying Cybersixgill /{endpoint_name} endpoint (code {assets.status_code}), attmept {retry_count+1} of {max_retries}")
        time.sleep(time_delay)
        assets = requests.get(url, headers=headers)
        retry_count += 1
    if assets.status_code != 200 and retry_count >= max_retries:
        print(f"ERROR: failed calling {endpoint_name}, max retries reached")
        return None
    else:
        assets = assets.json()
        asset_list = []
        # Grab aliases
        if "organization_aliases" in assets:
            for alias in assets.get("organization_aliases").get("explicit"):
                asset_list.append(
                    {
                        "asset_type": "alias",
                        "value": alias,
                    }
                )
        # Grab domains
        if "domain_names" in assets:
            for domain in assets.get("domain_names").get("explicit"):
                asset_list.append(
                    {
                        "asset_type": "domain",
                        "value": domain,
                    }
                )
        # Grab IPs
        if "ip_addresses" in assets:
            for ip in assets.get("ip_addresses").get("explicit"):
                asset_list.append(
                    {
                        "asset_type": "ip",
                        "value": ip,
                    }
                )
        # Grab executives
        if "executives" in assets:
            for exec in assets.get("executives").get("explicit"):
                asset_list.append(
                    {
                        "asset_type": "executive",
                        "value": exec,
                    }
                )
        # Convert to dataframe and return
        return pd.DataFrame(asset_list)
    

def update_sixgill_assets(org_sixgill_id, asset_dict):
    """Modify the cybersixgill assets for the specified organization"""
    # Call Cybersixgill's /organization assets endpoint to modify assets for an org
    url = f"https://api.cybersixgill.com/multi-tenant/organization/{org_sixgill_id}/assets"
    auth = cybersix_token()
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": "Bearer " + auth,
    }
    assets = requests.put(url, headers=headers, json=asset_dict)
    # Retry clause in case Cybersixgill's API falters
    retry_count, max_retries, time_delay = 0, 10, 3
    while assets.status_code != 200 and retry_count < max_retries:
        endpoint_name = url.split('/')[-1]
        print(f"Retrying Cybersixgill /{endpoint_name} endpoint (code {assets.status_code}), attmept {retry_count+1} of {max_retries}")
        time.sleep(time_delay)
        requests.put(url, headers=headers, json=asset_dict)
        retry_count += 1
    if assets.status_code != 200 and retry_count >= max_retries:
        print(f"ERROR: failed calling {endpoint_name}, max retries reached")
        return None
    else:
        print(f"Status code for asset update request: {assets.status_code}")
        print(f"Conent for asset update request: {assets.content}")


def run_cybersixgill_asset_refresh(orgs_list):
    """Refresh the cybersixgill assets for the specified organizations."""
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
                f"Updating CyberSixGill identifiers for \"{org_abbrv}\" ({org_idx + 1} of {len(pe_orgs_final)})"
            )

            # Get current sixgill assets for this org
            LOGGER.info(f"Retrieving current CyberSixGill assets for {org_abbrv}")
            org_csg_id = get_sixgill_id(org_abbrv)
            org_csg_assets = get_sixgill_assets(org_csg_id)
            csg_aliases = set(list(org_csg_assets.loc[org_csg_assets["asset_type"] == "alias"]["value"].str.lower()))
            csg_roots = set(list(org_csg_assets.loc[org_csg_assets["asset_type"] == "domain"]["value"].str.lower()))
            csg_ips = set(list(org_csg_assets.loc[org_csg_assets["asset_type"] == "ip"]["value"]))
            csg_execs = set(list(org_csg_assets.loc[org_csg_assets["asset_type"] == "executive"]["value"].str.lower()))

            # Get current up-to-date P&E assets for this org
            LOGGER.info(f"Retrieving current P&E database assets for {org_abbrv}")
            # Get current org cyhy_db_name/full name
            pe_aliases = get_pe_aliases(org_uid)
            pe_aliases = [pe_aliases.iat[0,0], pe_aliases.iat[0,1]]
            pe_aliases = set([item.lower() for item in pe_aliases])
            # Get current org root domains
            pe_roots = get_pe_roots(org_uid)
            pe_roots = set(list(pe_roots["root_domain"].str.lower()))
            # Get current org IPs/CIDRs
            pe_ips = get_pe_cidrs(org_uid)
            pe_ips = set(list(pe_ips["network"]))
            # Get current org executives (WIP, will be stored in the "executives" table)
            pe_execs = get_pe_execs(org_uid)
            pe_execs = set(list(pe_execs["executive"].str.lower()))

            # Calculate what assets need to be created
            aliases_create = list(pe_aliases - csg_aliases)
            roots_create = list(pe_roots - csg_roots)
            ips_create = list(pe_ips - csg_ips)
            execs_create = list(pe_execs - csg_execs)
            # Calculate what assets need to be deleted
            aliases_delete = list(csg_aliases - pe_aliases)
            roots_delete = list(csg_roots - pe_roots)
            ips_delete = list(csg_ips - pe_ips)
            execs_delete = list(csg_execs - pe_execs)
            # Print update summary
            print(f"\n>>> CyberSixGill Asset Update Summary for: {org_abbrv}")
            print(f"CSG Aliases: {csg_aliases}")
            print(f"PE Alieases: {pe_aliases}")
            print(f"Aliases to Create: {aliases_create}")
            print(f"Aliases to Delete: {aliases_delete}\n")
            print(f"CSG Roots: {csg_roots}")
            print(f"PE Roots: {pe_roots}")
            print(f"Roots to Create: {roots_create}")
            print(f"Roots to Delete: {roots_delete}\n")
            print(f"CSG IPs: {csg_ips}")
            print(f"PE IPs: {pe_ips}")
            print(f"IPs to Create: {ips_create}")
            print(f"IPs to Delete: {ips_delete}\n")
            print(f"CSG Execs: {csg_execs}")
            print(f"PE Execs: {pe_execs}")
            print(f"Execs to Create: {execs_create}")
            print(f"Execs to Delete: {execs_delete}\n")

            # Update assets in Cybersixgill
            LOGGER.info(f"Updating assets in CyberSixGill to align with P&E database for {org_abbrv}")
            asset_update_dict = {
                "organization_aliases": {
                    "explicit": list(pe_aliases),
                },
                "domain_names": {
                    "explicit": list(pe_roots),
                },
                # Warning: Could encounter issues with orgs that have a lot of IP addresses
                "ip_addresses": {
                    "explicit": list(pe_ips),
                },
                "executives": {
                    "explicit": list(pe_execs),
                },
            }
            update_sixgill_assets(org_csg_id, asset_update_dict)
            LOGGER.info(f"Sucessfully updated CyberSixGill assets for {org_abbrv}")
            success += 1
        except Exception as e:
            LOGGER.error(f"Error encountered while updating CyberSixGill assets for {org_abbrv} - {e}")
            failed += 1

    # Log summary success/fail statistics
    LOGGER.info(
        f"{success}/{len(pe_orgs_final)} organizations successfully updated CyberSixGill assets"
    )
    LOGGER.info(
        f"{failed}/{len(pe_orgs_final)} organizations encountered an error while updating CyberSixGill assets"
    )

