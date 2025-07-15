"""Scripts for importing Sixgill data into PE Postgres database."""

# Standard Python Libraries
import json
import logging
import time

# Third-Party Libraries
import pandas as pd
import requests

# cisagov Libraries
from pe_source.data.pe_db.config import cybersix_token

from .api import (
    alerts_content,
    alerts_count,
    alerts_list,
    credential_auth,
    dve_top_cves,
    get_bulk_cve_resp,
    intel_post,
    intel_post_next,
    org_assets,
)

LOGGER = logging.getLogger(__name__)


def alerts(org_id, sixgill_org_id):
    """Get actionable alerts for an organization."""
    # Get overall number of alerts for this org
    count = alerts_count(sixgill_org_id)
    count_total = count["total"]
    LOGGER.info(f"Total alerts for {org_id}: {count_total}")

    # Begin Retrieving all alerts
    # - Recommended "fetch_size" is 25. The maximum is 400.
    token = cybersix_token()
    token_refresh_counter = 1
    fetch_size = 10 # 50
    all_alerts = []
    df_all_alerts = pd.DataFrame()
    # Retrieve alert data for each chunk
    for offset in range(0, count_total, fetch_size):
        try:
            print(f"Working on {org_id} alert chunk at offset {offset} out of {count_total}")
            # Make API call
            [resp, token] = alerts_list(token, sixgill_org_id, fetch_size, offset)
            # Process data
            df_alerts = pd.DataFrame.from_dict(resp)
            # df_alerts.drop(columns=["sub_alerts"], inplace=True) # large unused data field
            all_alerts.append(df_alerts)
            df_all_alerts = pd.concat(all_alerts).reset_index(drop=True)
        except Exception as e:
            LOGGER.error(f"Issue fetching alert data chunk at offset: {offset}")
            LOGGER.error(e)
            continue

    # Fetch the full content of each alert
    # for i, r in df_all_alerts.iterrows():
    #     print(r["id"])
    #     content = alerts_content(org_id, r["id"])
    #     df_all_alerts.at[i, "content"] 

    return df_all_alerts


def all_assets_list(org_id):
    """List an organization's aliases."""
    assets = org_assets(org_id)
    df_assets = pd.DataFrame(assets)
    aliases = df_assets["organization_aliases"].loc["explicit":].tolist()[0]
    alias_dict = dict.fromkeys(aliases, "alias")
    domain_names = df_assets["domain_names"].loc["explicit":].tolist()[0]
    domain_dict = dict.fromkeys(domain_names, "domain")
    ips = df_assets["ip_addresses"].loc["explicit":].tolist()[0]
    ip_dict = dict.fromkeys(ips, "ip")
    assets_dict = {**alias_dict, **domain_dict, **ip_dict}
    return assets_dict


def get_alerts_content(organization_id, alert_id, org_assets_dict):
    """Get alert content snippet."""
    token = cybersix_token()
    asset_mentioned = ""
    snip = ""
    asset_type = ""
    content = alerts_content(token, organization_id, alert_id)
    if content:
        for asset, type in org_assets_dict.items():
            if asset in content:
                index = content.index(asset)
                snip = content[(index - 100) : (index + len(asset) + 100)]
                snip = "..." + snip + "..."
                asset_mentioned = asset
                asset_type = type
                LOGGER.info("Asset mentioned: %s", asset_mentioned)
    return snip, asset_mentioned, asset_type


def mentions(org_abbrv, date, aliases, soc_media_included=False):
    """Pull dark web mentions data for an organization."""
    # Build query using the org's aliases
    alias_str = ""
    for alias in aliases:
        alias_str += '"' + alias + '",'
    alias_str = alias_str[:-1]
    if soc_media_included:
        query = f"date:{date} AND (content:({str(alias_str)}) OR title:({str(alias_str)})) AND NOT tags:(Code_script, Credit_card, Cryptocurrency) AND NOT site:(paste_pastebin)"
    else:
        query = f"date:{date} AND (content:({str(alias_str)}) OR title:({str(alias_str)})) AND NOT tags:(Code_script, Credit_card, Cryptocurrency) AND NOT site:(paste_pastebin, twitter, Twitter, reddit, Reddit, Parler, parler, linkedin, Linkedin, discord, forum_discord, raddle, telegram, jabber, ICQ, icq, mastodon)"

    
    # Make initial API call and get the total number of mentions
    token = cybersix_token()
    all_mentions = []
    total_mentions = 0
    try:
        LOGGER.info(f"Retrieving total number of mentions for {org_abbrv}")
        [resp, token] = intel_post(token, query, frm=0, scroll=True, result_size=100)
        total_mentions = resp["total_intel_items"]
        scroll_id = resp["scroll_id"]
    except Exception as e:
        LOGGER.error(f"Total mentions count retrieval failed for {org_abbrv}")
        LOGGER.error(e)
    LOGGER.info(f"Total mentions for {org_abbrv}: {total_mentions}")
    # Catch scenario where org has 0 mentions
    if total_mentions == 0:
        return pd.DataFrame()
    else:
        all_mentions += resp["intel_items"]
    # Fetch all remaining mentions
    token = cybersix_token()
    more_results = True
    idx = 0
    # Keep retrieving until no more results
    while more_results:
        # Progress logging
        if len(all_mentions) % 1000 == 0:
            LOGGER.info(f"Retrieved {len(all_mentions)} of {total_mentions} mentions for {org_abbrv}")
        print(f"Retrieved {len(all_mentions)} of {total_mentions} mentions for {org_abbrv}")
        # Make API call
        [resp, token] = intel_post_next(token, scroll_id)
        intel_items = resp["intel_items"]
        if len(intel_items) != 0:
            # If there are more results, append this chunk
            all_mentions += intel_items
            # Update for variables for next iteration
            scroll_id = resp.get("scroll_id")
            idx += 1
        else:
            # If no more results, stop retrieving
            more_results = False
    # When all mentions retrieved, convert to df and return
    df_all_mentions = pd.DataFrame(all_mentions)
    # Remove mention records where content field is blank
    df_all_mentions = df_all_mentions.loc[~df_all_mentions["content"].isnull()]
    # Add keyword highlights in title and content columns
    aliases = sorted(aliases, key=len)
    for alias in aliases:
        df_all_mentions[["title", "content"]] = df_all_mentions[["title", "content"]].replace(f"(?i){alias}", f"@@mention_start@@{alias}@@mention_end@@", regex=True)
    
    return df_all_mentions


def alias_organization(org_id):
    """List an organization's aliases."""
    assets = org_assets(org_id)
    df_assets = pd.DataFrame(assets)
    aliases = df_assets["organization_aliases"].loc["explicit":].tolist()[0]
    return aliases


def creds(domain, from_date, to_date):
    """Get credentials."""
    token = cybersix_token()
    skip = 0
    params = {
        "domain": domain,
        "from_date": from_date,
        "to_date": to_date,
        "max_results": 100,
        "skip": skip,
    }
    # Retrieve cred data
    [resp, token] = credential_auth(token, params)
    total_hits = resp["total_results"]
    resp = resp["leaks"]
    # Continue retrieving cred data if there's more
    while total_hits > len(resp):
        skip += 1
        params["skip"] = skip
        [next_resp, token] = credential_auth(token, params)
        resp = resp + next_resp["leaks"]
    # Format and return data
    resp = pd.DataFrame(resp)
    df = resp.drop_duplicates(
        subset=["email", "breach_name"], keep="first"
    ).reset_index(drop=True)
    return df


def root_domains(org_id):
    """Get root domains."""
    assets = org_assets(org_id)
    df_assets = pd.DataFrame(assets)
    root_domains = df_assets["domain_names"].loc["explicit":].tolist()[0]
    return root_domains


def top_cves(size):
    """Top 10 CVEs mentioned in the dark web."""
    resp = dve_top_cves()
    return pd.DataFrame(resp)


def extract_bulk_cve_info(cve_list):
    """
    Make API call to C6G and retrieve/extract relevant info for a list of CVE names (10 max).

    Args:
        cve_list: list of cve names (i.e. ['CVE-2022-123', 'CVE-2022-456'...])

    Returns:
        A dataframe with the name and all relevant info for the CVEs listed
    """
    # Call get_bulk_cve_info() function to get response
    resp = get_bulk_cve_resp(cve_list)
    # Check if there was a good response
    if resp is None:
        # If no response, return empty dataframe
        return pd.DataFrame()
    else:
        # Proceed if there is a response
        resp_list = resp.get("objects")
        # Dataframe to hold finalized data
        resp_df = pd.DataFrame()
        # For each cve in api response, extract data
        for i in range(0, len(resp_list)):
            # CVE name
            cve_name = resp_list[i].get("name")
            # CVSS 2.0 info
            cvss_2_info = resp_list[i].get("x_sixgill_info").get("nvd").get("v2")
            if cvss_2_info is not None:
                cvss_2_0 = cvss_2_info.get("current")
                cvss_2_0_sev = cvss_2_info.get("severity")
                cvss_2_0_vec = cvss_2_info.get("vector")
            else:
                [cvss_2_0, cvss_2_0_sev, cvss_2_0_vec] = [None, None, None]
            # CVSS 3.0 info
            cvss_3_info = resp_list[i].get("x_sixgill_info").get("nvd").get("v3")
            if cvss_3_info is not None:
                cvss_3_0 = cvss_3_info.get("current")
                cvss_3_0_sev = cvss_3_info.get("severity")
                cvss_3_0_vec = cvss_3_info.get("vector")
            else:
                [cvss_3_0, cvss_3_0_sev, cvss_3_0_vec] = [None, None, None]
            # DVE info
            dve_info = resp_list[i].get("x_sixgill_info").get("score")
            if dve_info is not None:
                dve_score = dve_info.get("current")
            else:
                dve_score = None

            # Append this row of CVE info to the resp_df
            curr_info = {
                "cve_name": cve_name,
                "cvss_2_0": cvss_2_0,
                "cvss_2_0_severity": cvss_2_0_sev,
                "cvss_2_0_vector": cvss_2_0_vec,
                "cvss_3_0": cvss_3_0,
                "cvss_3_0_severity": cvss_3_0_sev,
                "cvss_3_0_vector": cvss_3_0_vec,
                "dve_score": dve_score,
            }
            resp_df = pd.concat(
                [resp_df, pd.DataFrame(curr_info, index=[0])],
                ignore_index=True,
            )
        # Return dataframe of relevant CVE/CVSS/DVE info
        return resp_df


# def cve_summary(cveid):
#     """Get CVE summary data."""
#     url = f"https://cve.circl.lu/api/cve/{cveid}"
#     return requests.get(url).json()