"""Scripts to collect data and findings from Flare."""

import pprint # testing

# Imports
import datetime
import logging
import pandas as pd
import requests
from requests.auth import HTTPBasicAuth
import time

from .data.pe_db.config import get_params
from .data.pe_db.db_query_source import (
    get_orgs,
    insert_flare_events,
    insert_shodan_top_cves,
    query_all_shodan_cves,
)

# Set up logging
LOGGER = logging.getLogger(__name__)

# Calculate start and end dates for data collection period
TODAY = datetime.date.today()
DAYS_BACK = datetime.timedelta(days=30)
START_DATE = (TODAY - DAYS_BACK).strftime("%Y-%m-%d")
END_DATE = TODAY.strftime("%Y-%m-%d")

# Retrieve Flare API credentials
params_section = "flare"
params = get_params(params_section)
tenant_id = params[0][1]
api_key = params[1][1]
api_auth = HTTPBasicAuth('', api_key)


def get_flare_token():
    """Get Flare API authentication token."""
    token_url = "https://api.flare.io/tokens/generate"
    headers = {
        "Content-Type": "application/json",
    }
    data = f'{{"tenant_id": {tenant_id}}}'
    resp = requests.post(token_url, data=data, headers=headers, auth=api_auth).json()
    return resp.get("token")

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
    orgs_resp = requests.get(orgs_url, headers=headers).json()
    orgs_list = orgs_resp.get("assets_groups")
    org_id = [o for o in orgs_list if o["name"] == org_name and o["parent_group_id"] == group_id][0].get("id")
    # Return results
    return {
        "name": org_name,
        "id": org_id,
    }

def get_ident_by_group_id(ident_group_id):
    """Retrieve all identifiers for the specified group ID."""
    flare_token = get_flare_token()
    url = "https://api.flare.io/firework/v3/identifiers/"
    params = {
        "parent_group_id": ident_group_id,
    }
    headers = {"Authorization": f"Bearer {flare_token}"}
    resp = requests.get(url, headers=headers, params=params).json()
    # Format identifier info
    ident_list = []
    for ident in resp.get("items"):
        ident_id = ident.get("id")
        ident_value = ident.get("name")
        ident_type = ident.get("type")
        ident_dict = {
            "id": ident_id,
            "value": ident_value,
            "type": ident_type
        }
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
    
def get_ident_group_events_chunk(token, ident_group_id, payload):
    """Call the Flare identifier group event feed endpoint."""
    headers = {
        "Content-Type": "application/json",
        'Authorization': f'Bearer {token}',
    }
    url = f"https://api.flare.io/firework/v4/events/identifier_groups/{ident_group_id}/_search"
    resp = requests.post(url, headers=headers, json=payload)
    # Retry clause in case API falters
    retry_count, max_retries, time_delay = 1, 5, 3
    while resp.status_code != 200 and retry_count <= max_retries:
        LOGGER.warning(f"\tRetrying Flare event retrieval API endpoint (code {resp.status_code}), attempt {retry_count} of {max_retries}")
        time.sleep(time_delay)
        resp = requests.post(url, headers=headers, json=payload)
        retry_count += 1
    # Return results
    if retry_count == max_retries:
        LOGGER.error(f"Error: Failed to retrieve Flare events for {ident_group_id}")
        return None
    else:
        # Print stats
        resp = resp.json()
        num_items = len(resp.get("items"))
        more_data = False
        if resp.get("next"):
            more_data = True
        print(f"\tChunk retrieved, contained {num_items} items")
        print(f"\tIs there another chunk to retrieve? {more_data}")
        # Return results
        return resp

def get_ident_group_events(identifier_group, event_types, start_date, end_date):
    """Retrieve all events for the specified identifier group (organization)."""
    ident_group_name = identifier_group.get("name")
    ident_group_id = identifier_group.get("id")
    print(f"Retrieving all events for the identifier group: {ident_group_name}")
    flare_token = get_flare_token()
    results_list = []
    more_data = False
    curr_next = ""
    chunk_size = 10
    # Make initial data feed call
    print(f"Working on data feed chunk 1")
    ini_payload = {
        "size": chunk_size,
        "filters": {
            "type": event_types,
            "estimated_created_at": {
                "gte": start_date,
                "lte": end_date,
            }
        }
    }
    ini_resp = get_ident_group_events_chunk(flare_token, ident_group_id, ini_payload)
    results_list += ini_resp.get("items")
    # Check if there's any more data to retrieve
    if ini_resp.get("next"):
        more_data = True
        curr_next = ini_resp.get("next")
    # If there's a next value, continue fetching data
    retrieve_ct = 2
    while more_data:
        time.sleep(1)
        print(f"Working on data feed chunk {retrieve_ct}")
        # Make API call for current chunk
        curr_payload = {
            "size": chunk_size,
            "from": curr_next,
            "filters": {
                "type": event_types,
                "estimated_created_at": {
                    "gte": start_date,
                    "lte": end_date,
                }
            }
        }
        curr_resp = get_ident_group_events_chunk(flare_token, ident_group_id, curr_payload)
        # Append results
        results_list += curr_resp.get("items")
        # Check if there's anymore data to retrieve
        if curr_resp.get("next"):
            # If there's more data, update next value
            curr_next = curr_resp.get("next")
        else:
            # If no next value, there's no more data to retrieve
            more_data = False
        retrieve_ct +=1
    # Once all data has been retrieved, return results
    results_list = [
        {
            "event_uid": item.get("metadata").get("uid"),
            "event_type": item.get("metadata").get("type"),
            "identifiers": item.get("identifiers"),
            "event_date": item.get("metadata").get("estimated_created_at"),
        } for item in results_list
    ]
    print(f"Total number of items retrieved for all identifiers: {len(results_list)}")
    return results_list

def get_event_details(event_uid, token):
    """Get additional details for the specified Flare event uid.""" 
    event_detail_url = f"https://api.flare.io/firework/v2/activities/{event_uid}"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    resp = requests.get(event_detail_url, headers=headers)
    # Retry clause in case API falters
    retry_count, max_retries, time_delay = 1, 5, 3
    while resp.status_code != 200 and retry_count <= max_retries:
        LOGGER.warning(f"\tRetrying Flare event detail API endpoint (code {resp.status_code}), attempt {retry_count} of {max_retries}")
        time.sleep(time_delay)
        resp = requests.get(event_detail_url, headers=headers)
        retry_count += 1
    # Return results
    if retry_count == max_retries:
        LOGGER.error(f"Error: Failed to retrieve Flare event details for {event_uid}")
        return None
    else:
        # Return results
        return resp.json()

def get_all_event_details(event_list, org_uid):
    """Retrieve the full set of details for each of the specified events."""
    flare_token = get_flare_token()
    # Iterate over each event
    total_event_list = []
    for idx, event in enumerate(event_list):
        # Retrieve further details for event
        event_uid = event.get("event_uid")
        event_type = event.get("event_type")
        event_details = get_event_details(event_uid, flare_token)
        event.update({"event_date": event.get("event_date")[:10]})

        # Format event details for the database, varies based on event type
        print(f"Retrieved details for event {idx+1} of {len(event_list)} - Type: {event_type}")
        # Parse social media post mention data
        if event_type in (
            "social_media", 
            "social_media_account",
        ):
            # Note: Very few results for "social_media"/"social_media_account"
            # Format social media post data
            soc_med_post_dict = parse_soc_media_post_event(event, event_details, org_uid)
            # Append record
            total_event_list.append(soc_med_post_dict)
        # Parse darkweb post mention data
        if event_type in (
            "blog_post",
            "forum_post",
        ):
            # Format darkweb post data
            darkweb_post_dict = parse_darkweb_post_event(event, event_details, org_uid) # in progress
            # Append record
            total_event_list.append(darkweb_post_dict)
        # Parse potential-threat/asset "alert" data
        if event_type in (
            "bot", # from infected_devices
            "leak",
            "ransomleak",
            "stealer_log", # from infected_devices
        ):
            # parse event
            if event_type == "bot":
                # Format bot event data
                potential_threat_alert_dict = parse_bot_event(event, event_details, org_uid)
            elif event_type == "leak":
                # Format leak event data
                potential_threat_alert_dict = parse_leak_event(event, event_details, org_uid) # updated
            elif event_type == "ransomleak":
                # Format ransomleak event data
                potential_threat_alert_dict = parse_ransomleak_event(event, event_details, org_uid)
            elif event_type == "stealer_log":
                # Format stealer_log event data
                potential_threat_alert_dict = parse_stealer_log_event(event, event_details, org_uid)
            # Append record
            total_event_list.append(potential_threat_alert_dict)
        # Parse invite-only market alert data
        if event_type in (
            "listing", 
            "seller",
        ):
            # Notes: Essentially no results for "seller"
            # parse event
            if event_type == "listing":
                # Format listing event data
                inv_market_alert_dict = parse_inv_market_event(event, event_details, org_uid)
            # Append record
            total_event_list.append(inv_market_alert_dict)

    # Return parsed event detail data
    return total_event_list

def parse_related_identifiers(event):
    """Parse identifiers related to this event for use in SQL query."""
    identifier_list_str = "ARRAY["
    for identifier in event.get("identifiers"):
        ident_id = identifier.get("id")
        identifier_list_str += f"'{ident_id}', "
    identifier_list_str = identifier_list_str[:-2] + "]"
    return identifier_list_str

def parse_soc_media_post_event(event, event_details, org_uid):
    """Parse and format data for social media post events."""
    event_details = event_details.get("activity")
    return {
        "organizations_uid": org_uid,
        "flare_uid": event.get("event_uid"),
        "event_type": event.get("event_type"),
        "event_date": event.get("event_date"),
        "collection_date": datetime.datetime.now().strftime("%Y-%m-%d"),
        "title": event_details.get("header").get("title"),
        "content": event_details.get("data").get("content"), # *different
        "content_hash": event_details.get("header").get("content_hash"),
        "actor": event_details.get("header").get("actor"),
        "category": event_details.get("header").get("category_name"),
        "source": event_details.get("metadata").get("source"), # (source ~= site for mentions)
        "url": event_details.get("data").get("url"),
        "risk_scores": event_details.get("header").get("risk"),
        "related_identifiers": parse_related_identifiers(event),
        "data_source_uid": "751a4ff4-ac0c-11ef-8c7d-02527bfc647f",
    }

def parse_darkweb_post_event(event, event_details, org_uid):
    """Parse and format data for darkweb post events."""
    event_details = event_details.get("activity")
    return {
        "organizations_uid": org_uid,
        "flare_uid": event.get("event_uid"),
        "event_type": event.get("event_type"),
        "event_date": event.get("event_date"),
        "collection_date": datetime.datetime.now().strftime("%Y-%m-%d"),
        "title": event_details.get("header").get("title"),
        "content": event_details.get("data").get("content"), # *different
        "content_hash": event_details.get("header").get("content_hash"),
        "actor": event_details.get("header").get("actor"),
        "category": event_details.get("header").get("category_name"),
        "source": event_details.get("metadata").get("source"), # (source ~= site for mentions)
        "url": event_details.get("data").get("url"),
        "risk_scores": event_details.get("header").get("risk"),
        "related_identifiers": parse_related_identifiers(event),
        "data_source_uid": "751a4ff4-ac0c-11ef-8c7d-02527bfc647f",
    }

def parse_leak_event(event, event_details, org_uid):
    """Parse and format data for leak events."""
    event_details = event_details.get("activity")
    return {
        "organizations_uid": org_uid,
        "flare_uid": event.get("event_uid"), 
        "event_type": event.get("event_type"), 
        "event_date": event.get("event_date"), 
        "collection_date": datetime.datetime.now().strftime("%Y-%m-%d"),
        "title": event_details.get("header").get("title"), 
        "content": event_details.get("header").get("content_preview"), # adjusted, iffy leak_source?
        "content_hash": event_details.get("header").get("content_hash"),
        "actor": event_details.get("header").get("actor"), 
        "category": event_details.get("header").get("category_name"), 
        "source": event_details.get("metadata").get("source"), 
        "url": event_details.get("data").get("url"), 
        "risk_scores": event_details.get("header").get("risk"), 
        "related_identifiers": parse_related_identifiers(event), 
        "data_source_uid": "751a4ff4-ac0c-11ef-8c7d-02527bfc647f", 
    }

def parse_ransomleak_event(event, event_details, org_uid):
    """Parse and format data for ransomleak events."""
    event_details = event_details.get("activity")
    return {
        "organizations_uid": org_uid,
        "flare_uid": event.get("event_uid"),  
        "event_type": event.get("event_type"), 
        "event_date": event.get("event_date"), 
        "collection_date": datetime.datetime.now().strftime("%Y-%m-%d"), 
        "title": event_details.get("header").get("title"), 
        "content": event_details.get("header").get("content_preview"), # adjusted, iffy
        "content_hash": event_details.get("header").get("content_hash"),
        "actor": event_details.get("header").get("actor"),
        "category": event_details.get("header").get("category_name"), 
        "source": event_details.get("metadata").get("source"), 
        "url": event_details.get("data").get("url"), 
        "risk_scores": event_details.get("header").get("risk"), 
        "related_identifiers": parse_related_identifiers(event), 
        "data_source_uid": "751a4ff4-ac0c-11ef-8c7d-02527bfc647f",
    }

def parse_stealer_log_event(event, event_details, org_uid):
    """Parse and format data for stealer_log events."""
    # Create custom content string
    content_str = f"A stealer log has been offered for sale." # break credentials into content records?
    event_details = event_details.get("activity")
    return {
        "organizations_uid": org_uid,
        "flare_uid": event.get("event_uid"), 
        "event_type": event.get("event_type"), 
        "event_date": event.get("event_date"), 
        "collection_date": datetime.datetime.now().strftime("%Y-%m-%d"), 
        "title": event_details.get("header").get("title"), 
        "content": event_details.get("header").get("content_preview"), # adjusted, iffy
        "content_hash": event_details.get("header").get("content_hash"),
        "actor": event_details.get("header").get("actor"), 
        "category": event_details.get("header").get("category_name"), 
        "source": event_details.get("metadata").get("source"), 
        "url": event_details.get("data").get("url"), 
        "risk_scores": event_details.get("header").get("risk"), 
        "related_identifiers": parse_related_identifiers(event), 
        "data_source_uid": "751a4ff4-ac0c-11ef-8c7d-02527bfc647f", 
    }

def parse_bot_event(event, event_details, org_uid):
    """Parse and format data for bot events."""
    # Create custom content string
    content_str = f"A device has potentially been infected by botnet malware and the data stolen from it has been offered for sale."
    event_details = event_details.get("activity")
    return {
        "organizations_uid": org_uid,
        "flare_uid": event.get("event_uid"),  
        "event_type": event.get("event_type"), 
        "event_date": event.get("event_date"), 
        "collection_date": datetime.datetime.now().strftime("%Y-%m-%d"), 
        "title": event_details.get("header").get("title"), 
        "content": event_details.get("header").get("content_preview"), # adjusted, iffy
        "content_hash": event_details.get("header").get("content_hash"),
        "actor": event_details.get("header").get("actor"), 
        "category": event_details.get("header").get("category_name"), 
        "source": event_details.get("metadata").get("source"), 
        "url": event_details.get("data").get("url"), 
        "risk_scores": event_details.get("header").get("risk"), 
        "related_identifiers": parse_related_identifiers(event), 
        "data_source_uid": "751a4ff4-ac0c-11ef-8c7d-02527bfc647f",
    }

def parse_inv_market_event(event, event_details, org_uid):
    """Parse and format data for invite only market events."""
    event_details = event_details.get("activity")
    return {
        "organizations_uid": org_uid,
        "flare_uid": event.get("event_uid"),
        "event_type": event.get("event_type"), 
        "event_date": event.get("event_date"), 
        "collection_date": datetime.datetime.now().strftime("%Y-%m-%d"),
        "title": event_details.get("header").get("title"), 
        "content": event_details.get("header").get("content_preview"), # adjusted, iffy
        "content_hash": event_details.get("header").get("content_hash"),
        "actor": event_details.get("header").get("actor"), 
        "category": event_details.get("header").get("category_name"), 
        "source": event_details.get("metadata").get("source"), 
        "url": event_details.get("data").get("url"), 
        "risk_scores": event_details.get("header").get("risk"), 
        "related_identifiers": parse_related_identifiers(event), 
        "data_source_uid": "751a4ff4-ac0c-11ef-8c7d-02527bfc647f",
    }


def run_flare(orgs_list):
    """Retrieve Flare data for the specified list of organizations and insert into the PE DB."""
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
    # Alphabetize org list for consistent order
    pe_orgs_final = sorted(pe_orgs_final, key=lambda d: d["cyhy_db_name"])

    # Specify which event types to collect
    event_types = [
        # Mention Data:
        "social_media", # non-existant
        "forum_post", # common
        "blog_post", # rare
        # Alert Data:
        # "infected_devices", # very common, lots of results - specifically from stealer_logs
        "leaks", # somewhat common
        "ransomleak", # moderate results
        "listing", # somewhat common
        "seller", # non-existant,
    ]
    # Run Flare data collection on each org
    LOGGER.info(f"Gathering Flare event data of the following types: {event_types}")
    start_date = START_DATE
    end_date = END_DATE
    success = 0
    failed = 0
    for org_idx, org in enumerate(pe_orgs_final):
        try:
            org_abbrv = org["cyhy_db_name"]
            org_uid = org["organizations_uid"]
            LOGGER.info(
                f"Running Flare on \"{org_abbrv}\" ({org_idx + 1} of {len(pe_orgs_final)})"
            )
            # Retrieve identifier group info for this org
            ident_group_info = get_ident_group_info(org_abbrv)
            # Retrieve all Flare events for this org
            LOGGER.info(f"Retrieving all Flare events for {org_abbrv}")
            event_list = get_ident_group_events(ident_group_info, event_types, start_date, end_date)
            # Retrieve further details for the events and format
            LOGGER.info(f"Retrieving additional details for {org_abbrv}'s events")
            final_event_list = get_all_event_details(event_list, org_uid)
            # Extra formatting to handle special characters in certain fields
            for event in final_event_list:
                event.update(
                    {
                        "content": event.get("content").replace("'", "''"),
                        "risk_scores": str(event.get("risk_scores")).replace("'", "''"),
                    }
                )
            final_event_df = pd.DataFrame(final_event_list)
            final_event_df.drop_duplicates(inplace=True)
            final_event_list = final_event_df.to_dict(orient="records")
            # Insert Flare data into PE DB
            LOGGER.info(f"Inserting Flare event data for {org_abbrv} into the PE database")
            if len(final_event_list) > 0:
                insert_flare_events(final_event_list)
                LOGGER.info(f"Flare events for {org_abbrv} successfully inserted into PE database")
            else:
                LOGGER.info(f"No Flare events for {org_abbrv} to insert, proceeding")
            success += 1
        except Exception as e:
            LOGGER.error(f"Error encountered during Flare scan for {org_abbrv} - {e}")
            failed += 1
            
    # Log overall success/fail statistics
    LOGGER.info(
        f"{success}/{len(pe_orgs_final)} organizations successfully completed their Flare scan"
    )
    LOGGER.info(
        f"{failed}/{len(pe_orgs_final)} organizations encountered an error during their Flare scan"
    )

def get_shodan_cve_info(cve):
        """Retrieve info about the specified CVE from Shodan's API."""
        url = f"https://cvedb.shodan.io/cve/{cve}"
        resp = requests.get(url)
        # Retry clause in case API falters
        retry_count, max_retries, time_delay = 1, 10, 3
        while resp.status_code != 200 and retry_count <= max_retries:
            LOGGER.warning(f"\tRetrying Shodan CVE info API endpoint (code {resp.status_code}), attempt {retry_count} of {max_retries}")
            time.sleep(time_delay)
            resp = requests.get(url)
            retry_count += 1
        # Return results
        if retry_count == max_retries:
            LOGGER.error(f"Error: Failed to retrieve Shodan CVE info for {cve}")
            return None
        else:
            return resp.json()
        
def get_cve_details(cve_list):
        """Retrieve details for the specified list of CVEs."""
        cve_detail_list = []
        for idx, cve in enumerate(cve_list):
            # Call shodan API to grab CVE info
            print(f"Retrieving CVE details for {cve} ({idx+1} of {len(cve_list)})")
            cve_details = get_shodan_cve_info(cve)
            epss = round(cve_details.get("epss") * 100, 2)
            cvss_v2 = cve_details.get("cvss_v2")
            cvss_v3 = cve_details.get("cvss_v3")
            summary = cve_details.get("summary")
            # Parse relevant details
            cve_detail_dict = {
                "cve_id": cve,
                "epss": epss,
                "nvd_base_score": f"{{'v2': {cvss_v2}, 'v3': {cvss_v3}}}",
                "date": TODAY.strftime("%Y-%m-%d"),
                "summary": summary,
                "data_source_uid": "763eb880-981d-11ec-a100-02589a36c9d7"
            }
            # Append CVE details
            cve_detail_list.append(cve_detail_dict)
        # Return as dataframe
        return pd.DataFrame(cve_detail_list)

def run_top_cves_shodan():
    """Get the top 10 CVEs by EPSS score amongst all distinct CVEs detected across all stakeholders for the report period."""
    # Retrieve list of all distinct CVEs detected in the past report period across all organizations
    end_date = TODAY.strftime("%Y-%m-%d")
    report_period_back = datetime.timedelta(days=15)
    start_date = (TODAY - report_period_back).strftime("%Y-%m-%d")
    all_cves = query_all_shodan_cves(start_date, end_date)
    LOGGER.info("Retrieved list of all distinct CVEs detected by Shodan across all stakeholders for the past report period")
    # Get further details for each CVE using shodan's API
    all_cve_details = get_cve_details(list(all_cves["cve"]))
    LOGGER.info("Retrieved details for all distinct CVEs")
    # Sort CVEs by EPSS score
    all_cve_details = all_cve_details.sort_values(by="epss", ascending=False).reset_index(drop=True)
    # Grab the top 10 CVEs with the highest EPSS score
    top_epss_cves = all_cve_details[:10]
    # Insert top 10 CVEs into the P&E database
    insert_shodan_top_cves(top_epss_cves)
    LOGGER.info("Recorded top 10 CVEs with the highest EPSS score in the P&E database")

   