"""Scripts to collect data and findings (events) from Flare."""

# Imports
import datetime
import logging
import openpyxl
from openpyxl import load_workbook
import os
import pandas as pd
import requests
from requests.auth import HTTPBasicAuth
import time
import traceback

from .data.flare.flare_helpers import (
    get_all_ident_by_group_id,
    get_event_details,
    get_flare_token,
    get_ident_group_info,
    remove_emoji,
)
from .data.pe_db.config import get_params
from .data.pe_db.db_query_source import (
    get_orgs,
    insert_flare_events,
)

# Set up logging
LOGGER = logging.getLogger(__name__)

# Calculate start and end dates for data collection period
TODAY = datetime.date.today()
DAYS_BACK = datetime.timedelta(days=20) # 20 days back default
START_DATE = (TODAY - DAYS_BACK).strftime("%Y-%m-%d")
END_DATE = TODAY.strftime("%Y-%m-%d")
# Or manually set data collection window
# START_DATE = "2026-01-16"
# END_DATE = "2026-01-31"


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
    if retry_count == max_retries + 1:
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

def get_ident_group_events(identifier_group, event_severities, event_types, start_date, end_date):
    """Retrieve all events for the specified identifier group (organization)."""
    ident_group_name = identifier_group.get("name")
    ident_group_id = identifier_group.get("id")
    print(f"Retrieving all events for the identifier group: {ident_group_name}")
    flare_token = get_flare_token()
    results_list = []
    more_data = False
    curr_next = ""
    chunk_size = 10 # max size is 10
    # Make initial data feed call
    print(f"Working on data feed chunk 1")
    ini_payload = {
        "size": chunk_size,
        "filters": {
            "severity": event_severities,
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
    # If there's a "next" value, continue fetching data
    retrieve_ct = 2
    while more_data:
        # Rate control delay
        time.sleep(1)
        # Refresh auth token every ~30 min (avg event retrieval api call ~= 1.5s)
        if retrieve_ct % 500 == 0: # default 1200
            LOGGER.warning("Refreshing Flare API auth token for intial event retrieval")
            print("REFRESHING FLARE AUTH TOKEN")
            flare_token = get_flare_token()
        print(f"Working on data feed chunk {retrieve_ct}")
        # Make API call for current chunk
        curr_payload = {
            "size": chunk_size,
            "from": curr_next,
            "filters": {
                "severity": event_severities,
                "type": event_types,
                "estimated_created_at": {
                    "gte": start_date,
                    "lte": end_date,
                }
            }
        }
        curr_resp = get_ident_group_events_chunk(flare_token, ident_group_id, curr_payload)
        # Handle edge case where no results found for this chunk
        if len(curr_resp.get("items")) != 0:
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

    # Once all data has been retrieved, format and return results
    results_list = [
        {
            "event_uid": item.get("metadata").get("uid"),
            "event_type": item.get("metadata").get("type"),
            "severity": item.get("metadata").get("severity"),
            "identifiers": item.get("identifiers"),
            "event_date": item.get("metadata").get("estimated_created_at"),
        } for item in results_list
    ]
    print(f"Total number of items retrieved for all identifiers: {len(results_list)}")
    return results_list

def get_all_event_details(event_list, org_uid, org_idents_df):
    """Retrieve the full set of details for each of the specified events."""
    flare_token = get_flare_token()
    # Iterate over each event
    total_event_list = []
    for idx, event in enumerate(event_list):
        # Refresh auth token every ~30 min (avg event detail api call ~= 0.5s)
        if (idx % 500 == 0) and (idx != 0): # default 3600
            LOGGER.warning("Refreshing Flare API auth token for event details retrieval")
            print("REFRESHING FLARE AUTH TOKEN")
            flare_token = get_flare_token()
        # Retrieve further details for event
        event_uid = event.get("event_uid")
        event_type = event.get("event_type")

        print(f"Retrieving details for event {idx+1} of {len(event_list)} - Type: {event_type}")

        # If event doesn't have related identifiers, skip
        if len(event.get("identifiers")) == 0:
            print("\tERROR: No related identifiers for this event")
            continue
        # If event type is leaked_credential, skip (incompatible with event details endpoint)
        if event_type == "leaked_credential":
            print("WARNING: leaked_credential event encountered, skipping")
            print(f"\tevent_uid: {event_uid}")
            continue
        # Call event details endpoint
        event_details = get_event_details(event_uid, flare_token)
        # Skip event if no details available
        if event_details is None:
            print("\tERROR: No details found for this event")
            continue
        event.update({"event_date": event.get("event_date")[:10]})
        # Parse out releveant data based on event type
        if event_type == "stealer_log":
            # Special parsing for stealer_log type events
            event_dict = parse_stealer_log_event_fields(event, event_details, org_uid, org_idents_df)
            # Append record
            if event_dict != -1:
                total_event_list.append(event_dict)
        elif event_type == "bot":
            # Parse bot events with custom title + content_preview
            bot_title = f"A device has potentially been infected by botnet malware and the data stolen from it has been offered for sale."
            event_dict = parse_default_event_fields(event, event_details, org_uid, True, bot_title)
            # Append record
            total_event_list.append(event_dict)
        elif event_type in ("leak", "ransomleak", "listing", "seller"):
            # Parse event types that: use content_preview field, no custom title
            event_dict = parse_default_event_fields(event, event_details, org_uid, True)
            # Append record
            total_event_list.append(event_dict)
        elif event_type == "chat_message":
            # Parse event types that: use content field, no custom title
            event_dict = parse_default_event_fields(event, event_details, org_uid)
            # Append record, only if chat_message has content field
            if (event_dict.get("content")) and (event_dict.get("content") != "None"):
                total_event_list.append(event_dict)
            else:
                print("\tERROR: No content field for this chat_message event")
        else:
            # Parse event types that: use content field, no custom title
            event_dict = parse_default_event_fields(event, event_details, org_uid)
            # Append record
            total_event_list.append(event_dict)

    # Return parsed event detail data
    return total_event_list

def parse_related_identifiers(event, text=False):
    """Parse identifiers related to this event for use in SQL query."""
    identifier_list_str = "ARRAY["
    for identifier in event.get("identifiers"):
        if text:
            ident_str = identifier.get("name")
        else:
            ident_str = identifier.get("id")
        identifier_list_str += f"'{ident_str}', "
    identifier_list_str = identifier_list_str[:-2] + "]"
    return identifier_list_str

def parse_stealer_log_event_fields(event, event_details, org_uid, org_idents_df):
    """Parse and format relevant data fields for stealer_log type events."""
    event_details = event_details.get("activity")
    content = event_details.get("header").get("content_preview")
    # If content field is like "N credentials", add extra details
    if content[-12:] == " credentials":
        total_creds = int(content[:-12])
        # Identify relevent credentials
        rel_ident = list(org_idents_df.loc[org_idents_df["type"] == "domain"]["value"])
        rel_creds = []
        creds_list = event_details.get("data").get("credentials")
        for cred in creds_list:
            # Record any creds that contain any of the relevant identifiers
            user = cred.get("username")
            passwd = cred.get("password")
            url = cred.get("url")
            if (any(item in user for item in rel_ident) or any(item in url for item in rel_ident)) and ("@" in user):
                cred_str = f"username: {user} - password: {passwd} - login_url: {url}"
                rel_creds.append(cred_str)
        # Discard this finding if none of the credentials are relevant
        if len(rel_creds) == 0:
            return -1
        # Get compromised device info
        user_ip = event_details.get("data").get("user_information").get("ip_address")
        user_os = event_details.get("data").get("user_information").get("os")
        user_username = event_details.get("data").get("user_information").get("username")
        # Build custom content field
        content = f"A stealer log was offered for sale containing {total_creds} leaked credentials.\n{len(rel_creds)} of those {total_creds} credentials are related to your organization:"
        for cred in rel_creds:
            content += f"\n- {cred}"
        content += f"\n\nInformation about the device this data was supposedly stolen off of:\nip:{user_ip}\nOS:{user_os}\nusername:{user_username}"

    # Return parsed info
    return {
        "organizations_uid": org_uid,
        "flare_uid": event.get("event_uid"),
        "event_type": event.get("event_type"),
        "event_date": event.get("event_date"),
        "collection_date": datetime.datetime.now().strftime("%Y-%m-%d"),
        "title": "A Stealer Log Was Offered for Sale",
        "content": content,
        "content_hash": event_details.get("header").get("content_hash"),
        "actor": event_details.get("header").get("actor"),
        "category": event_details.get("header").get("category_name"),
        "source": event_details.get("metadata").get("source"), # (source ~= site for mentions)
        "url": event_details.get("data").get("url"),
        "risk_scores": event_details.get("header").get("risk"),
        "related_identifiers": parse_related_identifiers(event),
        "related_identifiers_txt": parse_related_identifiers(event, True),
        "data_source_uid": "751a4ff4-ac0c-11ef-8c7d-02527bfc647f",
        "severity": event.get("severity"),
    }

def parse_default_event_fields(event, event_details, org_uid, content_preview=False, custom_title=None):
    """Parse and format the standard data fields from the specified event."""
    event_details = event_details.get("activity")
    url =  event_details.get("data").get("url")

    # Use custom title if provided
    if custom_title is not None:
        title = custom_title
    else:
        title = event_details.get("header").get("title")
    # Use content_preview instead of content if specified
    if content_preview:
        content = event_details.get("header").get("content_preview")
    else:
        content = event_details.get("data").get("content")

    # Special content parsing needed for chat_message events
    if event.get("event_type") == "chat_message":
        content = event_details.get("data").get("message")
        conv_link = event_details.get("data").get("conversation_link")
        if conv_link is not None:
            url = conv_link

    # Special formatting to get rid of emojis and null chars
    if isinstance(content, str):
        content = remove_emoji(content)
        content = content.replace('\x00', '')

    # Return parsed info
    return {
        "organizations_uid": org_uid,
        "flare_uid": event.get("event_uid"),
        "event_type": event.get("event_type"),
        "event_date": event.get("event_date"),
        "collection_date": datetime.datetime.now().strftime("%Y-%m-%d"),
        "title": title,
        "content": content,
        "content_hash": event_details.get("header").get("content_hash"),
        "actor": event_details.get("header").get("actor"),
        "category": event_details.get("header").get("category_name"),
        "source": event_details.get("metadata").get("source"), # (source ~= site for mentions)
        "url": url,
        "risk_scores": event_details.get("header").get("risk"),
        "related_identifiers": parse_related_identifiers(event),
        "related_identifiers_txt": parse_related_identifiers(event, True),
        "data_source_uid": "751a4ff4-ac0c-11ef-8c7d-02527bfc647f",
        "severity": event.get("severity"),
    }

def run_flare_events(orgs_list):
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
        for org in orgs_list:
            org_dict = next((d for d in pe_orgs if d["cyhy_db_name"] == org), None)
            pe_orgs_final.append(org_dict)
    # Alphabetize org list for consistent order
    # pe_orgs_final = sorted(pe_orgs_final, key=lambda d: d["cyhy_db_name"])

    # Create file for exe time performance logging
    pe_orgs_final_df = pd.DataFrame(pe_orgs_final)
    current_date = datetime.date.today().strftime("%Y-%m-%d")
    first_org = pe_orgs_final_df.iloc[0]["cyhy_db_name"]
    last_org = pe_orgs_final_df.iloc[-1]["cyhy_db_name"]
    exe_time_file = os.path.dirname(os.path.abspath(__file__)) + f"/exe_time_logs/flare_events_logs/flare_events_{current_date}_{first_org}-{last_org}_exe_times.xlsx"
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

    # Specify which event severities to collect
    event_severities = [
        # "info",
        "low",
        "medium",
        "high",
        "critical",
    ]
    # Specify which event types to collect
    event_types = [
        # > Asset Alert Data: 
        # Any events involving IP/Domain assets
        # > Executive Alert Data:
        # Any events involving executive name assets
        # > Potential Threat Alert Data:
        "bot", 
        "bucket", 
        "bucket_object", 
        "domain", 
        "service",
        # > Market Alert Data:
        "listing", 
        "stealer_log", # warning, lots of results (still somewhat acceptable)
        # > Credential Data:
        "leak",
        "leaked_credential", # *** Incompatible with event details endpoint for some reason
        "leaked_data",
        "leaked_file",
        "ransomleak",
        # > Chat (Mention) Data:
        "chat_message",
        # > Dark Web Media (Mention) Data:
        "blog_content",
        "blog_post",
        "forum_post",
        "forum_profile",
        "forum_topic",
    ]
    # Run Flare data collection on each org
    LOGGER.info(f"Gathering Flare event data of the following types: {event_types}")
    start_date = START_DATE
    end_date = END_DATE
    success = 0
    failed = 0
    failed_list = []
    for org_idx, org in enumerate(pe_orgs_final):
        # Start exe time for this org
        time_start = time.time()
        # Run Flare on this organization
        try:
            org_abbrv = org["cyhy_db_name"]
            org_uid = org["organizations_uid"]
            LOGGER.info(
                f"Running Flare on \"{org_abbrv}\" ({org_idx + 1} of {len(pe_orgs_final)})"
            )
            # Retrieve identifier group info for this org
            ident_group_info = get_ident_group_info(org_abbrv)
            # Retrieve list of all identifiers for this org
            org_idents_df = pd.DataFrame(get_all_ident_by_group_id(ident_group_info.get("id")))
            # Retrieve all Flare events for this org
            LOGGER.info(f"Retrieving all Flare events for {org_abbrv}")
            event_list = get_ident_group_events(ident_group_info, event_severities, event_types, start_date, end_date)
            LOGGER.info(f"Found {len(event_list)} events for {org_abbrv}")
            # Retrieve further details for the events and format
            LOGGER.info(f"Retrieving additional details for {org_abbrv}'s events")
            final_event_list = get_all_event_details(event_list, org_uid, org_idents_df)
            if len(final_event_list) > 0:
                # Convert risk_score field to string type
                for event in final_event_list:
                    if event.get("risk_scores") is not None:
                        event.update({"risk_scores": str(event.get("risk_scores"))})
                # Drop duplicates
                final_event_df = pd.DataFrame(final_event_list)
                final_event_df = final_event_df.sort_values(by="event_date", ascending=False).reset_index(drop=True)
                final_event_df.drop_duplicates(subset=["organizations_uid", "flare_uid"], keep="first", inplace=True)
                final_event_list = final_event_df.to_dict(orient="records")
                # Insert Flare event data into PE DB
                LOGGER.info(f"Inserting {len(final_event_list)} Flare event records for {org_abbrv} into the PE database")
                insert_flare_events(final_event_list)
                LOGGER.info(f"Flare events for {org_abbrv} successfully inserted into PE database")
            else:
                LOGGER.info(f"No Flare events for {org_abbrv} to insert, skipping")
            # Log successful data collection for this org
            success += 1
        except Exception as e:
            LOGGER.error(f"Error encountered during Flare scan for {org_abbrv} - {e}")
            traceback.print_exc()
            # Log failed data collection for this org
            failed += 1
            failed_list.append(org_abbrv)

        # End exe time for this org
        time_end = time.time()
        # Write exe time to file
        org_exe_time = '{:.5f}'.format(datetime.timedelta(seconds=(time_end - time_start)).total_seconds())
        org_exe_stats = [
            str(datetime.datetime.now()),
            org_abbrv,
            org_exe_time,
        ]
        workbook = load_workbook(exe_time_file)
        sheet = workbook["Sheet"]
        sheet.append(org_exe_stats)
        workbook.save(exe_time_file)

    # Log overall success/fail statistics
    LOGGER.info(
        f"{success}/{len(pe_orgs_final)} organizations successfully completed their Flare scan"
    )
    LOGGER.info(
        f"{failed}/{len(pe_orgs_final)} organizations encountered an error during their Flare scan: {failed_list}"
    )