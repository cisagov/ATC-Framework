"""Scripts to collect data and findings from Flare."""

# Imports
import datetime
import logging
import numpy as np
import pandas as pd
import re
import requests
from requests.auth import HTTPBasicAuth
import time
import traceback

from .data.pe_db.config import get_params
from .data.pe_db.db_query_source import (
    get_cred_breach_uids,
    get_orgs,
    insert_flare_breaches,
    insert_flare_credentials,
    insert_flare_events,
    insert_shodan_top_cves,
    query_all_shodan_cves,
)

# Set up logging
LOGGER = logging.getLogger(__name__)

# Calculate start and end dates for data collection period
TODAY = datetime.date.today()
DAYS_BACK = datetime.timedelta(days=20) # 20 days back default
START_DATE = (TODAY - DAYS_BACK).strftime("%Y-%m-%d")
END_DATE = TODAY.strftime("%Y-%m-%d")
# Or manually set data collection window
# START_DATE = "2025-11-01"
# END_DATE = "2025-11-15"

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
    # Return results
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
        # rate control delay
        time.sleep(1)
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
    if retry_count == max_retries + 1:
        LOGGER.error(f"Error: Failed to retrieve Flare event details for {event_uid}")
        return None
    else:
        return resp.json()

def get_all_event_details(event_list, org_uid, org_idents):
    """Retrieve the full set of details for each of the specified events."""
    flare_token = get_flare_token()
    # Iterate over each event
    total_event_list = []
    total_cred_list = []
    for idx, event in enumerate(event_list):
        # Retrieve further details for event
        event_uid = event.get("event_uid")
        event_type = event.get("event_type")
        # List of this org's domain identifiers
        org_domain_idents = [d["value"] for d in org_idents if d["type"] == "domain"] 
        # If event doesn't have related identifiers, skip
        if len(event.get("identifiers")) == 0:
            print("\tERROR: no related identifiers for this event")
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
            continue
        event.update({"event_date": event.get("event_date")[:10]})
        print(f"Retrieved details for event {idx+1} of {len(event_list)} - Type: {event_type}")

        # Parse out releveant data based on event type
        if event_type == "stealer_log":
            # Parse stealer_log events with custom title + content_preview
            stealer_log_title = f"A stealer log has been offered for sale."
            event_dict = parse_default_event_fields(event, event_details, org_uid, True, stealer_log_title)
            # Also parse stealer_logs for any leaked credentials
            cred_list = parse_creds_stealer_log(event_details, org_domain_idents)
            # Append record
            total_event_list.append(event_dict)
            if cred_list is not None:
                total_cred_list.extend(cred_list)
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
        else:
            # Parse event types that: use content field, no custom title
            event_dict = parse_default_event_fields(event, event_details, org_uid)
            # Append record
            total_event_list.append(event_dict)
        
    # Return parsed event detail data
    return total_event_list, total_cred_list

def remove_emoji(txt):
    """Remove emoji characters from a given string."""
    # Regex pattern to match various emoji Unicode ranges
    emoji_pattern = re.compile(
        "["
        "\U0001F600-\U0001F64F"  # emoticons
        "\U0001F300-\U0001F5FF"  # symbols & pictographs
        "\U0001F680-\U0001F6FF"  # transport & map symbols
        "\U0001F1E0-\U0001F1FF"  # flags (iOS)
        "\U00002702-\U000027B0"  # Dingbats
        "\U000024C2-\U0001F251"
        "]+", flags=re.UNICODE
    )
    return emoji_pattern.sub(r'', txt)

def parse_related_identifiers(event):
    """Parse identifiers related to this event for use in SQL query."""
    identifier_list_str = "ARRAY["
    for identifier in event.get("identifiers"):
        ident_id = identifier.get("id")
        identifier_list_str += f"'{ident_id}', "
    identifier_list_str = identifier_list_str[:-2] + "]"
    return identifier_list_str

def parse_default_event_fields(event, event_details, org_uid, content_preview=False, custom_title=None):
    """Parse and format the standard data fields from the specified event."""
    event_details = event_details.get("activity")
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
        "url": event_details.get("data").get("url"),
        "risk_scores": event_details.get("header").get("risk"),
        "related_identifiers": parse_related_identifiers(event),
        "data_source_uid": "751a4ff4-ac0c-11ef-8c7d-02527bfc647f",
        "severity": event.get("severity"),
    }

def parse_creds_stealer_log(event_details, domain_idents):
    """Extract leaked username password pairs from stealer_log events if available."""
    # Check if this stealer_log event has any credentials
    try:
        raw_creds_list = event_details.get("activity").get("data").get("credentials")
    except Exception as e:
        print("\tError: No credentials found for this stealer_log event")
        return None
    if raw_creds_list is None:
        print("\tError: No credentials found for this stealer_log event")
        return None
    # If it does, iterate over the list of creds to find the ones relevant to the organization
    creds_list = []
    for dict in raw_creds_list:
        curr_url = dict.get("url")
        curr_username = dict.get("username")
        # Extract only leaked creds whose URL involves the organization's domains
        for domain in domain_idents:
            if (domain in curr_url) and (curr_username != ""):
                append_dict = {
                    # uid,
                    "username": dict.get("username"),
                    # org_uid, 
                    "root_domain": domain,
                    "sub_domain": domain,
                    "breach_name": dict.get("application"),
                    # "modified_date": datetime.datetime.now().strftime("%Y-%m-%d"),
                    "modified_date": event_details.get("activity").get("data").get("metadata").get("estimated_created_at"),
                    "credential_breaches_uid": None, 
                    "data_source_uid": "751a4ff4-ac0c-11ef-8c7d-02527bfc647f",
                    # name,
                    # login_id,
                    # phone,
                    "password": dict.get("password"),
                    "hash_type": "plain-text",
                    # intelx_system_id,
                    "url": dict.get("url")
                }
                # Append results to the overall list for this stealer_log event
                creds_list.append(append_dict)

    # Format and return results
    creds_df = pd.DataFrame(creds_list)
    creds_list = creds_df.to_dict(orient="records")
    return creds_list

def format_creds_for_db(cred_list, org_abbrv, org_uid):
    """Format list of flare credential leak dictionaries to be inserted into PE DB."""
    # Convert list of creds to dataframe
    all_df = pd.DataFrame.from_dict(cred_list)
    all_df["username"] = all_df["username"].str.lower()
    # Only include credentials that feature a @ in the username
    all_df = all_df[all_df["username"].str.contains("@", na=False)].reset_index(drop=True)
    all_df = all_df.drop_duplicates(subset=["username", "breach_name"], keep="first")
    # Add additional columns
    all_df["password_included"] = np.where(
        (pd.isna(all_df["password"])) | (all_df["password"] == ""), 0, 1
    )
    all_df["sub_domain"] = all_df["username"].str.split("@").str[1]
    all_df["sub_domain"].fillna("None", inplace=True)
    all_df["organizations_uid"] = org_uid
    all_df["intelx_system_id"] = "None"
    all_df = all_df.loc[all_df["breach_name"] != ""]
    all_df.rename(
        columns={
            "username": "email",
        },
        inplace=True,
    )
    # Assemble credential exposures dataframe
    creds_df = all_df[
        [
            "email",
            "organizations_uid",
            "root_domain",
            "sub_domain",
            "breach_name",
            "modified_date",
            "credential_breaches_uid",
            "data_source_uid",
            "password",
            "hash_type",
            "intelx_system_id",
        ]
    ].reset_index(drop=True)
    # Assemble credential breaches dataframe
    breaches_df = all_df.groupby(
        [
            "breach_name", 
            "modified_date", 
            # "bucket", 
            "url",
            "data_source_uid",
        ]
    ).aggregate({"email": "count", "password_included": "sum"})
    breaches_df = breaches_df.reset_index()
    breaches_df["password_included"] = breaches_df["password_included"] > 0
    breaches_df.rename(columns={"email": "exposed_cred_count"}, inplace=True)
    breaches_df["description"] = (
        breaches_df["breach_name"]
        + " was identified on "
        + breaches_df["modified_date"]
        + ". The post "
        + (
            "does not contain"
            if breaches_df["password_included"] is True
            else "contains"
        )
        + " passwords. This data came from a stealer log where credentials were recorded while being used at this URL: "
        + breaches_df["url"]
    )
    breaches_df["breach_date"] = breaches_df["modified_date"]
    breaches_df["added_date"] = END_DATE
    breaches_df = breaches_df[
        [
            "breach_name",
            "description",
            "breach_date",
            "added_date",
            "modified_date",
            "password_included",
            "data_source_uid",
        ]
    ]
    # Return results
    return creds_df, breaches_df

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
    for org_idx, org in enumerate(pe_orgs_final):
        try:
            org_abbrv = org["cyhy_db_name"]
            org_uid = org["organizations_uid"]
            LOGGER.info(
                f"Running Flare on \"{org_abbrv}\" ({org_idx + 1} of {len(pe_orgs_final)})"
            )
            # Retrieve identifier group info for this org
            ident_group_info = get_ident_group_info(org_abbrv)
            # Retrieve identifiers for this org
            org_identifiers = get_ident_by_group_id(ident_group_info.get("id"))
            # Retrieve all Flare events for this org
            LOGGER.info(f"Retrieving all Flare events for {org_abbrv}")
            event_list = get_ident_group_events(ident_group_info, event_severities, event_types, start_date, end_date)
            LOGGER.info(f"Found {len(event_list)} events for {org_abbrv}")
            # Retrieve further details for the events and format
            LOGGER.info(f"Retrieving additional details for {org_abbrv}'s events")
            final_event_list, final_cred_list = get_all_event_details(event_list, org_uid, org_identifiers)
            # Convert risk_score field to string type
            for event in final_event_list:
                if event.get("risk_scores") is not None:
                    event.update({"risk_scores": str(event.get("risk_scores"))})
            final_event_df = pd.DataFrame(final_event_list)
            final_event_df.drop_duplicates(inplace=True)
            final_event_list = final_event_df.to_dict(orient="records")

            # Insert Flare event data into PE DB
            LOGGER.info(f"Inserting Flare event data for {org_abbrv} into the PE database")
            if len(final_event_list) > 0:
                insert_flare_events(final_event_list)
                LOGGER.info(f"Flare events for {org_abbrv} successfully inserted into PE database")
            else:
                LOGGER.info(f"No Flare events for {org_abbrv} to insert, skipping")

            # Insert Flare credential leak data into PE DB if available
            if len(final_cred_list) > 0:
                # Format cred leak data to match PE DB tables
                final_cred_df, final_breach_df = format_creds_for_db(final_cred_list, org_abbrv, org_uid) 
                # Skip if no valid cred data to insert after formatting
                if (len(final_cred_df) == 0) or (len(final_breach_df) == 0):
                    LOGGER.info(f"No Flare credential information to insert, skipping")
                else:
                    LOGGER.info(f"Found {len(final_cred_list)} credentials for {org_abbrv}, formatting credential data")
                    # Insert Flare breach data into PE DB
                    insert_flare_breaches(final_breach_df)
                    LOGGER.info(f"Flare breaches for {org_abbrv} successfully inserted into PE database")
                    # Retrieve breach uids for the credential records
                    breach_uid_df = get_cred_breach_uids(list(final_cred_df["breach_name"]))
                    breach_dict = dict(zip(breach_uid_df["breach_name"], breach_uid_df["credential_breaches_uid"]))
                    # Add credential_breaches_uid to credential records
                    for idx, row in final_cred_df.iterrows():
                        breach_uid = breach_dict.get(row["breach_name"])
                        final_cred_df.at[idx, "credential_breaches_uid"] = breach_uid
                    # Insert Flare credential data into PE DB
                    insert_flare_credentials(final_cred_df)
                    LOGGER.info(f"Flare credentials for {org_abbrv} successfully inserted into PE database")
            else:
                LOGGER.info(f"No Flare credential information to insert, skipping")

            # Log successful data collection for this org
            success += 1
        except Exception as e:
            LOGGER.error(f"Error encountered during Flare scan for {org_abbrv} - {e}")
            traceback.print_exc()
            # Log failed data collection for this org
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
        if retry_count == max_retries + 1:
            LOGGER.error(f"Error: Failed to retrieve Shodan CVE info for {cve}")
            return None
        else:
            return resp.json()
        
def get_cve_details(cve_list):
        """Retrieve details for the specified list of CVEs."""
        cve_detail_list = []
        for idx, cve in enumerate(cve_list):
            # Call shodan API to get CVE info
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
