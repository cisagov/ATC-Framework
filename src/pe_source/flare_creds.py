"""Scripts to collect credential leak data from Flare."""

import datetime
import logging
import numpy as np
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
)
from .data.pe_db.config import get_params
from .data.pe_db.db_query_source import (
    get_cred_breach_uids,
    get_orgs,
    insert_flare_breaches,
    insert_flare_credentials,
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


def get_ident_creds_chunk(token, ident_id, payload):
    """Get leaked creds for the speicifed identifier ID."""
    size = payload.get("size")
    frm = payload.get("from")
    headers = {
        "Content-Type": "application/json",
        'Authorization': f'Bearer {token}',
    }
    if frm is not None:
        url = f"https://api.flare.io/firework/v3/identifiers/{ident_id}/feed/credentials?size={size}&from={frm}"
    else:
        url = f"https://api.flare.io/firework/v3/identifiers/{ident_id}/feed/credentials?size={size}"
    resp = requests.get(url, headers=headers)
    # Retry clause in case API falters
    retry_count, max_retries, time_delay = 1, 5, 3
    while resp.status_code != 200 and retry_count <= max_retries:
        print(f"\tRetrying Flare leaked cred retrieval API endpoint (code {resp.status_code}), attempt {retry_count} of {max_retries}")
        time.sleep(time_delay)
        resp = requests.get(url, headers=headers)
        retry_count += 1
    # Return results
    if retry_count == max_retries + 1:
        print(f"Error: Failed to retrieve Flare leaked creds for {ident_id}")
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
    
def get_ident_creds(ident_id, start_date, end_date):
    """Retrieve all leaked creds for the specified identifier ID."""
    print(f"Retrieving all leaked creds for the identifier ID: {ident_id}")
    start_date = datetime.datetime.strptime(start_date, '%Y-%m-%d').date()
    end_date = datetime.datetime.strptime(end_date, '%Y-%m-%d').date()
    flare_token = get_flare_token()
    results_list = []
    more_data = False
    curr_next = ""
    chunk_size = 100 # default 20
    # Make initial data feed call
    print(f"Working on data feed chunk 1")
    ini_payload = {
        "size": chunk_size,
        # "filters": {
        #     "estimated_created_at": {
        #         "gte": start_date,
        #         "lte": end_date,
        #     }
        # }
    }
    ini_resp = get_ident_creds_chunk(flare_token, ident_id, ini_payload)
    results_list += ini_resp.get("items")
    # rate control delay
    time.sleep(0.75)
    # Check if there's any more data to retrieve
    if ini_resp.get("next"):
        more_data = True
        curr_next = ini_resp.get("next")
    # If there's a "next" value, continue fetching data
    retrieve_ct = 2
    while more_data:
        # rate control delay
        time.sleep(1)
        print(f"Working on leaked credentials feed chunk {retrieve_ct}")
        # Make API call for current chunk
        curr_payload = {
            "size": chunk_size,
            "from": curr_next,
            # "filters": {
            #     "estimated_created_at": {
            #         "gte": start_date,
            #         "lte": end_date,
            #     }
            # }
        }
        curr_resp = get_ident_creds_chunk(flare_token, ident_id, curr_payload)
        # Handle edge case where no results found for this chunk
        if len(curr_resp.get("items")) != 0:
            # Append results
            results_list += curr_resp.get("items")
            curr_last_record = curr_resp.get("items")[-1]
            last_rec_date = datetime.datetime.fromisoformat(curr_last_record.get("imported_at")).date()
        else:
            last_rec_date = end_date
        # Check if data retrieval should continue
        if last_rec_date < start_date:
            # Stop retrieving if we've passed the start date of the specified time period
            more_data = False
            # No use in continuing since all following results will be even older records
        elif curr_resp.get("next"):
            # If there's more data, update next value - continue
            curr_next = curr_resp.get("next")
        else:
            # If no next value, there's no more data to retrieve - stop
            more_data = False
        retrieve_ct +=1

    # Once all data has been retrieved, format and return results
    results_list = [
        {
            "modified_date": item.get("imported_at"),
            "email": item.get("identity_name"),
            "password": item.get("hash"),
            "hash_type": "plain-text",
            "root_domain": item.get("domain"),
            "sub_domain": item.get("domain"),
            "credential_breaches_uid": None,
            "breach_name": item.get("source").get("id"),
            "breach_description": item.get("source").get("description_en"),
            "breach_date": item.get("source").get("breached_at"),
            "related_identifier": ident_id,
            "data_source_uid": "751a4ff4-ac0c-11ef-8c7d-02527bfc647f",
        } for item in results_list
    ]
    # Filter for results only within the specified time period
    results_list = [
        record for record in results_list
        if start_date <= datetime.datetime.fromisoformat(record["modified_date"]).date() <= end_date
    ]
    # Return results
    print(f"Total number of leaked credentials retrieved for identifier: {len(results_list)}")
    return results_list

def format_ident_creds(cred_list, org_uid, end_date):
    """Format list of Flare identifier leaked creds to be inserted into the database."""
    # Convert list of creds to dataframe
    all_df = pd.DataFrame.from_dict(cred_list)
    # Remove duplicates and drop records w/o breach names
    all_df = all_df.drop_duplicates(subset=["email", "breach_name"], keep="first")
    all_df = all_df.loc[all_df["breach_name"] != ""]
    # Add additional columns
    all_df["password_included"] = np.where(
        (pd.isna(all_df["password"])) | (all_df["password"] == ""), 0, 1
    )
    all_df["sub_domain"] = all_df["email"].str.split("@").str[1]
    all_df["sub_domain"] = all_df["sub_domain"].fillna("None")
    all_df["organizations_uid"] = org_uid
    all_df["intelx_system_id"] = "None"
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
            "breach_description", 
            "modified_date",
            "data_source_uid",
        ]
    ).aggregate({"email": "count", "password_included": "sum"}).reset_index()
    breaches_df["password_included"] = breaches_df["password_included"] > 0
    breaches_df.rename(
        columns={
            "email": "exposed_cred_count",
            "breach_description": "description",
        }, 
        inplace=True
    )
    breaches_df["breach_date"] = breaches_df["modified_date"]
    breaches_df["added_date"] = end_date
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


def get_ident_group_stealer_logs_chunk(token, ident_group_id, payload):
    """Call the Flare identifier group event feed endpoint specifically for stealer_logs."""
    headers = {
        "Content-Type": "application/json",
        'Authorization': f'Bearer {token}',
    }
    url = f"https://api.flare.io/firework/v4/events/identifier_groups/{ident_group_id}/_search"
    resp = requests.post(url, headers=headers, json=payload)
    # Retry clause in case API falters
    retry_count, max_retries, time_delay = 1, 5, 3
    while resp.status_code != 200 and retry_count <= max_retries:
        LOGGER.warning(f"\tRetrying Flare stealer_log event retrieval API endpoint (code {resp.status_code}), attempt {retry_count} of {max_retries}")
        time.sleep(time_delay)
        resp = requests.post(url, headers=headers, json=payload)
        retry_count += 1
    # Return results
    if retry_count == max_retries + 1:
        LOGGER.error(f"Error: Failed to retrieve Flare stealer_log events for {ident_group_id}")
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

def get_ident_group_stealer_logs(identifier_group, event_severities, start_date, end_date):
    """Retrieve all stealer_log events for the specified identifier group (organization)."""
    ident_group_name = identifier_group.get("name")
    ident_group_id = identifier_group.get("id")
    print(f"\n\nRetrieving all stealer_log events for the identifier group: {ident_group_name}")
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
            "type": ["stealer_log"],
            "estimated_created_at": {
                "gte": start_date,
                "lte": end_date,
            }
        }
    }
    ini_resp = get_ident_group_stealer_logs_chunk(flare_token, ident_group_id, ini_payload)
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
                "type": ["stealer_log"],
                "estimated_created_at": {
                    "gte": start_date,
                    "lte": end_date,
                }
            }
        }
        curr_resp = get_ident_group_stealer_logs_chunk(flare_token, ident_group_id, curr_payload)
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
    print(f"Total number of stealer_log records retrieved for identifier group: {len(results_list)}")
    return results_list

def get_stealer_log_details(event_list, org_idents):
    """Retrieve the full set of details for each of the stealer_log events."""
    flare_token = get_flare_token()
    # Iterate over each event
    total_cred_list = []
    for idx, event in enumerate(event_list):
        # General event info
        event_uid = event.get("event_uid")
        event_type = event.get("event_type")
        org_domain_idents = [d["value"] for d in org_idents if d["type"] == "domain"] 
        # If event doesn't have related identifiers, skip
        if len(event.get("identifiers")) == 0:
            print("\tERROR: no related identifiers for this event")
            continue
        # Call event details endpoint
        event_details = get_event_details(event_uid, flare_token)
        # Skip event if no details available
        if event_details is None:
            continue
        event.update({"event_date": event.get("event_date")[:10]})
        print(f"Retrieved details for event {idx+1} of {len(event_list)} - Type: {event_type}")
        # Parse any leaked credentials in this stealer_logs event
        cred_list = extract_stealer_log_creds(event_details, org_domain_idents)
        # Append any creds found to overall list
        if cred_list is not None:
            total_cred_list.extend(cred_list)
        
    # Return full list of stealer_log creds
    return total_cred_list

def extract_stealer_log_creds(event_details, domain_idents):
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

def format_stealer_log_creds(cred_list, org_uid):
    """Format list of Flare stealer_log leaked creds to be inserted into the database."""
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

def run_flare_creds(orgs_list):
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
    pe_orgs_final = sorted(pe_orgs_final, key=lambda d: d["cyhy_db_name"])

    # Create file for exe time performance logging
    pe_orgs_final_df = pd.DataFrame(pe_orgs_final)
    current_date = datetime.date.today().strftime("%Y-%m-%d")
    first_org = pe_orgs_final_df.iloc[0]["cyhy_db_name"]
    last_org = pe_orgs_final_df.iloc[-1]["cyhy_db_name"]
    exe_time_file = os.path.dirname(os.path.abspath(__file__)) + f"/exe_time_logs/flare_creds_logs/flare_creds_{current_date}_{first_org}-{last_org}_exe_times.xlsx"
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

    # Run Flare leaked credential data collection on each org
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
                f"Running Flare leaked credentials collection on \"{org_abbrv}\" ({org_idx + 1} of {len(pe_orgs_final)})"
            )
            # Retrieve identifier group info for this org
            ident_group_info = get_ident_group_info(org_abbrv)
            # Retrieve identifiers for this org
            org_idents = get_all_ident_by_group_id(ident_group_info.get("id"))
            # Retrieve leaked credentials from each of the org's identifiers
            ident_cred_df = pd.DataFrame()
            ident_breach_df = pd.DataFrame()
            ident_creds_results = []
            for ident_idx, ident in enumerate(org_idents):
                ident_val = ident.get("value")
                ident_id = ident.get("id")
                print(f"Retrieving creds for identifier: {ident_val} ({ident_idx+1} of {len(org_idents)})")
                # Look up credentials for this identifier
                ident_creds = get_ident_creds(ident_id, start_date, end_date)
                # Add it to the overall list for this org
                ident_creds_results.extend(ident_creds)
            # If any identifier creds found
            if len(ident_creds_results) > 0:
                # Format identifier creds to be inserted into db
                print(f"{len(ident_creds_results)} Flare leaked creds found from org identifiers")
                ident_cred_df, ident_breach_df = format_ident_creds(ident_creds_results, org_uid, end_date)
            else:
                print("0 Flare leaked creds found from org identifiers")
            LOGGER.info(f"Found {len(ident_cred_df)} Flare creds from {org_abbrv}'s identifiers")

            # Retrieve leaked credentials from this org's stealer_log events
            stealer_log_cred_df = pd.DataFrame()
            stealer_log_breach_df = pd.DataFrame()
            event_severities = [
                # "info",
                "low",
                "medium",
                "high",
                "critical",
            ]
            # Get all stealer_log type events for this org
            stealer_log_event_list = get_ident_group_stealer_logs(ident_group_info, event_severities, start_date, end_date)
            stealer_log_event_list = [d for d in stealer_log_event_list if d["event_type"] == "stealer_log"]
            # Check if any stealer_log events found
            if len(stealer_log_event_list) > 0:
                # If so, retrieve further details for the stealer_log events
                stealer_log_creds_list = get_stealer_log_details(stealer_log_event_list, org_idents)
                # Check if any stealer_log creds found
                if len(stealer_log_creds_list) > 0:
                    # Format stealer_log creds to be inserted into db
                    stealer_log_cred_df, stealer_log_breach_df = format_stealer_log_creds(stealer_log_creds_list, org_uid)
                else:
                    print("0 Flare leaked creds found from stealer_log events")
            else:
                print("0 Flare leaked creds found from stealer_log events")
            LOGGER.info(f"Found {len(stealer_log_cred_df)} Flare creds from {org_abbrv}'s stealer_log events")

            # Combine lists of identifier creds and stealer_log creds
            total_cred_df = pd.concat(
                [ident_cred_df, stealer_log_cred_df],
                axis=0,
                ignore_index=True
            )
            total_breach_df = pd.concat(
                [ident_breach_df, stealer_log_breach_df],
                axis=0,
                ignore_index=True
            )
            total_cred_df = total_cred_df.drop_duplicates(subset=["email", "password"], keep="first").reset_index(drop=True)
            total_breach_df = total_breach_df.drop_duplicates(subset=["breach_name", "description"], keep="first").reset_index(drop=True)
            LOGGER.info(f"Found {len(total_cred_df)} unique Flare creds overall for {org_abbrv}")
            if len(total_cred_df) == 0:
                # If no Flare credentials found for this org, skip
                LOGGER.warning(f"No Flare credentials found for {org_abbrv}, skipping")
                success += 1
            else:
                # Otherwise, insert Flare breach data into PE DB
                insert_flare_breaches(total_breach_df)
                LOGGER.info(f"Flare breaches for {org_abbrv} successfully inserted into PE database")
                # Retrieve breach UIDs for the credential records
                breach_uid_df = get_cred_breach_uids(list(total_cred_df["breach_name"]))
                breach_dict = dict(zip(breach_uid_df["breach_name"], breach_uid_df["credential_breaches_uid"]))
                # Add breach UIDs to credential records
                for idx, row in total_cred_df.iterrows():
                    breach_uid = breach_dict.get(row["breach_name"])
                    total_cred_df.at[idx, "credential_breaches_uid"] = breach_uid
                # Insert Flare credential data into PE DB
                insert_flare_credentials(total_cred_df)
                LOGGER.info(f"Flare credentials for {org_abbrv} successfully inserted into PE database")
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
        f"{success}/{len(pe_orgs_final)} organizations successfully completed their Flare leaked creds data collection"
    )
    LOGGER.info(
        f"{failed}/{len(pe_orgs_final)} organizations encountered an error during their Flare leaked creds data collection: {failed_list}"
    )
