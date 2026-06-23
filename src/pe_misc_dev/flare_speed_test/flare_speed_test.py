"""Test Flare API speed by endpoint and event type."""

# Standard Python Libraries
import datetime
import os
import time

# Third-Party Libraries
import openpyxl
from openpyxl import load_workbook
import requests
from requests.auth import HTTPBasicAuth

TENANT_ID = 0
PARAM_DICT = {
    "api_key_1": HTTPBasicAuth("", ""),
    "api_key_2": HTTPBasicAuth("", ""),
}
KEY_NUM = 1


def get_flare_token():
    """Get Flare API authentication token."""
    # Use the API key specified by env variable
    api_auth = PARAM_DICT.get(f"api_key_{KEY_NUM}")
    # Get API token
    token_url = "https://api.flare.io/tokens/generate"  # nosec
    headers = {
        "Content-Type": "application/json",
    }
    data = f'{{"tenant_id": {TENANT_ID}}}'
    resp = requests.post(
        token_url, data=data, headers=headers, auth=api_auth, timeout=60
    )
    # Retry clause in case API falters
    retry_count, max_retries, time_delay = 1, 5, 3
    while resp.status_code != 200 and retry_count <= max_retries:
        print(
            f"\tRetrying Flare token API endpoint (code {resp.status_code}), attempt {retry_count} of {max_retries}"
        )
        time.sleep(time_delay)
        resp = requests.post(
            token_url, data=data, headers=headers, auth=api_auth, timeout=60
        )
        retry_count += 1
    # Return results
    if retry_count == max_retries + 1:
        print("Error: Failed to retrieve Flare auth token")
        return None
    else:
        resp = resp.json()
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
    orgs_resp = requests.get(orgs_url, headers=headers, timeout=60)
    # Retry clause in case API falters
    retry_count, max_retries, time_delay = 1, 10, 5
    while orgs_resp.status_code != 200 and retry_count <= max_retries:
        print(
            f"\tRetrying Flare identifier group info API endpoint (code {orgs_resp.status_code}), attempt {retry_count} of {max_retries}"
        )
        time.sleep(time_delay)
        orgs_resp = requests.get(orgs_url, headers=headers, timeout=60)
        retry_count += 1
    # Return results
    if retry_count == max_retries + 1:
        print("Error: Failed to retrieve Flare identifier group info")
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


def get_ident_group_events_chunk(token, ident_group_id, payload):
    """Call the Flare identifier group event feed endpoint."""
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    url = f"https://api.flare.io/firework/v4/events/identifier_groups/{ident_group_id}/_search"
    resp = requests.post(url, headers=headers, json=payload, timeout=60)
    # Retry clause in case API falters
    retry_count, max_retries, time_delay = 1, 5, 3
    while resp.status_code != 200 and retry_count <= max_retries:
        print(
            f"\tRetrying Flare event retrieval API endpoint (code {resp.status_code}), attempt {retry_count} of {max_retries}"
        )
        time.sleep(time_delay)
        resp = requests.post(url, headers=headers, json=payload, timeout=60)
        retry_count += 1
    # Return results
    if retry_count == max_retries + 1:
        print(f"Error: Failed to retrieve Flare events for {ident_group_id}")
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


def get_ident_group_events(
    identifier_group, event_severities, event_types, start_date, end_date
):
    """Retrieve all events for the specified identifier group (organization)."""
    ident_group_name = identifier_group.get("name")
    ident_group_id = identifier_group.get("id")
    print(f"Retrieving all events for the identifier group: {ident_group_name}")
    flare_token = get_flare_token()
    results_list = []
    more_data = False
    curr_next = ""
    chunk_size = 10  # max size is 10
    # Make initial data feed call
    print("Working on data feed chunk 1")
    ini_payload = {
        "size": chunk_size,
        "filters": {
            "severity": event_severities,
            "type": event_types,
            "estimated_created_at": {
                "gte": start_date,
                "lte": end_date,
            },
        },
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
        if retrieve_ct % 500 == 0:  # default 1200
            print("Refreshing Flare API auth token for intial event retrieval")
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
                },
            },
        }
        curr_resp = get_ident_group_events_chunk(
            flare_token, ident_group_id, curr_payload
        )
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
        retrieve_ct += 1

    # Once all data has been retrieved, format and return results
    results_list = [
        {
            "event_uid": item.get("metadata").get("uid"),
            "event_type": item.get("metadata").get("type"),
            "severity": item.get("metadata").get("severity"),
            "identifiers": item.get("identifiers"),
            "event_date": item.get("metadata").get("estimated_created_at"),
        }
        for item in results_list
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
    resp = requests.get(event_detail_url, headers=headers, timeout=60)
    # Retry clause in case API falters
    retry_count, max_retries, time_delay = 1, 10, 5
    while resp.status_code != 200 and retry_count <= max_retries:
        print(
            f"\tRetrying Flare event detail API endpoint (code {resp.status_code}), attempt {retry_count} of {max_retries}"
        )
        time.sleep(time_delay)
        resp = requests.get(event_detail_url, headers=headers, timeout=60)
        retry_count += 1
    # Return results
    if retry_count == max_retries + 1:
        print(f"Error: Failed to retrieve Flare event details for {event_uid}")
        return None
    else:
        return resp.json()


def test_flare_api_speed_event_type():
    """Test Flare API speed by event type."""
    # Retrieve list of flare events for testing
    org_name = "EOP"
    org_info = get_ident_group_info(org_name)
    event_severities = [
        # "info",
        "low",
        "medium",
        "high",
        "critical",
    ]
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
        "stealer_log",  # warning, lots of results (still somewhat acceptable)
        # > Credential Data:
        "leak",
        "leaked_credential",  # *** Incompatible with event details endpoint for some reason
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
    start_date = "2026-03-29"
    end_date = "2026-03-31"
    event_list = get_ident_group_events(
        org_info, event_severities, event_types, start_date, end_date
    )
    # Set up logging for exe logging by event type
    current_date = datetime.date.today().strftime("%Y-%m-%d")
    save_file = (
        os.path.dirname(os.path.abspath(__file__))
        + f"/test_results/event_type_results/event_type_test_results_{current_date}.xlsx"
    )
    if not os.path.exists(save_file):
        workbook = openpyxl.Workbook()
        sheet = workbook["Sheet"]
        sheet.append(
            [
                "org_abbrv",
                "event_uid",
                "event_type",
                "event_date",
                "identifiers",
                "retrieval_time",
            ]
        )
        workbook.save(save_file)
    # Begin retrieving details for each event in list
    flare_token = get_flare_token()
    for idx, event in enumerate(event_list):
        # Refresh auth token every ~30 min (avg event detail api call ~= 0.5s)
        if (idx % 500 == 0) and (idx != 0):  # default 3600
            print("REFRESHING FLARE AUTH TOKEN")
            flare_token = get_flare_token()
        # Retrieve further details for event
        event_uid = event.get("event_uid")
        event_type = event.get("event_type")
        print(
            f"Retrieving details for event {idx+1} of {len(event_list)} - Type: {event_type}"
        )
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
        time_start = time.time()
        get_event_details(event_uid, flare_token)
        time_end = time.time()
        # Record event retrieval time and details to file
        event_exe_stats = [
            org_name,
            event_uid,
            event_type,
            event.get("event_date"),
            str(event.get("identifiers")),
            "{:.5f}".format(
                datetime.timedelta(seconds=(time_end - time_start)).total_seconds()
            ),
        ]
        workbook = load_workbook(save_file)
        sheet = workbook["Sheet"]
        sheet.append(event_exe_stats)
        workbook.save(save_file)


def get_all_ident_by_group_id(ident_group_id):
    """Retrieve all identifiers belonging to the specified identifier group (organization)."""
    print(f"Retrieving all identifiers for the identifier group: {ident_group_id}")
    flare_token = get_flare_token()
    results_list = []
    more_data = False
    curr_next = ""
    # chunk_size = 10  # max size is 10
    # Make initial data feed call
    print("Working on group identifiers chunk 1")
    ini_params = {
        "parent_group_id": ident_group_id,
    }
    ini_resp = get_ident_by_group_id_chunk(flare_token, ini_params)
    results_list += ini_resp.get("ident_list")
    # Check if there's any more data to retrieve
    if ini_resp.get("next_val"):
        more_data = True
        curr_next = ini_resp.get("next_val")
    # If there's a "next" value, continue fetching data
    retrieve_ct = 2
    while more_data:
        # Rate control delay
        time.sleep(1)
        # Refresh auth token every ~30 min (avg event retrieval api call ~= 1.5s)
        if retrieve_ct % 1000 == 0:  # default 1200
            print("Refreshing Flare API auth token for intial event retrieval")
            print("REFRESHING FLARE AUTH TOKEN")
            flare_token = get_flare_token()
        print(f"Working on group identifiers chunk {retrieve_ct}")
        # Make API call for current chunk
        curr_params = {
            "parent_group_id": ident_group_id,
            "from": curr_next,
        }
        curr_resp = get_ident_by_group_id_chunk(flare_token, curr_params)
        # Handle edge case where no results found for this chunk
        if len(curr_resp.get("ident_list")) != 0:
            # Append results
            results_list += curr_resp.get("ident_list")
        # Check if there's anymore data to retrieve
        if curr_resp.get("next_val"):
            # If there's more data, update next value
            curr_next = curr_resp.get("next_val")
        else:
            # If no next value, there's no more data to retrieve
            more_data = False
        retrieve_ct += 1
    # Once all data has been retrieved, format and return results
    print(f"Total number of identifiers retrieved for this group: {len(results_list)}")
    if len(results_list) == 0:
        return [
            {
                "id": None,
                "value": None,
                "type": None,
            }
        ]
    else:
        return results_list


def get_ident_by_group_id_chunk(flare_token, params):
    """Retrieve chunk of identifiers for the specified group ID."""
    url = "https://api.flare.io/firework/v3/identifiers/"
    headers = {"Authorization": f"Bearer {flare_token}"}
    resp = requests.get(url, headers=headers, params=params, timeout=60)
    # Retry clause in case API falters
    retry_count, max_retries, time_delay = 1, 5, 3
    while resp.status_code != 200 and retry_count <= max_retries:
        print(
            f"\tRetrying Flare identifiers by group ID API endpoint (code {resp.status_code}), attempt {retry_count} of {max_retries}"
        )
        time.sleep(time_delay)
        resp = requests.get(url, headers=headers, params=params, timeout=60)
        retry_count += 1
    # Return results
    if retry_count == max_retries + 1:
        print("Error: Failed to retrieve Flare identifiers by group ID")
        return None
    else:
        resp = resp.json()
        next_val = resp.get("next")
        # Format identifier info
        ident_list = []
        for ident in resp.get("items"):
            ident_id = ident.get("id")
            ident_value = ident.get("name")
            ident_type = ident.get("type")
            ident_dict = {"id": ident_id, "value": ident_value, "type": ident_type}
            ident_list.append(ident_dict)
        # Log info
        num_items = len(ident_list)
        more_data = False
        if resp.get("next"):
            more_data = True
        print(f"\tChunk retrieved, contained {num_items} items")
        print(f"\tIs there another chunk to retrieve? {more_data} (next = {next_val})")
        # Return results
        return {
            "ident_list": ident_list,
            "next_val": next_val,
        }
