"""Scripts to download and maintain blocklist.de's blocklist locally."""

# Standard Python Libraries
import logging

# Third-Party Libraries
import datetime
import pandas as pd
import requests
from requests.adapters import HTTPAdapter, Retry
import sys
from data.pe_db.db_query_source import connect

# Set up logging
LOGGER = logging.getLogger(__name__)

def download_blocklist_as_dict(
    url: str = "https://lists.blocklist.de/lists/all.txt",
) -> dict:
    """Download full blocklist from the given URL and returns as dictionary."""
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()  # Raises an HTTPError if the response was unsuccessful
        lines = response.text.splitlines()
        blocklist_dict = {line.strip(): True for line in lines if line.strip()}
        return blocklist_dict
    except requests.RequestException as e:
        LOGGER.warning("Failed to download blocklist: %s", e)
        return {}

def query_blocklist_api(ip_str):
    """Query blocklist API for the given IP address and return info."""
    # Call API to retrieve IP info
    session = requests.Session()
    retries = Retry(
        total=5,
        backoff_factor=0.1,
        status_forcelist=[500, 502, 503, 504, 429]
    )
    session.mount("http://", HTTPAdapter(max_retries=retries))
    response = session.get(
        "http://api.blocklist.de/api.php?ip=" + ip_str,
        timeout=60,
    ).content
    response = str(response)
    # Parse IP info
    malicious = False
    attacks = int(str(response).split("attacks: ")[1].split("<")[0])
    reports = int(str(response).split("reports: ")[1].split("<")[0])
    if attacks > 0 or reports > 0:
        malicious = True
    return malicious, attacks, reports

def get_current_blocklist():
    """Get the current blocklist in the local database."""
    try:
        conn = connect()
        query = "SELECT * FROM blocklist"
        df = pd.read_sql_query(query, conn)
        conn.close()
        return df
    except Exception as e:
        LOGGER.error("Error: Failed retrieving current blocklist from database")

def create_blocklist_records(create_list):
    """Create records in the blocklist database table for the specified IPs."""
    if len(create_list) != 0:
        print(f"Creating {len(create_list)} block list records...")
        # Retrieve details for all IPs
        print("Retrieving blocklist details for IPs")
        values_str = ""
        curr_timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for idx, ip_str in enumerate(create_list):
            try:
                # Query ip details from blocklist.de API
                malicious, attacks, reports = query_blocklist_api(ip_str)
                values_str += f"\t('{ip_str}', '{curr_timestamp}', '{curr_timestamp}', {malicious}, {attacks}, {reports}),\n"
                print(f"\tRetrieved Blocklist.de info for IP \"{ip_str}\" ({idx+1} of {len(create_list)})")
            except Exception as e:
                LOGGER.warning("\tFailed to get blocklist info for IP %s: %s", ip_str, e)
                continue
        values_str = values_str[:-2]
        # Bulk create new records
        try:
            conn = connect()
            cursor = conn.cursor()
            query = f"""
            INSERT INTO blocklist (ip, created_at, updated_at, malicious, attacks, reports)
            VALUES
            {values_str}
            """
            cursor.execute(query)
            conn.commit()
            conn.close()
            print(f"Created {len(create_list)} block list records successfully")
        except Exception as e:
            print(f"Error: Failed to create {len(create_list)} block list records")
    else:
        print("No records to create, skipping")


def update_blocklist_records(update_list):
    """Update records in the blocklist database table for the specified IPs."""
    if len(update_list) != 0:
        print(f"Updating {len(update_list)} blocklist records...")
        conn = connect()
        cursor = conn.cursor()
        for idx, update_record in enumerate(update_list):
            try:
                curr_uid = update_record.get("blocklist_uid")
                curr_ip = update_record.get("ip")
                # Retrieve new details for IP
                malicious, attacks, reports = query_blocklist_api(str(curr_ip))
                updated_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                # Update record
                query = f"""
                UPDATE blocklist 
                SET 
                    updated_at = '{updated_at}',
                    malicious = {malicious},
                    attacks = {attacks},
                    reports = {reports}
                WHERE
                    blocklist_uid = '{curr_uid}'
                """
                cursor.execute(query)
                conn.commit()
                print(f"Updated blocklist record for {curr_ip} ({idx+1} of {len(update_list)})")
            except Exception as e:
                print(f"Error: Failed to update blocklist record for {curr_ip} - {e}")
        conn.close()
    else:
        print("No records to update, skipping")

def delete_blocklist_records(delete_list):
    """Delete the specified records from the local blocklist table."""
    if len(delete_list) != 0:
        print(f"Deleting {len(delete_list)} outdated blocklist records...")
        try:
            conn = connect()
            # compile uids to delete
            uid_list_str = ""
            for uid in delete_list:
                uid_list_str += f"\'{uid}\', "
            uid_list_str = uid_list_str[:-2]
            # execute query
            query = f"DELETE FROM blocklist WHERE blocklist_uid IN ({uid_list_str})"
            cursor = conn.cursor()
            cursor.execute(query)
            conn.commit()
            conn.close()
            print(f"Deleted {len(delete_list)} outdated blocklist records successfully")
        except Exception as e:
            LOGGER.error("Error: Failed deleteing records from blocklist table in database")
    else:
        print("No records to delete, skipping")

def prune_current_blocklist(current_blocklist):
    """Go through the entire current blocklist and check for any records to delete."""
    # Iterate over current blocklist
    print(f"Checking current database blocklist ({len(current_blocklist)} records) for any that need to be deleted")
    delete_list = []
    for idx, record in current_blocklist.iterrows():
        curr_ip = record["ip"]
        curr_uid = record["blocklist_uid"]
        # Check IP against blocklist.de API
        curr_malicious, curr_attacks, curr_reports = query_blocklist_api(curr_ip)
        if (curr_attacks == 0) & (curr_reports == 0):
            # If no attacks or reports on record, mark for deletion
            print(f"({idx+1}/{len(current_blocklist)}) IP marked for deletion: {curr_ip}")
            delete_list.append(curr_uid)
        else:
            print(f"({idx+1}/{len(current_blocklist)}) Keeping IP: {curr_ip}")
    
    # Delete records
    print(f"Pruning records with uids: {delete_list}")
    delete_blocklist_records(delete_list)

def refresh_blocklist(prune=False):
    """Update local database blocklist based on the latest blocklist.de download."""
    # Download the latest blocklist.de 48h list
    new_blocklist = download_blocklist_as_dict()
    if len(new_blocklist) == 0:
        LOGGER.warning("Error: Failed to download latest 48h blocklist data.")
        return
    # Query the current blocklist from the database
    current_blocklist = get_current_blocklist()

    # Iterate over the current blocklist
    update_list = []
    for idx, record in current_blocklist.iterrows():
        curr_uid = record["blocklist_uid"]
        curr_ip = record["ip"]
        if curr_ip in new_blocklist:
            # If ip is in the latest blocklist, update record
            update_list.append(
                {
                    "blocklist_uid": curr_uid,
                    "ip": curr_ip,
                }
            )
            # Keep track of new IPs to add
            new_blocklist.pop(curr_ip, None)
    create_list = list(new_blocklist.keys())

    # Update any existing blocklist records in the database
    update_blocklist_records(update_list)
    # Create any records that are in the latest blocklist, but not yet in the database
    create_blocklist_records(create_list)

    # If prune requested, review database blocklist for any records to be deleted
    if prune:
        print(f"Prune requested, deleting outdated records...")
        prune_current_blocklist(current_blocklist)

if __name__ == '__main__':
    if len(sys.argv) > 1:
        arguments = sys.argv[1:]
        if arguments[0] == "prune":
            print("Running database blocklist refresh, pruning requested...")
            refresh_blocklist(prune=True)
        else:
            print(f"Error: unrecognized argument '{arguments[0]}'")
    else:
        print("Running database blocklist refresh, no pruning requested...")
        refresh_blocklist()
    