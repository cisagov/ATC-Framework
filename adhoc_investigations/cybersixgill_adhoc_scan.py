"""Adhoc version of the CyberSixGill scan."""
# Standard Python Libraries
import json
import logging
import math
import time

# Third-Party Libraries
import pandas as pd
import requests

# .ini Data
import adhoc_config

# Setup logging
main_log = logging.getLogger(__name__)

# Sixgill api info
client_id = adhoc_config.get_ini_data().get("cybersixgill_id")
client_secret = adhoc_config.get_ini_data().get("cybersixgill_secret")


def cybersix_token():
    """Retrieve bearer token from Cybersixgill client."""
    url = "https://api.cybersixgill.com/auth/token/"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Cache-Control": "no-cache",
    }
    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    resp = requests.post(url, headers=headers, data=payload).json()
    return resp["access_token"]


def call_sixgill_intel_items(query, start_date, end_date, results_size, start_index):
    """Get data about a specific CVE."""
    url = "https://api.cybersixgill.com/intel/intel_items"
    auth = cybersix_token()
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": "Bearer " + auth,
    }
    data = json.dumps(
        {
            "query": query,
            "date_range": f"{start_date} TO {end_date}",
            "results_size": results_size,
            "from": start_index,
            # "highlight": True,
        }
    )
    # Make initial attempt to call cybersixgill API
    resp = requests.post(url, headers=headers, data=data)
    # Retry if API fails
    retry_max = 10
    retry_count = 1
    while resp.status_code != 200 and retry_count <= retry_max:
        main_log.error(f"Cybersixgill API call failed, code: {resp.status_code}")
        main_log.error(f"\tRetrying in 5 sec - retry {retry_count} of {retry_max}")
        time.sleep(5)
        resp = requests.post(url, headers=headers, data=data)
        retry_count += 1
    return resp.json()


def get_cybersixgill_data(org_uid, org_abbrv, query, start_date, end_date, chunk_size, time_delay, save_file):
    """Retrieve Cybersixgill data for the specified organization."""
    main_log.info(f"=== {org_abbrv} Cybersixgill Adhoc Scan Starting ===")
    main_log.info(f"Submitting this query to the cybersixgill API: {query}")
    # Make initial call to sixgill API to get number of results
    num_results = None
    while num_results is None:
        main_log.info("Retrieving number of query results...")
        initial_result = call_sixgill_intel_items(query, start_date, end_date, 1, 0)
        num_results = initial_result.get("total_intel_items")
        if num_results is None:
            main_log.error("Issue making initial sixgill API call, trying again")
            time.sleep(time_delay)
    main_log.info(f"{num_results} results found for {org_abbrv} query between {start_date} and {end_date}")

    # Call sixgill API to retrieve all the results
    if num_results == 0:
        # If there are no results
        main_log.info("No results found for that query")
        main_log.info(f"=== {org_abbrv} Cybersixgill Adhoc Scan Complete ===")
        return 0
    elif num_results > chunk_size:
        # If there are more results than chunk_size, break into chunks
        main_log.info(f"More than {chunk_size} query results found, breaking into chunks and retrieving...")
        overall_list = []
        num_chunks = math.ceil(num_results / chunk_size)
        chunk_idx = 0
        for i in range(0, num_chunks):
            main_log.info(f"On chunk {i+1} of {num_chunks}...")
            chunk_result = call_sixgill_intel_items(query, start_date, end_date, chunk_size, chunk_idx)

            while chunk_result.get("intel_items") is None:
                time.sleep(time_delay)
                main_log.info("\tSixgill API overloaded, trying again...")
                chunk_result = call_sixgill_intel_items(query, start_date, end_date, chunk_size, chunk_idx)
            
            main_log.info(f"\tQuery index from {chunk_idx} to {chunk_idx+chunk_size}")
            overall_list.extend(chunk_result.get("intel_items"))
            main_log.info(f"\tChunk {i+1} complete, {len(overall_list)} results retrieved")
            chunk_idx += chunk_size
            time.sleep(time_delay)
        main_log.info("All chunks retrieved")
    else:
        # If there are less results than chunk_size, just make one call
        main_log.info("Retrieving query results...")
        result = call_sixgill_intel_items(query, start_date, end_date, chunk_size, 0)
        overall_list = result.get("intel_items")
        main_log.info("All results retrieved")
        
    # Clean up and format final results
    final_result_df = pd.DataFrame(overall_list)
    target_cols = [
            "date",
            "language",
            "creator",
            "rep_grade", # creator_grade
            "title",
            "content",
            "comments_count",
            "type", # post_type
            "category", # post_category
            "site",
            "site_grade",
            "source_type", # site_type
            "malware",
            "ransomware",
            "ips",
            "iab", # sorta useful?
            "apt", # sorta useful?
            "tags",
            "url", # post_url
            "post_id", 
            # "cpe/product", # not available via api
            # "domain", # not available via api
            # "email", # not available via api
            # "organization", # not available via api
            # "sector", # not available via api
            # "github", # not available via api
            # "intel_item_url", # not available via api
            # "hash", # not useful
            # "module", # not useful
            # "sub_category", # not useful
            # "id", # not useful
            # "intel_id", # not useful
            # "price", # not useful
            # "financial", not useful
            # "pds", # possibly useful, but adds a LOT of data
        ]   
    final_result_df = final_result_df.reindex(columns=target_cols).fillna("")
    # Fix column names for clarity
    final_result_df.rename(
        columns={
            "type": "post_type",
            "category": "post_category",
            "rep_grade": "creator_grade",
            "source_type": "site_type",
            "iab": "init_access_broker",
            "apt": "adv_persist_threat",
            "url": "post_url",
        },
        inplace=True
    )
    final_result_df.insert(0, "organization", org_abbrv)
    final_result_df.insert(0, "organizations_uid", org_uid)
    # Fix issue w/ escape character in "content" field
    final_result_df.replace({'\x00': ''}, regex=True, inplace=True)
    # Save to file
    main_log.info(f"Saving to file: {save_file[1:]}")
    main_log.info(f"=== {org_abbrv} Cybersixgill Adhoc Scan Complete ===")
    final_result_df.to_csv(save_file)
    return 1
