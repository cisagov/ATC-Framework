"""Scan to pull top 10 CVE data from Cybersixgill for the Threat Hunt team."""
# Standard Python Libraries
import datetime
import json
import logging
import math
import time

# Third-Party Libraries
import pandas as pd
import requests

# Setup logging
main_log = logging.getLogger(__name__)

# C6G API credentials:
client_id = ""  # nosec
client_secret = ""  # nosec


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
    retry_ct = 1
    while retry_ct <= 10:
        try:
            resp = requests.post(url, headers=headers, data=payload, timeout=60).json()
            break
        except Exception as e:
            print(f"Error fetching token - {e}, trying again...")
            time.sleep(5)
            retry_ct += 1
    return resp["access_token"]


def dve_enrich_endpoint():
    """Call the cybersixgill dve_enrich endpoint."""
    url = "https://api.cybersixgill.com/dve_enrich/enrich"
    auth = cybersix_token()
    main_log.info("Cybersixgill auth token retrieved")
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-cache",
        "Authorization": "Bearer " + auth,
    }
    data = json.dumps(
        {
            "filters": {
                "sixgill_rating_range": {"from": 6, "to": 10},
            },
            "results_size": 10,
            "enriched": True,
            "from_index": 0,
        }
    )
    # Attempt initial API call
    main_log.info("Calling cybersixgill dve_enrich API endpoint")
    resp = requests.post(url, headers=headers, data=data, timeout=60)

    # Retry clause if call fails
    retry_count = 1
    while resp.status_code != 200 and retry_count <= 10:
        main_log.error(f"dve_enrich endpoint call failed, code: {resp.status_code}")
        main_log.error(f"\tRetrying in 5 sec - retry {retry_count} of 10")
        time.sleep(5)
        resp = requests.post(url, headers=headers, data=data, timeout=60)
        retry_count += 1
    return resp.json()


def intel_items_endpoint(query, start_date, end_date, results_size, start_index):
    """Call the cybersixgill intel_items endpoint."""
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
            "highlight": True,
            # careful w/ highlight tags, they can cause parsing errors
            "custom_highlight_start_tag": "@@keyword>@@",
            "custom_highlight_end_tag": "@@<keyword@@",
        }
    )
    # Attempt initial API call
    main_log.info("Calling cybersixgill intel_items API endpoint")
    resp = requests.post(url, headers=headers, data=data, timeout=60)
    # Retry clause if call fails
    retry_count = 1
    while resp.status_code != 200 and retry_count <= 10:
        main_log.error(f"intel_items endpoint call failed, code: {resp.status_code}")
        main_log.error(f"\tRetrying in 5 sec - retry {retry_count} of 10")
        time.sleep(5)
        resp = requests.post(url, headers=headers, data=data, timeout=60)
        retry_count += 1
    return resp.json()


def top_cves():
    """Retrieve the current top 10 CVEs from Cybersixgill based on DVE score."""
    # Make API call
    resp = dve_enrich_endpoint()
    # Process data
    result_list = resp.get("objects")
    final_results = []
    for result in result_list:
        x_sixgill_info = result.get("x_sixgill_info")
        attribute_dict = {
            item["name"]: item
            for item in result.get("x_sixgill_info").get("attributes")
        }
        # Parse CVE info
        cve_id = result.get("name")
        summary = result.get("description").strip()
        published = x_sixgill_info.get("nvd").get("published", None)
        dve_score = x_sixgill_info.get("rating").get("current")
        if x_sixgill_info.get("nvd").get("v3") is None:
            nvd_v3_score = "N/A"
            cvss_v3_vector = "N/A"
        else:
            nvd_v3_score = x_sixgill_info.get("nvd").get("v3").get("current", None)
            cvss_v3_vector = x_sixgill_info.get("nvd").get("v3").get("vector", None)
        if x_sixgill_info.get("nvd").get("v2") is None:
            nvd_v2_score = "N/A"
        else:
            nvd_v2_score = x_sixgill_info.get("nvd").get("v2").get("current", None)

        attr_verified = attribute_dict.get("Is_Verified_Exploit").get("value")
        attr_wild_exploit = attribute_dict.get("Has_Exploit_in_the_wild_attribute").get(
            "value"
        )
        attr_exploit_kit = attribute_dict.get("Has_Exploit_kit_attribute").get("value")
        attr_poc_exploit = attribute_dict.get("Has_POC_exploit_attribute").get("value")
        attr_trend_underground = attribute_dict.get(
            "Is_Trend_Underground_attribute"
        ).get("value")
        attr_apt = attribute_dict.get("Is_Related_APT_attribute").get("value")
        attr_ransomware = attribute_dict.get("Is_Related_Ransomware_attribute").get(
            "value"
        )
        total_mentions = x_sixgill_info.get("mentions").get("mentions_total", None)
        last_mentioned = x_sixgill_info.get("mentions").get("last_mention", None)
        nvd_link = x_sixgill_info.get("nvd").get("link", None)
        cve_record = {
            "cve_id": cve_id,
            "summary": summary,
            "published": published,
            "cybersixgill_dve_score": dve_score,
            "nvd_v3_score": nvd_v3_score,
            "nvd_v2_score": nvd_v2_score,
            "cvss_vector": cvss_v3_vector,
            "attr_is_verified": attr_verified,
            "attr_has_been_exploited_in_wild": attr_wild_exploit,
            "attr_is_part_of_exploit_kit": attr_exploit_kit,
            "attr_has_poc_exploit": attr_poc_exploit,
            "attr_is_apt_related": attr_apt,
            "attr_is_ransomware_related": attr_ransomware,
            "attr_is_trending_underground": attr_trend_underground,
            "total_mentions": total_mentions,
            "last_mentioned": last_mentioned,
            "nvd_link": nvd_link,
        }
        # Add CVE info to list
        final_results.append(cve_record)
    # Return final results
    return pd.DataFrame(final_results)


def keywords():
    """Retrieve all cybersixgill darkweb findings containing a set of keywords."""
    # Load in current full keyword set
    keyword_csv = pd.read_csv("./Darkfeed_terms.csv", engine=None)
    keyword_list = list(keyword_csv["Terms"])
    # Revise query keywords
    keyword_block_list = [
        # Most general terms
        "China",
        "CVE",
        "CWE",
        "exploit",
        "IOC",
        "Iran",
        "North Korea",
        "Russia",
        "vulnerability"
        # Moderately general terms
        # "backdoor",
        # "botnet",
        # "injection",
        # "keylogging",
        # "pivoting",
        # "PoC",
        # "ransomware",
    ]
    keyword_list = [x for x in keyword_list if x not in keyword_block_list]
    # Build query
    site_block_list = [
        "github",
        "nvd",
        "reddit",
        "twitter",
        "forum_4chan",
    ]
    source_type_list = [
        "cert",
        "forum",
        "isac",
        "market",
    ]
    query = (
        '("'
        + '" OR "'.join(keyword_list)
        + '")'
        + ' AND NOT site:("'
        + '" "'.join(site_block_list)
        + '")'
        + ' AND ( source_type:("'
        + '" "'.join(source_type_list)
        + '") OR (site:forum* OR site:market* OR site:rw*) )'
        # + ' AND site_grade:("4" "5")' # blocks certs and isacs for some reason
    )
    end_date = datetime.datetime.today().strftime("%Y-%m-%d")
    start_date = (datetime.datetime.today() - datetime.timedelta(days=1)).strftime(
        "%Y-%m-%d"
    )

    # Make initial API call to get total number of results
    num_results = None
    main_log.info("Retrieving number of query results...")
    initial_result = intel_items_endpoint(query, start_date, end_date, 1, 0)
    num_results = initial_result.get("total_intel_items")
    main_log.info(
        f"{num_results} results found for query between {start_date} and {end_date}"
    )

    # Call sixgill API again to retrieve all results
    chunk_size = 200  # set chunk size
    time_delay = 1  # set delay between chunk calls
    if num_results == 0:
        # If there are no results, exit early
        main_log.info("No results found for that query")
        return None
    elif num_results > chunk_size:
        # If there are more results than chunk_size, break into chunks
        main_log.info(
            f"More than {chunk_size} query results found, breaking into chunks and retrieving..."
        )
        overall_list = []
        num_chunks = math.ceil(num_results / chunk_size)
        chunk_idx = 0
        # Retrieve each data chunk
        for i in range(0, num_chunks):
            main_log.info(f"Working on chunk {i+1} of {num_chunks}...")
            chunk_result = intel_items_endpoint(
                query, start_date, end_date, chunk_size, chunk_idx
            )
            main_log.info(f"\tQuery index from {chunk_idx} to {chunk_idx+chunk_size}")
            overall_list.extend(chunk_result.get("intel_items"))
            main_log.info(
                f"\tChunk {i+1} complete, {len(overall_list)} results retrieved overall"
            )
            chunk_idx += chunk_size
            time.sleep(time_delay)
        main_log.info("All results retrieved")
    else:
        # If there are less results than chunk_size, just make one call
        main_log.info("Retrieving query results...")
        result = intel_items_endpoint(query, start_date, end_date, chunk_size, 0)
        overall_list = result.get("intel_items")
        main_log.info("All results retrieved")

    # Clean up and format final results
    final_result_df = pd.DataFrame(overall_list)
    target_cols = [
        "date",
        "language",
        "title",
        "content",
        "comments_count",
        "malware",
        "ransomware",
        "ips",
        "iab",  # sorta useful?
        "apt",  # sorta useful?
        "creator",
        "rep_grade",  # creator_grade
        "site",
        "site_grade",
        "source_type",  # site_type
        "type",  # post_type
        "category",  # post_category
        "tags",
        "url",  # post_url
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
    # Rename columns for clarity
    final_result_df.rename(
        columns={
            "rep_grade": "creator_grade",
            "type": "post_type",
            "category": "post_category",
            "url": "post_url",
        },
        inplace=True,
    )
    # Fix issue w/ escape character in "content" field
    final_result_df.replace({"\x00": ""}, regex=True, inplace=True)
    # Return results as dataframe
    return final_result_df


def keywords_hist_data():
    """Get historical result counts for line chart."""
    main_log.info("Retrieving historical data for line chart")
    # Load in current full keyword set
    keyword_csv = pd.read_csv("./Darkfeed_terms.csv", engine=None)
    keyword_list = list(keyword_csv["Terms"])
    # Revise query keywords
    keyword_block_list = [
        # Most general terms
        "China",
        "CVE",
        "CWE",
        "exploit",
        "IOC",
        "Iran",
        "North Korea",
        "Russia",
        "vulnerability",
    ]
    keyword_list = [x for x in keyword_list if x not in keyword_block_list]
    # Build query
    site_block_list = [
        "github",
        "nvd",
        "reddit",
        "twitter",
        "forum_4chan",
    ]
    source_type_list = [
        "cert",
        "forum",
        "isac",
        "market",
    ]
    query = (
        '("'
        + '" OR "'.join(keyword_list)
        + '")'
        + ' AND NOT site:("'
        + '" "'.join(site_block_list)
        + '")'
        + ' AND ( source_type:("'
        + '" "'.join(source_type_list)
        + '") OR (site:forum* OR site:market* OR site:rw*) )'
    )

    # retrieve total result counts for the past 4 days
    final_results_list = []
    today = datetime.datetime.today()
    for i in range(0, 4):
        # Query total results for the current date
        curr_end_date = (today - datetime.timedelta(days=i)).strftime("%Y-%m-%d")
        curr_start_date = (today - datetime.timedelta(days=i + 1)).strftime("%Y-%m-%d")
        # Make initial API call to get total number of results
        initial_result = intel_items_endpoint(
            query, curr_start_date, curr_end_date, 1, 0
        )
        num_results = initial_result.get("total_intel_items")
        row_results = {
            "Scan Date": curr_end_date,
            "Total Results": num_results,
        }
        final_results_list.insert(0, row_results)
        # print(f"Period: {curr_start_date} to {curr_end_date}, results: {num_results}")
    final_results_df = pd.DataFrame.from_dict(final_results_list, orient="columns")
    final_results_df.set_index("Scan Date", inplace=True)
    # return final results
    return final_results_df
