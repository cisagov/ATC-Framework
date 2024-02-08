"""Query the PE PostgreSQL database."""

# Standard Python Libraries
from datetime import datetime
import json
import logging
import socket
import sys
import time

# Third-Party Libraries
import pandas as pd
import psycopg2
from psycopg2 import OperationalError
import psycopg2.extras as extras
import requests

# cisagov Libraries
from pe_reports import app
from pe_reports.data.config import config, staging_config
from pe_reports.data.db_query import task_api_call

# Setup logging to central file
LOGGER = app.config["LOGGER"]

CONN_PARAMS_DIC = config()
CONN_PARAMS_DIC_STAGING = staging_config()

# These need to filled with API key/url path in database.ini
pe_api_key = CONN_PARAMS_DIC_STAGING.get("pe_api_key")
pe_api_url = CONN_PARAMS_DIC_STAGING.get("pe_api_url")


def show_psycopg2_exception(err):
    """Handle errors for PostgreSQL issues."""
    err_type, err_obj, traceback = sys.exc_info()
    LOGGER.error(
        "Database connection error: %s on line number: %s", err, traceback.tb_lineno
    )


def connect():
    """Connect to PostgreSQL database."""
    try:
        conn = psycopg2.connect(**CONN_PARAMS_DIC)
    except OperationalError as err:
        show_psycopg2_exception(err)
        conn = None
    return conn


def close(conn):
    """Close connection to PostgreSQL."""
    conn.close()


# --- Issue 641 ---
def get_intelx_breaches(source_uid):
    """
    Query API for all IntelX credential breaches.

    Args:
        source_uid: The data source uid to filter credential breaches by

    Return:
        Credential breach data that have the specified data_source_uid as a list of tuples
    """
    # Endpoint info
    task_url = "cred_breach_intelx"
    status_url = "cred_breach_intelx/task/"
    data = json.dumps({"source_uid": source_uid})
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    # Convert result to list of tuples to match original function
    tup_result = [tuple(row.values()) for row in result]
    return tup_result


# --- Issue 653 ---
def insert_sixgill_alerts(new_alerts):
    """
    Query API to insert multiple records into alerts table.

    Args:
        new_alerts: Dataframe containing the new alerts
    """
    # Select specific columns
    cols = [
        "alert_name",
        "content",
        "date",
        "sixgill_id",
        "read",  # bool
        "severity",  # int64
        "site",  # sometimes NaN instead of text
        "threat_level",
        "threats",  # list
        "title",
        "user_id",
        "category",  # float
        "lang",  # float
        "organizations_uid",
        "data_source_uid",
        "content_snip",
        "asset_mentioned",
        "asset_type",
    ]
    # Select specified data fields, missing fields filled with empty strings
    new_alerts = new_alerts.reindex(columns=cols).fillna("")
    # Adjust data types
    new_alerts["date"] = pd.to_datetime(new_alerts["date"])
    new_alerts["date"] = new_alerts["date"].dt.strftime("%Y-%m-%d")
    new_alerts[
        [
            "read",  # bool
            "severity",  # int64
            "site",  # sometimes NaN instead of text
            "threats",  # list
            "category",  # float
            "lang",  # float
        ]
    ] = new_alerts[
        [
            "read",  # bool
            "severity",  # int64
            "site",  # sometimes NaN instead of text
            "threats",  # list
            "category",  # float
            "lang",  # float
        ]
    ].astype(
        str
    )
    new_alerts["threats"] = new_alerts["threats"].str.replace("[", "{")
    new_alerts["threats"] = new_alerts["threats"].str.replace("]", "}")
    new_alerts["threats"] = new_alerts["threats"].str.replace("'", '"')
    # Remove any "[\x00|NULL]" characters if column data type is object
    new_alerts = new_alerts.apply(
        lambda col: col.str.replace(r"(\x00)|(NULL)", "", regex=True)
        if col.dtype == object
        else col
    )
    # Convert dataframe to list of dictionaries
    new_alerts = new_alerts.to_dict("records")
    # Break overall list into chunks of size n
    n = 500
    chunked_list = [
        new_alerts[i * n : (i + 1) * n] for i in range((len(new_alerts) + n - 1) // n)
    ]
    # Iterate through and insert each list chunk
    chunk_ct = 1
    for chunk in chunked_list:
        LOGGER.info(
            "Working on chunk " + str(chunk_ct) + " of " + str(len(chunked_list))
        )
        # Endpoint info
        task_url = "alerts_insert"
        status_url = "alerts_insert/task/"
        data = json.dumps({"new_alerts": chunk})
        # Make API call
        result = task_api_call(task_url, status_url, data, 3)
        chunk_ct += 1
        # Process data and return
        LOGGER.info(result)


# --- 654 ---
def insert_sixgill_mentions(new_mentions):
    """
    Query API to insert multiple records into the mentions table.

    Args:
        df: Dataframe containing mention data to be inserted
    """
    # Convert dataframe to list of dictionaries
    cols = [
        "organizations_uid",
        "data_source_uid",
        "category",
        "collection_date",
        "content",
        "creator",
        "date",
        "sixgill_mention_id",
        "lang",
        "post_id",
        "rep_grade",  # float64
        "site",
        "site_grade",  # int64
        "sub_category",
        "title",
        "type",
        "url",
        "comments_count",  # float64
        "tags",  # float64
    ]
    # Select specified data fields, missing fields filled with empty strings
    new_mentions = new_mentions.reindex(columns=cols).fillna("")
    new_mentions["date"] = new_mentions["date"].str[:10]
    # Remove any "[\x00|NULL]" characters if column data type is object
    new_mentions = new_mentions.apply(
        lambda col: col.str.replace(r"(\x00)|(NULL)", "", regex=True)
        if col.dtype == object
        else col
    )
    # Remove useless image file text from content field
    new_mentions["content"] = new_mentions["content"].str.replace(
        r"(?:@@@SIXGILL_IMAGE?)[^\s]+", "[SIXGILL_IMAGE_FILE]", regex=True
    )
    new_mentions["sub_category"] = "NaN"
    new_mentions[
        [
            "collection_date",
            "date",
            "rep_grade",  # float64
            "site_grade",  # int64
            "title",  # Needs string conversion
            "comments_count",  # float64
            "tags",  # float64
        ]
    ] = new_mentions[
        [
            "collection_date",
            "date",
            "rep_grade",  # float64
            "site_grade",  # int64
            "title",  # Needs str conversion
            "comments_count",  # float64
            "tags",  # float64
        ]
    ].astype(
        str
    )
    new_mentions["comments_count"].replace(
        "nan", "NaN", inplace=True
    )  # switch nan to NaN

    # for col in new_mentions.columns:
    #     max_str_len = new_mentions[col].map(len).max()
    #     print("column: " + col)
    #     print("\tmax string length in col: " + str(max_str_len))

    # Convert dataframe to list of dictionaries
    new_mentions = new_mentions.to_dict("records")
    # Break overall list into chunks of size n
    n = 10
    chunked_list = [
        new_mentions[i * n : (i + 1) * n]
        for i in range((len(new_mentions) + n - 1) // n)
    ]
    # Iterate through and insert each list chunk
    chunk_ct = 1
    for chunk in chunked_list:
        LOGGER.info(
            "Working on chunk " + str(chunk_ct) + " of " + str(len(chunked_list))
        )
        # Endpoint info
        task_url = "mentions_insert"
        status_url = "mentions_insert/task/"
        data = json.dumps({"new_mentions": chunk})
        # Make API call
        result = task_api_call(task_url, status_url, data, 1)
        chunk_ct += 1
        # Process data and return
        LOGGER.info(result)


# --- 655 ---
def insert_sixgill_breaches(new_breaches):
    """
    Query API to insert multiple records into the credential_breaches table.

    Args:
        df: Dataframe containing credential breach data to be inserted
    """
    # Convert dataframe to list of dictionaries
    new_breaches["breach_date"] = new_breaches["breach_date"].astype(str)
    new_breaches["modified_date"] = new_breaches["modified_date"].astype(str)
    new_breaches = new_breaches.to_dict("records")
    # Endpoint info
    task_url = "cred_breaches_sixgill_insert"
    status_url = "cred_breaches_sixgill_insert/task/"
    data = json.dumps({"new_breaches": new_breaches})
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    LOGGER.info(result)


# --- Issue 656 ---
def insert_sixgill_credentials(new_exposures):
    """
    Query API to insert multiple records into credential_exposures table.

    Args:
        new_exposures: Dataframe containing the new credential exposures
    """
    # Convert dataframe to list of dictionaries
    new_exposures = new_exposures.to_dict("records")
    # Endpoint info
    task_url = "cred_exp_sixgill_insert"
    status_url = "cred_exp_sixgill_insert/task/"
    data = json.dumps({"new_exposures": new_exposures})
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    LOGGER.info(result)


# --- 657 ---
def insert_sixgill_topCVEs(new_topcves):
    """
    Query API to insert multiple records into the top_cves table.

    Args:
        df: Dataframe containing top cve data to be inserted
    """
    # Convert dataframe to list of dictionaries
    new_topcves["date"] = new_topcves["date"].astype(str)
    new_topcves = new_topcves.to_dict("records")
    # Endpoint info
    task_url = "top_cves_insert"
    status_url = "top_cves_insert/task/"
    data = json.dumps({"new_topcves": new_topcves})
    # Make API call
    result = task_api_call(task_url, status_url, data, 3)
    # Process data and return
    LOGGER.info(result)


# --- 659 ---
def execute_dnsmonitor_data(df):
    """
    Query API to insert multiple records into the domain_permutations table.

    Args:
        df: Dataframe containing DNSMonitor data to be inserted
    """
    # Endpoint info
    endpoint_url = pe_api_url + "domain_permu_insert"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    # Adjust data types and convert to list of dictionaries
    df["date_observed"] = pd.to_datetime(df["date_observed"])
    df["date_observed"] = df["date_observed"].dt.strftime("%Y-%m-%d")
    df_dict_list = df.to_dict("records")
    data = json.dumps({"insert_data": df_dict_list})
    try:
        # Call endpoint
        result = requests.put(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        LOGGER.info(result)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)


# --- 660 ---
def execute_dnsmonitor_alert_data(df):
    """
    Query API to insert multiple records into the domain_alerts table.

    Args:
        df: Dataframe containing DNSMonitor data to be inserted
    """
    # Endpoint info
    endpoint_url = pe_api_url + "domain_alerts_insert"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    # Adjust data types and convert to list of dictionaries
    df["date"] = pd.to_datetime(df["date"])
    df["date"] = df["date"].dt.strftime("%Y-%m-%d")
    df_dict_list = df.to_dict("records")
    data = json.dumps({"insert_data": df_dict_list})
    try:
        # Call endpoint
        result = requests.put(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        LOGGER.info(result)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)


# --- Issue 661 ---
def addRootdomain(root_domain, pe_org_uid, source_uid, org_name):
    """
    Query API to insert a single root domain into the root_domains table.

    Args:
        root_domain: The root domain associated with the new record
        pe_org_uid: The organizations_uid associated with the new record
        source_uid: The data_source_uid associated with the new record
        org_name: The name of the organization associated with the new record
    """
    # Endpoint info
    endpoint_url = pe_api_url + "root_domains_single_insert"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(
        {
            "root_domain": root_domain,
            "pe_org_uid": pe_org_uid,
            "source_uid": source_uid,
            "org_name": org_name,
        }
    )
    try:
        # Call endpoint
        result = requests.put(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        LOGGER.info(result)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)


# --- Issue 662 ---
def addSubdomain(domain, pe_org_uid, root):
    """
    Query API to insert a single sub domain into the sub_domains table.

    Args:
        domain: The sub domain associated with the new record
        pe_org_uid: The organizations_uid associated with the new record
        root: Boolean whether or not specified domain is also a root domain
    """
    # Endpoint info
    endpoint_url = pe_api_url + "sub_domains_single_insert"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(
        {
            "domain": domain,
            "pe_org_uid": pe_org_uid,
            "root": root,
        }
    )
    try:
        # Call endpoint
        result = requests.put(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        LOGGER.info(result)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)


# --- Issue 663 ---
def insert_intelx_breaches(df):
    """
    Query API to insert multiple records into the credential_breaches table.

    Args:
        df: Dataframe containing IntelX breach data to be inserted
    """
    # Endpoint info
    endpoint_url = pe_api_url + "cred_breaches_intelx_insert"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    # Remove duplicates and convert to list of dictionaries
    df = df.drop_duplicates(subset=["breach_name"])
    df[["breach_date", "added_date", "modified_date"]] = df[
        ["breach_date", "added_date", "modified_date"]
    ].astype(str)
    df_dict_list = df.to_dict("records")
    data = json.dumps({"breach_data": df_dict_list})
    try:
        # Call endpoint
        result = requests.put(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        LOGGER.info(result)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)


# --- Issue 664 ---
def insert_intelx_credentials(df):
    """
    Query API to insert multiple records into the credential_exposures table.

    Args:
        df: Dataframe containing IntelX credential exposure data to be inserted
    """
    # Endpoint info
    endpoint_url = pe_api_url + "cred_exp_intelx_insert"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    # Remove duplicates and convert to list of dictionaries
    df = df.drop_duplicates(subset=["breach_name", "email"])
    df["modified_date"] = df["modified_date"].astype(str)
    df_dict_list = df.to_dict("records")
    data = json.dumps({"exp_data": df_dict_list})
    try:
        # Call endpoint
        result = requests.put(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        LOGGER.info(result)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)


# --- Issue 682 ---
def insert_or_update_business_unit(business_unit_dict):
    """
    Insert a Xpanse business unit record into the PE databawse .

    On conflict, update the old record with the new data

    Args:
        business_unit_dict: Dictionary of column names and values to be inserted

    Return:
        Status on if the record was inserted successfully
    """
    # Endpoint info
    endpoint_url = pe_api_url + "xpanse_business_unit_insert_or_update"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(business_unit_dict, default=str)

    LOGGER.info(data)
    try:
        # Call endpoint
        xpanse_business_unit_insert_result = requests.put(
            endpoint_url, headers=headers, data=data
        ).json()
        # print(xpanse_business_unit_insert_result)
        LOGGER.info("Successfully inserted new record in xpanse_business_units table.")
        return xpanse_business_unit_insert_result
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)


# --- Issue 682 ---
def api_xpanse_alert_insert(xpanse_alert_dict):
    """
    Insert an xpanse alert record and connected assets and services.

    On conflict, update the old record with the new data

    Args:
        xpanse_alert_dict: Dictionary of column names and values to be inserted

    Return:
        Status on if the record was inserted successfully
    """
    # Endpoint info
    endpoint_url = pe_api_url + "xpanse_alert_insert_or_update"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(xpanse_alert_dict, default=str)

    # LOGGER.info(data)
    try:
        # Call endpoint
        xpanse_alert_insert_result = requests.put(
            endpoint_url, headers=headers, data=data
        ).json()
        LOGGER.info(xpanse_alert_insert_result)
        LOGGER.info(
            "Successfully inserted new record in xpanse_alerts table with associated assets and services"
        )
        return xpanse_alert_insert_result
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)


# --- Issue 682 ---
def api_pull_xpanse_vulns(business_unit, modified_date):
    """
    Query API for all domains that have not been recently run through PSHTT.

    Return:
        All subdomains that haven't been run in the last 15 days
    """
    create_task_url = pe_api_url + "xpanse_vulns"
    check_task_url = pe_api_url + "xpanse_vulns/task/"

    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(
        {"business_unit": business_unit, "modified_datetime": modified_date},
        default=str,
    )
    print(data)
    try:
        print("in try")
        # Create task for query
        create_task_result = requests.post(
            create_task_url, headers=headers, data=data
        ).json()

        print(create_task_result)
        task_id = create_task_result.get("task_id")
        LOGGER.info("Created task for xpanse_vuln endpoint query, task_id: %s", task_id)
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"

        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            print(check_task_resp)

            task_status = check_task_resp.get("status")
            LOGGER.info("\tPinged xpanse_vuln status endpoint, status: %s", task_status)
            time.sleep(3)
    except requests.exceptions.HTTPError as errh:
        print("HTTPError")
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
        print("ConnectionError")
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
        print("Timeout")
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
        print("RequestException")
    except json.decoder.JSONDecodeError as err:
        print("JSONDecodeError")
        LOGGER.error(err)

    # Once task finishes, return result
    try:
        if task_status == "Completed":
            print(check_task_resp.get("result"))
            result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
            list_of_dicts = result_df.to_dict("records")
            return list_of_dicts
        else:
            raise Exception(
                "xpanse_vuln query task failed 1, details: ", check_task_resp
            )
    except Exception as e:
        raise Exception("xpanse_vuln query task failed 2, details: ", e)


# --- Issue 696 ---
def api_cve_insert(cve_dict):
    """
    Insert a cve record for  into the cve table with linked products and venders.

    On conflict, update the old record with the new data

    Args:
        cve_dict: Dictionary of column names and values to be inserted

    Return:
        Status on if the record was inserted successfully
    """
    # Endpoint info
    endpoint_url = pe_api_url + "cve_insert_or_update"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(cve_dict, default=str)

    LOGGER.info(data)
    try:
        # Call endpoint
        cve_insert_result = requests.put(
            endpoint_url, headers=headers, data=data
        ).json()
        # print(cve_insert_result)
        LOGGER.info(
            "Successfully inserted new record in cves table with associated cpe products and venders"
        )
        return cve_insert_result
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)


# --- Issue 696 ---
def get_cve_and_products(cve_name):
    """
    Query API to retrieve a CVE and its associated products data for the specified CVE.

    Args:
        cve_name: The CVE name or code

    Return:
        CVE data and a dictionary of venders and products
    """
    # Endpoint info
    endpoint_url = pe_api_url + "get_cve"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"cve_name": cve_name})
    try:
        # Call endpoint
        result = requests.post(endpoint_url, headers=headers, data=data).json()
        # Process data and return

        return result
    except requests.exceptions.HTTPError as errh:
        LOGGER.info(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.info(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.info(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.info(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.info(err)


# --- Issue 696 ---
def query_all_cves(modified_date=None):
    """Query all CVEs added or changed since provided date."""
    start_time = time.time()
    total_num_pages = 1
    page_num = 1
    total_data = []
    # Retrieve data for each page
    while page_num <= total_num_pages:
        # Endpoint info
        create_task_url = "cves_by_modified_date"
        check_task_url = "cves_by_modified_date/task/"

        data = json.dumps(
            {"modified_datetime": modified_date, "page": page_num, "per_page": 500}
        )
        # Make API call
        result = task_api_call(create_task_url, check_task_url, data, 3)
        # Once task finishes, append result to total list
        print(result)
        total_data += result.get("data")
        total_num_pages = result.get("total_pages")
        LOGGER.info("Retrieved page: " + str(page_num) + " of " + str(total_num_pages))
        page_num += 1
    # Once all data has been retrieved, return overall tuple list
    # total_data = pd.DataFrame.from_dict(total_data)
    total_data = [tuple(dic.values()) for dic in total_data]
    LOGGER.info("Total time to retrieve cves: %s", (time.time() - start_time))
    # total_data["first_seen"] = pd.to_datetime(total_data["first_seen"]).dt.date
    # total_data["last_seen"] = pd.to_datetime(total_data["last_seen"]).dt.date
    return total_data


# --- Pshtt Scan ---
def api_pshtt_domains_to_run():
    """
    Query API for all domains that have not been recently run through PSHTT.

    Return:
        All subdomains that haven't been run in the last 15 days
    """
    create_task_url = pe_api_url + "pshtt_unscanned_domains"
    check_task_url = pe_api_url + "pshtt_unscanned_domains/task/"

    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }

    try:
        print("in try")
        # Create task for query
        create_task_result = requests.post(
            create_task_url,
            headers=headers,
            # data = data
        ).json()

        print(create_task_result)
        task_id = create_task_result.get("task_id")
        LOGGER.info(
            "Created task for pshtt_domains_to_run endpoint query, task_id: %s", task_id
        )
        # Once task has been started, keep pinging task status until finished
        check_task_url += task_id
        task_status = "Pending"

        while task_status != "Completed" and task_status != "Failed":
            # Ping task status endpoint and get status
            check_task_resp = requests.get(check_task_url, headers=headers).json()
            print(check_task_resp)

            task_status = check_task_resp.get("status")
            LOGGER.info(
                "\tPinged pshtt_domains_to_run status endpoint, status: %s", task_status
            )
            time.sleep(3)
    except requests.exceptions.HTTPError as errh:
        print("HTTPError")
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
        print("ConnectionError")
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
        print("Timeout")
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
        print("RequestException")
    except json.decoder.JSONDecodeError as err:
        print("JSONDecodeError")
        LOGGER.error(err)

    # Once task finishes, return result
    try:
        if task_status == "Completed":
            result_df = pd.DataFrame.from_dict(check_task_resp.get("result"))
            list_of_dicts = result_df.to_dict("records")
            return list_of_dicts
        else:
            raise Exception(
                "pshtt_domains_to_run query task failed, details: ", check_task_resp
            )
    except Exception as e:
        raise Exception("pshtt_domains_to_run query task failed, details: ", e)


# --- Pshtt Scan ---
def api_pshtt_insert(pshtt_dict):
    """
    Insert a pshtt record for an subdomain into the pshtt_records table.

    On conflict, update the old record with the new data

    Args:
        pshtt_dict: Dictionary of column names and values to be inserted

    Return:
        Status on if the record was inserted successfully
    """
    # Endpoint info
    endpoint_url = pe_api_url + "pshtt_result_update_or_insert"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(pshtt_dict, default=str)

    LOGGER.info(data)
    try:
        # Call endpoint
        pshtt_insert_result = requests.put(
            endpoint_url, headers=headers, data=data
        ).json()
        print(pshtt_insert_result)
        return pshtt_insert_result
        LOGGER.info("Successfully inserted new record in report_summary_stats table")
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)


# v ===== ACTIVE TSQL THAT STILL NEEDS CONVERSION ===== v
# Conversion in progress
def get_orgs():
    """Query organizations table."""
    conn = connect()
    try:
        cur = conn.cursor()
        sql = """SELECT * FROM organizations"""
        cur.execute(sql)
        pe_orgs = cur.fetchall()
        keys = ("org_uid", "org_name", "cyhy_db_name")
        pe_orgs = [dict(zip(keys, values)) for values in pe_orgs]
        cur.close()
        return pe_orgs
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


# Conversion in progress
def get_ips(org_uid):
    """Get IP data."""
    conn = connect()
    sql = """SELECT wa.asset as ip_address
            FROM web_assets wa
            WHERE wa.organizations_uid = %(org_uid)s
            and wa.report_on = True
            """
    df = pd.read_sql(sql, conn, params={"org_uid": org_uid})
    ips = list(df["ip_address"].values)
    conn.close()
    return ips


# Conversion in progress
def get_data_source_uid(source):
    """Get data source uid."""
    conn = connect()
    cur = conn.cursor()
    sql = """SELECT * FROM data_source WHERE name = '{}'"""
    cur.execute(sql.format(source))
    source = cur.fetchone()[0]
    cur.close()
    cur = conn.cursor()
    # Update last_run in data_source table
    date = datetime.today().strftime("%Y-%m-%d")
    sql = """update data_source set last_run = '{}'
            where name = '{}';"""
    cur.execute(sql.format(date, source))
    cur.close()
    close(conn)
    return source


# Conversion in progress
def get_breaches():
    """Get credential breaches."""
    conn = connect()
    try:
        cur = conn.cursor()
        sql = """SELECT breach_name, credential_breaches_uid FROM credential_breaches"""
        cur.execute(sql)
        pe_orgs = cur.fetchall()
        cur.close()
        return pe_orgs
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


# Conversion in progress
def insert_shodan_data(dataframe, table, thread, org_name, failed):
    """Insert Shodan data into database."""
    conn = connect()
    tpls = [tuple(x) for x in dataframe.to_numpy()]
    cols = ",".join(list(dataframe.columns))
    sql = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (organizations_uid, ip, port, protocol, timestamp)
    DO NOTHING;"""
    cursor = conn.cursor()
    try:
        extras.execute_values(
            cursor,
            sql.format(
                table,
                cols,
            ),
            tpls,
        )
        conn.commit()
        LOGGER.info(
            "{} Data inserted using execute_values() successfully - {}".format(
                thread, org_name
            )
        )
    except Exception as e:
        LOGGER.error("{} failed inserting into {}".format(org_name, table))
        LOGGER.error("{} {} - {}".format(thread, e, org_name))
        failed.append("{} failed inserting into {}".format(org_name, table))
        conn.rollback()
    cursor.close()
    return failed


# ???
def query_orgs_rev():
    """Query orgs in reverse."""
    conn = connect()
    sql = "SELECT * FROM organizations WHERE report_on is True ORDER BY organizations_uid DESC;"
    df = pd.read_sql_query(sql, conn)
    close(conn)
    return df


# Conversion in progress
def getSubdomain(conn, domain):
    """Get subdomains given a domain from the databases."""
    cur = conn.cursor()
    sql = """SELECT * FROM sub_domains sd
        WHERE sd.sub_domain = %(domain)s"""
    cur.execute(sql, {"domain": domain})
    sub = cur.fetchone()
    cur.close()
    return sub


# Conversion in progress
def getDataSource(conn, source):
    """Get datasource information from a database."""
    cur = conn.cursor()
    sql = """SELECT * FROM data_source WHERE name=%(s)s"""
    cur.execute(sql, {"s": source})
    source = cur.fetchone()
    cur.close()
    return source


# Conversion in progress
def org_root_domains(conn, org_uid):
    """Get root domains from database given the org_uid."""
    sql = """
        select * from root_domains rd
        where rd.organizations_uid = %(org_id)s;
    """
    df = pd.read_sql_query(sql, conn, params={"org_id": org_uid})
    return df


# Conversion in progress
def get_root_domains(conn, org_uid):
    """Get root domains from database given the org_uid."""
    sql = """
        select * from root_domains rd
        where rd.organizations_uid = %(org_id)s
        and enumerate_subs is True;
    """
    df = pd.read_sql_query(sql, conn, params={"org_id": org_uid})
    return df


# v ===== OLD TSQL VERSIONS OF FUNCTIONS ===== v
# --- 641 OLD TSQL ---
def get_intelx_breaches_tsql(source_uid):
    """Get IntelX credential breaches."""
    conn = connect()
    try:
        cur = conn.cursor()
        sql = """SELECT breach_name, credential_breaches_uid FROM credential_breaches where data_source_uid = %s"""
        cur.execute(sql, [source_uid])
        all_breaches = cur.fetchall()
        cur.close()
        return all_breaches
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


# --- 653 OLD TSQL ---
def insert_sixgill_alerts_tsql(df):
    """Insert sixgill alert data."""
    conn = connect()
    columns_to_subset = [
        "alert_name",
        "content",
        "date",
        "sixgill_id",
        "read",
        "severity",
        "site",
        "threat_level",
        "threats",
        "title",
        "user_id",
        "category",
        "lang",
        "organizations_uid",
        "data_source_uid",
        "content_snip",
        "asset_mentioned",
        "asset_type",
    ]
    try:
        df = df.loc[:, df.columns.isin(columns_to_subset)]
    except Exception as e:
        logging.error(e)
    table = "alerts"
    # Create a list of tuples from the dataframe values
    tuples = [tuple(x) for x in df.to_numpy()]
    # Comma-separated dataframe columns
    cols = ",".join(list(df.columns))
    # SQL query to execute
    query = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (sixgill_id) DO UPDATE SET
    content = EXCLUDED.content,
    content_snip = EXCLUDED.content_snip,
    asset_mentioned = EXCLUDED.asset_mentioned,
    asset_type = EXCLUDED.asset_type;"""
    cursor = conn.cursor()
    try:
        extras.execute_values(
            cursor,
            query.format(
                table,
                cols,
            ),
            tuples,
        )
        conn.commit()
        logging.info("Successfully inserted/updated alert data into PE database.")
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error(error)
        conn.rollback()
    cursor.close()


# --- 654 OLD TSQL ---
def insert_sixgill_mentions_tsql(df):
    """Insert sixgill mention data."""
    conn = connect()
    columns_to_subset = [
        "organizations_uid",
        "data_source_uid",
        "category",
        "collection_date",
        "content",
        "creator",
        "date",
        "sixgill_mention_id",
        "lang",
        "post_id",
        "rep_grade",
        "site",
        "site_grade",
        "sub_category",
        "title",
        "type",
        "url",
        "comments_count",
        "tags",
    ]
    try:
        df = df.loc[:, df.columns.isin(columns_to_subset)]
    except Exception as e:
        logging.error(e)

    # Remove any "[\x00|NULL]" characters
    df = df.apply(
        lambda col: col.str.replace(r"[\x00|NULL]", "", regex=True)
        if col.dtype == object
        else col
    )
    table = "mentions"
    # Create a list of tuples from the dataframe values
    tuples = [tuple(x) for x in df.to_numpy()]
    # Comma-separated dataframe columns
    cols = ",".join(list(df.columns))
    # SQL query to execute
    query = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (sixgill_mention_id) DO NOTHING;"""
    cursor = conn.cursor()
    try:
        extras.execute_values(
            cursor,
            query.format(
                table,
                cols,
            ),
            tuples,
        )
        conn.commit()
        logging.info("Successfully inserted/updated mention data into PE database.")
    except (Exception, psycopg2.DatabaseError) as error:
        logging.error(error)
        conn.rollback()
    cursor.close()


# --- 655 OLD TSQL ---
def insert_sixgill_breaches_tsql(df):
    """Insert sixgill breach data."""
    conn = connect()
    table = "credential_breaches"
    # Create a list of tuples from the dataframe values
    tuples = [tuple(x) for x in df.to_numpy()]
    # Comma-separated dataframe columns
    cols = ",".join(list(df.columns))
    # SQL query to execute
    query = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (breach_name) DO UPDATE SET
    password_included = EXCLUDED.password_included;"""
    cursor = conn.cursor()
    try:
        extras.execute_values(
            cursor,
            query.format(
                table,
                cols,
            ),
            tuples,
        )
        conn.commit()
        logging.info("Successfully inserted/updated breaches into PE database.")
    except (Exception, psycopg2.DatabaseError) as error:
        logging.info(error)
        conn.rollback()
    cursor.close()


# --- 656 OLD TSQL ---
def insert_sixgill_credentials_tsql(df):
    """Insert sixgill credential data."""
    conn = connect()
    table = "credential_exposures"
    # Create a list of tuples from the dataframe values
    tuples = [tuple(x) for x in df.to_numpy()]
    # Comma-separated dataframe columns
    cols = ",".join(list(df.columns))
    # SQL query to execute
    query = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (breach_name, email) DO UPDATE SET
    modified_date = EXCLUDED.modified_date;"""
    cursor = conn.cursor()
    try:
        extras.execute_values(
            cursor,
            query.format(
                table,
                cols,
            ),
            tuples,
        )
        conn.commit()
        logging.info(
            "Successfully inserted/updated exposed credentials into PE database."
        )
    except (Exception, psycopg2.DatabaseError) as error:
        logging.info(error)
        conn.rollback()
    cursor.close()


# --- 657 OLD TSQL ---
def insert_sixgill_topCVEs_tsql(df):
    """Insert sixgill top CVEs."""
    conn = connect()
    table = "top_cves"
    # Create a list of tuples from the dataframe values
    tuples = [tuple(x) for x in df.to_numpy()]
    # Comma-separated dataframe columns
    cols = ",".join(list(df.columns))
    # SQL query to execute
    query = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (cve_id, date) DO NOTHING;"""
    cursor = conn.cursor()
    try:
        extras.execute_values(
            cursor,
            query.format(
                table,
                cols,
            ),
            tuples,
        )
        conn.commit()
        logging.info("Successfully inserted/updated top cve data into PE database.")
    except (Exception, psycopg2.DatabaseError) as error:
        logging.info(error)
        conn.rollback()
    cursor.close()


# --- 659 OLD TSQL ---
def execute_dnsmonitor_data_tsql(dataframe, table):
    """Insert DNSMonitor data."""
    conn = connect()
    tpls = [tuple(x) for x in dataframe.to_numpy()]
    cols = ",".join(list(dataframe.columns))
    sql = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (domain_permutation, organizations_uid)
    DO UPDATE SET ipv4 = EXCLUDED.ipv4,
        ipv6 = EXCLUDED.ipv6,
        date_observed = EXCLUDED.date_observed,
        mail_server = EXCLUDED.mail_server,
        name_server = EXCLUDED.name_server,
        sub_domain_uid = EXCLUDED.sub_domain_uid,
        data_source_uid = EXCLUDED.data_source_uid;"""
    cursor = conn.cursor()
    extras.execute_values(
        cursor,
        sql.format(table, cols),
        tpls,
    )
    conn.commit()


# --- 660 OLD TSQL ---
def execute_dnsmonitor_alert_data_tsql(dataframe, table):
    """Insert DNSMonitor alerts."""
    conn = connect()
    tpls = [tuple(x) for x in dataframe.to_numpy()]
    cols = ",".join(list(dataframe.columns))
    sql = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (alert_type, sub_domain_uid, date, new_value)
    DO NOTHING;"""
    cursor = conn.cursor()
    extras.execute_values(
        cursor,
        sql.format(table, cols),
        tpls,
    )
    conn.commit()


# --- 661 OLD TSQL ---
def addRootdomain_tsql(root_domain, pe_org_uid, source_uid, org_name):
    """Add root domain."""
    conn = connect()
    ip_address = str(socket.gethostbyname(root_domain))
    sql = """insert into root_domains(root_domain, organizations_uid, organization_name, data_source_uid, ip_address)
            values ('{}', '{}', '{}', '{}', '{}');"""
    cur = conn.cursor()
    cur.execute(sql.format(root_domain, pe_org_uid, org_name, source_uid, ip_address))
    conn.commit()
    cur.close()


# --- 662 OLD TSQL ---
def addSubdomain_tsql(conn, domain, pe_org_uid, root):
    """Add a subdomain into the database."""
    conn = connect()
    if root:
        root_domain = domain
    else:
        root_domain = domain.split(".")[-2:]
        root_domain = ".".join(root_domain)
    cur = conn.cursor()
    date = datetime.today().strftime("%Y-%m-%d")
    cur.callproc(
        "insert_sub_domain",
        (False, date, domain, pe_org_uid, "findomain", root_domain, None),
    )
    LOGGER.info("Success adding domain %s to subdomains table.", domain)
    conn.commit()
    close(conn)


# --- 663 OLD TSQL ---
def insert_intelx_breaches_tsql(df):
    """Insert intelx breach data."""
    df = df.drop_duplicates(subset=["breach_name"])
    conn = connect()
    table = "credential_breaches"
    # Create a list of tuples from the dataframe values
    tuples = [tuple(x) for x in df.to_numpy()]
    # Comma-separated dataframe columns
    cols = ",".join(list(df.columns))
    # SQL query to execute
    query = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (breach_name) DO UPDATE SET
    password_included = EXCLUDED.password_included;"""
    cursor = conn.cursor()
    try:
        extras.execute_values(
            cursor,
            query.format(
                table,
                cols,
            ),
            tuples,
        )
        conn.commit()
        logging.info("Successfully inserted/updated breaches into PE database.")
    except (Exception, psycopg2.DatabaseError) as error:
        logging.info(error)
        conn.rollback()
    cursor.close()


# --- 664 OLD TSQL ---
def insert_intelx_credentials_tsql(df):
    """Insert sixgill credential data."""
    df = df.drop_duplicates(subset=["breach_name", "email"])
    conn = connect()
    table = "credential_exposures"
    # Create a list of tuples from the dataframe values
    tuples = [tuple(x) for x in df.to_numpy()]
    # Comma-separated dataframe columns
    cols = ",".join(list(df.columns))
    # SQL query to execute
    query = """INSERT INTO {}({}) VALUES %s
    ON CONFLICT (breach_name, email) DO UPDATE SET
    modified_date = EXCLUDED.modified_date;"""
    cursor = conn.cursor()
    try:
        extras.execute_values(
            cursor,
            query.format(
                table,
                cols,
            ),
            tuples,
        )
        conn.commit()
        logging.info(
            "Successfully inserted/updated exposed credentials into PE database."
        )
    except (Exception, psycopg2.DatabaseError) as error:
        logging.info(error)
        conn.rollback()
    cursor.close()
