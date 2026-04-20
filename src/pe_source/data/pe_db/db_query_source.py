"""Query the PE PostgreSQL database."""

# Standard Python Libraries
from datetime import datetime
from decimal import Decimal
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
# from pe_reports import app
from pe_reports.data.config import config, staging_config
from pe_reports.data.db_query import task_api_call

# Setup logging to central file
LOGGER = logging.getLogger(__name__)

CONN_PARAMS_DIC = config()
CONN_PARAMS_DIC_STAGING = staging_config()

# These need to filled with API key/url path in database.ini
API_DIC = staging_config(section="pe_api")
pe_api_key = API_DIC.get("pe_api_key")
pe_api_url = API_DIC.get("pe_api_url")


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
        # Check total content field data size for this chunk
        total_content_size = sum([len(entry["content"]) for entry in chunk])
        # If total content field size is too big, trim content field for this chunk
        if total_content_size > 400000:
            LOGGER.warning("Excessive alert content data for this chunk, trimming...")
            for entry in chunk:
                over_limit = len(entry["content"]) > 2000
                entry["content"] = entry["content"][:2000]
                if over_limit:
                    entry["content"] += "\n[content has been trimmed for space savings]"
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
    df = df.copy()
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
    try:
        # Call endpoint
        xpanse_business_unit_insert_result = requests.put(
            endpoint_url, headers=headers, data=data
        ).json()
        LOGGER.info("Successfully inserted new record in xpanse_business_units table.") # possible log cluttering
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


# --- Issue 699 pe-reports ---
def get_linked_xpanse_business_units():
    """
    Query API to retrieve data for all business units that link to an org.

    Return:
        All linked xpanse business units
    """
    # Endpoint info
    endpoint_url = pe_api_url + "linked_xpanse_business_units"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    try:
        result = requests.get(endpoint_url, headers=headers).json()
        # Process data and return
        return result
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
    try:
        # Call endpoint
        xpanse_alert_insert_result = requests.put(
            endpoint_url, headers=headers, data=data
        ).json()
        LOGGER.info(
            "Successfully inserted new record in xpanse_alerts table with associated assets and services"
        ) # possible log cluttering
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


# --- Issue 699 pe-reports ---
def get_orgs():
    """
    Query API to retrieve data for all demo or report_on orgs.

    Return:
        All demo or report_on org data as list of tuples
    """
    # Endpoint info
    endpoint_url = pe_api_url + "organizations_demo_or_report_on"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    try:
        result = requests.get(endpoint_url, headers=headers).json()
        # Process data and return
        for row in result:
            if row.get("date_first_reported") is not None:
                row["date_first_reported"] = datetime.strptime(
                    row.get("date_first_reported"), "%Y-%m-%d"
                )
            if row.get("cyhy_period_start") is not None:
                row["cyhy_period_start"] = datetime.strptime(
                    row.get("cyhy_period_start"), "%Y-%m-%d"
                )
            if row.get("county_fips") is not None:
                row["county_fips"] = Decimal(row.get("county_fips"))
            if row.get("state_fips") is not None:
                row["state_fips"] = Decimal(row.get("state_fips"))
        return result
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


# --- Issue 700 pe-reports ---
def get_data_source_uid(source):
    """
    Query API to get the uid for the specified data source.

    Args:
        source: The name of the specified data source

    Return:
        Data for the specified data source
    """
    # Endpoint info
    endpoint_url = pe_api_url + "data_source_by_name"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"name": source})
    try:
        result = requests.post(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        tup_result = [tuple(row.values()) for row in result]
        return tup_result[0][0]
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


# --- Issue 701 pe-reports ---
def get_breaches():
    """
    Query API to get all the breach_names and uids from credential_breaches table.

    Return:
        All breach_names and uids as a list of tuples
    """
    # Endpoint info
    endpoint_url = pe_api_url + "breach_names_and_uids"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    try:
        result = requests.get(endpoint_url, headers=headers).json()
        # Process data and return
        tup_result = [tuple(row.values()) for row in result]
        return tup_result
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


# --- Issue 702 pe-reports ---
def getSubdomain(domain):
    """
    Query API to get the uid for the specified subdomain.

    Args:
        domain: The name of the specified subdomain

    Return:
        uid for the specified subdomain
    """
    # Endpoint info
    endpoint_url = pe_api_url + "subdomain_uid_by_domain"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"domain": domain})
    try:
        result = requests.post(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        tup_result = [tuple(row.values()) for row in result]
        # Catch deleted subdomain error
        try:
            return tup_result[0][0]
        except Exception as e:
            return -1
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


# --- Issue 703 pe-reports ---
def org_root_domains(org_uid):
    """
    Query API to get the root domains for the specified org uid.

    Args:
        org_uid: The uid of the specified organization

    Return:
        root domains for the specified org uid
    """
    # Endpoint info
    endpoint_url = pe_api_url + "rootdomains_by_org_uid"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"org_uid": org_uid})
    try:
        result = requests.post(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        result_df = pd.DataFrame.from_dict(result)
        result_df.rename(
            columns={"root_domain_uid": "root_uid", "organizations_uid": "org_uid"},
            inplace=True,
        )
        result_dict_list = result_df.to_dict("records")
        return result_dict_list
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


# --- Issue 706 pe-reports/005 atc-framework ---
def insert_dnstwist_domain_permu(df):
    """
    Query API to insert multiple dnstwist records into the domain_permutations table.

    Args:
        df: Dataframe containing DNSTwist data to be inserted
    """
    # Endpoint info
    endpoint_url = pe_api_url + "domain_permu_insert_dnstwist"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    # Adjust data types and convert to list of dictionaries
    df["date_active"] = pd.to_datetime(df["date_active"])
    df["date_active"] = df["date_active"].dt.strftime("%Y-%m-%d")
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


# --- Issue 707 pe-reports/006 atc-framework ---
# Reuse the /rootdomains_by_org_uid endpoint, but return as dataframe
def get_root_domains(org_uid):
    """
    Query API to get the root domains for the specified org uid.

    Args:
        org_uid: The uid of the specified organization

    Return:
        root domains for the specified org uid as dataframe
    """
    # Endpoint info
    endpoint_url = pe_api_url + "rootdomains_by_org_uid"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"org_uid": org_uid})
    try:
        result = requests.post(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        result_df = pd.DataFrame.from_dict(result)
        return result_df
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


# --- Issue 708 pe-reports/007 atc-framework ---
# Reuse the /data_source_by_name endpoint, but return all fields
def getDataSource_api(source):
    """
    Query API to get all info for the specified data source.

    Args:
        source: The name of the specified data source

    Return:
        Data for the specified data source
    """
    # Endpoint info
    endpoint_url = pe_api_url + "data_source_by_name"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"name": source})
    try:
        result = requests.post(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        tup_result = [tuple(row.values()) for row in result]
        return tup_result[0]
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


# --- Issue 709 pe-reports/008 atc-framework ---
# Very similar to insert_intelx_breaches(), but for HIBP
def execute_hibp_breach_values(jsonList, thread):
    """
    Query API to insert multiple HIBP records into the credential_breaches table.

    Args:
        jsonList: List of dictionaries containing HIBP breach data to be inserted
    """
    # Endpoint info
    endpoint_url = pe_api_url + "cred_breaches_hibp_insert"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    # Remove duplicates and convert to list of dictionaries
    data = json.dumps({"breach_data": jsonList})
    try:
        # Call endpoint
        result = requests.put(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        LOGGER.info("Data inserted into credential_breaches successfully..")
        LOGGER.info("\t", result)
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


# --- Issue 710 pe-reports/009 atc-framework ---
# Very similar to insert_intelx_credentials(), but for HIBP
def execute_hibp_emails_values(jsonList, thread):
    """
    Query API to insert multiple HIBP records into the credential_exposures table.

    Args:
        jsonList: List of dictionaries containing HIBP credential exposure data to be inserted
    """
    # Endpoint info
    endpoint_url = pe_api_url + "cred_exp_hibp_insert"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    # Remove duplicates and convert to list of dictionaries
    data = json.dumps({"exp_data": jsonList})
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


# --- Issue 010 atc-framework ---
def get_breach_uids():
    """
    Query API to get all breach names and uids.

    Return:
        All breach names and uids.
    """
    # Endpoint info
    endpoint_url = pe_api_url + "breach_uids"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    try:
        # Call endpoint
        result = requests.get(endpoint_url, headers=headers).json()
        # Process data and return
        return result
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


# --- Issue 011 atc-framework ---
def query_orgs(thread):
    """
    Query API to get all orgs where report_on is true.

    Return:
        All orgs where report_on is true as a dataframe.
    """
    # Endpoint info
    endpoint_url = pe_api_url + "reported_orgs"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    try:
        # Call endpoint
        result = requests.get(endpoint_url, headers=headers).json()
        # Process data and return
        result_df = pd.DataFrame(result)
        return result_df
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


# --- Issue 012 atc-framework ---
def query_PE_subs(org_uid):
    """
    Query API to get all subdomains for the specified organization.

    Args:
        org_uid: The organizations_uid of the specified org.

    Return:
        All subdomains for the specified organization.
    """
    # Endpoint info
    endpoint_url = pe_api_url + "subdomains_by_org_uid"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"org_uid": org_uid})
    try:
        # Call endpoint
        result = requests.post(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        result_df = pd.DataFrame(result)
        return result_df
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


# --- Issue 016 atc-framework ---
def insert_shodan_assets(asset_data, failed):
    """
    Query API to insert Shodan data into the shodan_assets table.

    Args:
        data: Dataframe of the shodan data to be inserted into shodan_assets.
    """
    # Endpoint info
    endpoint_url = pe_api_url + "shodan_assets_insert"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"asset_data": asset_data})
    try:
        # Call endpoint
        result = requests.put(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        LOGGER.info(result.get("message"))
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
        failed.append("Failed inserting shodan assets: {}".format(errh))
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
        failed.append("Failed inserting shodan assets: {}".format(errc))
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
        failed.append("Failed inserting shodan assets: {}".format(errt))
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
        failed.append("Failed inserting shodan assets: {}".format(err))
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)
        failed.append("Failed inserting shodan assets: {}".format(err))
    return failed


# --- Issue 017 atc-framework ---
def insert_shodan_vulns(vuln_data, failed):
    """
    Query API to insert Shodan data into the shodan_vulns table.

    Args:
        data: Dataframe of the shodan data to be inserted into shodan_vulns.
    """
    # Endpoint info
    endpoint_url = pe_api_url + "shodan_vulns_insert"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps({"vuln_data": vuln_data})
    try:
        # Call endpoint
        result = requests.put(endpoint_url, headers=headers, data=data).json()
        # Process data and return
        LOGGER.info(result)
    except requests.exceptions.HTTPError as errh:
        LOGGER.error(errh)
        failed.append("Failed inserting shodan assets: {}".format(errh))
    except requests.exceptions.ConnectionError as errc:
        LOGGER.error(errc)
        failed.append("Failed inserting shodan assets: {}".format(errc))
    except requests.exceptions.Timeout as errt:
        LOGGER.error(errt)
        failed.append("Failed inserting shodan assets: {}".format(errt))
    except requests.exceptions.RequestException as err:
        LOGGER.error(err)
        failed.append("Failed inserting shodan assets: {}".format(err))
    except json.decoder.JSONDecodeError as err:
        LOGGER.error(err)
        failed.append("Failed inserting shodan assets: {}".format(err))
    return failed


# v ===== ACTIVE TSQL THAT STILL NEEDS CONVERSION ===== v


# Conversion in progress
def get_ips_tsql(org_uid):
    """Get IP data."""
    conn = connect()
    # CIDR IPs
    sql1 = """SELECT i.ip_hash, i.ip, ct.network FROM ips i
    JOIN cidrs ct on ct.cidr_uid = i.origin_cidr
    JOIN organizations o on o.organizations_uid = ct.organizations_uid
    where o.organizations_uid = %(org_uid)s
    and i.origin_cidr is not null
    and i.shodan_results is True
    and i.current;"""
    df1 = pd.read_sql(sql1, conn, params={"org_uid": org_uid})
    ips1 = list(df1["ip"].values)
    # Subdomain IPs
    sql2 = """select i.ip_hash, i.ip
    from ips i
    join ips_subs is2 ON i.ip_hash = is2.ip_hash
    join sub_domains sd on sd.sub_domain_uid = is2.sub_domain_uid
    join root_domains rd on rd.root_domain_uid = sd.root_domain_uid
    JOIN organizations o on o.organizations_uid = rd.organizations_uid
    where o.organizations_uid = %(org_uid)s
    and i.shodan_results is True
    and sd.current
    and i.current;"""
    df2 = pd.read_sql(sql2, conn, params={"org_uid": org_uid})
    ips2 = list(df2["ip"].values)
    # Get union of both CIDR/Subdomain IP sets
    in_first = set(ips1)
    in_second = set(ips2)
    in_second_but_not_in_first = in_second - in_first
    ips = ips1 + list(in_second_but_not_in_first)
    conn.close()
    return ips


def get_ips(org_uid):
    """
    Query API to get all ips for an org to run through Shodan.

    Return:
        All ips to run through Shodan
    """
    # Endpoint info
    endpoint_url = pe_api_url + "query_shodan_ips/" + org_uid
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    try:
        result = requests.get(endpoint_url, headers=headers).json()
        # Process data and return
        return result
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


# ???
def query_orgs_rev():
    """Query orgs in reverse."""
    conn = connect()
    sql = "SELECT * FROM organizations WHERE report_on is True ORDER BY organizations_uid DESC;"
    df = pd.read_sql_query(sql, conn)
    close(conn)
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
    df = df.replace("\x00","")

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

# --- WAS queries ---
def getPotential(org_id):
    """Get findings for specific time period in months."""
    conn = connect()
    cur = conn.cursor()
    sql = """   SELECT COUNT(*) FROM was_findings
                WHERE was_org_id = '{}' AND potential IS TRUE;
                """
    cur.execute(sql.format(org_id), conn)
    ret = cur.fetchall()
    cur.close()
    close(conn)
    return ret


def insertWASIds(listIds):
    """Insert WAS IDs into database."""
    conn = connect()
    sql = """INSERT INTO was_map (was_org_id,pe_org_id)
            VALUES ('{}','{}')
            ON CONFLICT (was_org_id) DO NOTHING;"""
    sqlNoUUID = """INSERT INTO was_map (was_org_id)
            VALUES ('{}')
            ON CONFLICT (was_org_id) DO NOTHING;"""
    cur = conn.cursor()
    for id in listIds:
        if id[1] == "":
            cur.execute(sqlNoUUID.format(id[0]))
        else:
            cur.execute(sql.format(id[0], id[1]))
    conn.commit()
    close(conn)
    print("Success adding WAS IDs to database.")


def getPreviousFindingsHistorical(org_id, monthsAgo):
    """Get findings for specific time period in months."""
    conn = connect()
    cur = conn.cursor()
    sql = """   SELECT * FROM was_findings
                WHERE was_org_id = '{}';
                """
    cur.execute(sql.format(org_id, monthsAgo - 1, monthsAgo), conn)
    ret = cur.fetchall()
    cur.close()
    close(conn)
    return ret


def insertFindingData(findingList):
    """Insert finding data into database."""
    # TODO: Dont use was_ord_id to reference orgs, use customer_id once was data become available
    conn = connect()
    sql = """INSERT INTO was_findings (finding_uid, finding_type, webapp_id, webapp_url, webapp_name, was_org_id, name, owasp_category, severity, times_detected, cvss_v3_attack_vector, base_score, temporal_score, fstatus, last_detected, first_detected, potential, cwe_list, wasc_list)
            VALUES ('{}','{}','{}','{}','{}','{}','{}','{}','{}','{}','{}','{}','{}','{}','{}','{}','{}','{}','{}')
            ON CONFLICT (finding_uid) DO UPDATE 
            SET is_remediated = CASE
                WHEN was_findings.fstatus != 'FIXED' AND excluded.fstatus = 'FIXED' THEN TRUE
                ELSE was_findings.is_remediated
            END,
            webapp_name = excluded.webapp_name,
            webapp_url = excluded.webapp_url,
            name = excluded.name,
            cvss_v3_attack_vector = excluded.cvss_v3_attack_vector,
            fstatus = excluded.fstatus,
            times_detected = excluded.times_detected,
            last_detected = excluded.last_detected,
            potential = excluded.potential,
            cwe_list = excluded.cwe_list,
            wasc_list = excluded.wasc_list
            ;"""
    cur = conn.cursor()
    for finding in findingList:
        finding["cwe_list"] = "{" + ",".join(map(str, finding["cwe_list"])) + "}"
        try:
            cur.execute(
                sql.format(
                    finding["finding_uid"],
                    finding["finding_type"],
                    finding["webapp_id"],
                    finding["webapp_url"],
                    finding["webapp_name"],
                    finding["was_org_id"],
                    finding["name"],
                    finding["owasp_category"],
                    finding["severity"],
                    finding["times_detected"],
                    finding["cvss_v3_attack_vector"],
                    finding["base_score"],
                    finding["temporal_score"],
                    finding["fstatus"],
                    finding["last_detected"],
                    finding["first_detected"],
                    finding["potential"],
                    finding["cwe_list"],
                    json.dumps(finding["wasc_list"]),
                )
            )
        except KeyError:
            print("KeyError")
            print(finding)
    conn.commit()
    close(conn)
    print("Success adding finding data to database.")


def queryVulnWebAppCount(org_id):
    """Query the amount of webapps with vulnerabilities."""
    # TODO: Dont use was_ord_id to reference orgs, use customer_id once was data become available
    conn = connect()
    sql = """   SELECT webapp_id FROM was_findings
                WHERE was_org_id = '{}'
                AND
                (
                    fstatus = 'ACTIVE'
                    OR fstatus = 'NEW'
                    OR fstatus = 'REOPENED'
                );
        """
    df = pd.read_sql_query(sql.format(org_id), conn)
    webIdsList = df["webapp_id"].values.tolist()
    close(conn)
    return len(set(webIdsList))


def queryWASOrgList():
    """Query the list of WAS orgs."""
    # TODO: Dont use was_ord_id to reference orgs, use customer_id once was data become available
    conn = connect()
    sql = """SELECT was_org_id FROM was_map"""
    df = pd.read_sql_query(sql, conn)
    orgList = df["was_org_id"].values.tolist()
    close(conn)
    return orgList


def getPEuuid(org_id):
    """Query the org uuid given a certain cyhy db name."""
    conn = connect()
    sql = """SELECT organizations_uid FROM organizations WHERE cyhy_db_name = '{}'"""
    cur = conn.cursor()
    cur.execute(sql.format(org_id))
    ret = cur.fetchone()[0]
    close(conn)
    return ret


def getPreviousFindings(org_id, monthsAgo):
    """Get findings for specific time period in months."""
    conn = connect()
    cur = conn.cursor()
    sql = """   SELECT * FROM was_findings
                WHERE was_org_id = '{}'
                AND last_detected >= date_trunc('month', now() - interval '{} month')
                AND last_detected < date_trunc('month', now() - interval '{} month');
                """
    cur.execute(sql.format(org_id, monthsAgo, monthsAgo - 1), conn)
    ret = cur.fetchall()
    cur.close()
    close(conn)
    return ret


def queryVulnCountAll(org_id):
    """Query the amount of webapps with vulnerabilities."""
    # TODO: Dont use was_ord_id to reference orgs, use customer_id once was data become available
    conn = connect()
    sql = """   SELECT webapp_id FROM was_findings
                WHERE was_org_id = '{}'
                AND
                (
                    fstatus = 'ACTIVE'
                    OR fstatus = 'NEW'
                    OR fstatus = 'REOPENED'
                );
        """
    df = pd.read_sql_query(sql.format(org_id), conn)
    webIdsList = df["webapp_id"].values.tolist()
    close(conn)
    return len(webIdsList)


def queryVulnCountSeverity(org_id, severity):
    """Query the amount of webapps with vulnerabilities."""
    # TODO: Dont use was_ord_id to reference orgs, use customer_id once was data become available
    conn = connect()
    sql = """   SELECT webapp_id FROM was_findings
                WHERE was_org_id = '{}'
                AND severity = '{}'
                AND
                (
                    fstatus = 'ACTIVE'
                    OR fstatus = 'NEW'
                    OR fstatus = 'REOPENED'
                );
        """
    df = pd.read_sql_query(sql.format(org_id, severity), conn)
    webIdsList = df["webapp_id"].values.tolist()
    close(conn)
    return len(webIdsList)


def insertWASVulnData(data):
    """Insert WAS vulnerability data into database."""
    conn = connect()
    cur = conn.cursor()
    sql = """   INSERT INTO was_history (was_org_ID,date_scanned,vuln_cnt,vuln_webapp_cnt,web_app_cnt,high_rem_time,crit_rem_time,report_period,high_vuln_cnt,crit_vuln_cnt,crit_rem_cnt,high_rem_cnt,total_potential)
                VALUES ('{}','{}',{},{},{}, (CASE WHEN {} = 0 THEN NULL ELSE {} END), (CASE WHEN {} = 0 THEN NULL ELSE {} END),'{}',{},{},{},{},{}) """
    cur.execute(
        sql.format(
            data["was_org_id"],
            data["date_scanned"],
            data["vuln_cnt"],
            data["vuln_webapp_cnt"],
            data["web_app_cnt"],
            data["high_rem_time"],
            data["high_rem_time"],
            data["crit_rem_time"],
            data["crit_rem_time"],
            data["report_period"],
            data["high_vuln_cnt"],
            data["crit_vuln_cnt"],
            data["high_rem_cnt"],
            data["crit_rem_cnt"],
            data["total_potential"],
        )
    )
    conn.commit()
    close(conn)
    print("Success adding finding data to database.")


# --- 699 pe-reports OLD TSQL ---
def get_orgs_tsql():
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


# --- 700 pe-reports OLD TSQL ---
def get_data_source_uid_tsql(source):
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


# --- 701 pe-reports OLD TSQL ---
def get_breaches_tsql():
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
        logging.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


# --- 702 pe-reports OLD TSQL ---
def getSubdomain_tsql(domain):
    """Get subdomain."""
    conn = connect()
    try:
        cur = conn.cursor()
        sql = """select * from sub_domains sd
                where sd.sub_domain = %s;"""
        cur.execute(sql, [domain])
        sub = cur.fetchall()
        cur.close()
        return sub[0][0]
    except (Exception, psycopg2.DatabaseError):
        print("Adding domain to the sub-domain table")
    finally:
        if conn is not None:
            close(conn)


# --- 703 pe-reports OLD TSQL ---
def org_root_domains_tsql(conn, org_uid):
    """Get root domains from database given the org_uid."""
    conn = connect()
    try:
        cur = conn.cursor()
        sql = """select * from root_domains rd
                where rd.organizations_uid = %s
                and enumerate_subs is True;"""
        cur.execute(sql, [org_uid])
        roots = cur.fetchall()
        keys = (
            "root_uid",
            "org_uid",
            "root_domain",
            "ip_address",
            "data_source_uid",
            "enumerate_subs",
        )
        roots = [dict(zip(keys, values)) for values in roots]
        cur.close()
        return roots
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error("There was a problem with your database query %s", error)
    finally:
        if conn is not None:
            close(conn)


# --- 706 pe-reports/005 atc-framework OLD TSQL ---
# The old TSQL did not come from a function, it was
# a loose query floating around in dnstwistscript.py


# --- 707 pe-reports/006 atc-framework OLD TSQL ---
def get_root_domains_tsql(conn, org_uid):
    """Get root domains from database given the org_uid."""
    sql = """
        select * from root_domains rd
        where rd.organizations_uid = %(org_id)s
        and enumerate_subs is True;
    """
    df = pd.read_sql_query(sql, conn, params={"org_id": org_uid})
    return df


# --- 708 pe-reports/007 atc-framework OLD TSQL ---
# This TSQL is from the getDataSource() function in
# hibp_latest.py and hibp_latest_rev.py
def getDataSource(conn, source):
    """Get datasource information from a database."""
    cur = conn.cursor()
    sql = """SELECT * FROM data_source WHERE name=%(s)s"""
    cur.execute(sql, {"s": source})
    source = cur.fetchone()
    cur.close()
    return source


# --- 709 pe-reports/008 atc-framework OLD TSQL ---
# This TSQL is from the execute_hibp_breach_values() function in
# hibp_latest.py and hibp_latest_rev.py


# --- 710 pe-reports/009 atc-framework OLD TSQL ---
# This TSQL is from the execute_hibp_emails_values() function in
# hibp_latest.py and hibp_latest_rev.py


# --- 010 atc-framework OLD TSQL ---
# The old TSQL did not come from a function, it was
# a loose query floating around in hibp_latest.py/hibp_latest_rev.py


# --- 011 atc-framework OLD TSQL ---
# This TSQL is from the query_orgs() function in
# adhoc/data/run.py


# --- 012 atc-framework OLD TSQL ---
# This TSQL is from the query_PE_subs() function in
# hibp_latest.py and hibp_latest_rev.py


# --- 016/017 atc-framework OLD TSQL ---
# This TSQL function is being broken up into two separate endpoints
def insert_shodan_data(dataframe, table, thread, org_name, failed):
    """Insert Shodan data into database."""
    # get rid of \x00 characters
    dataframe = dataframe.replace({"\x00": ""}, regex=True)
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
        logging.error("{} failed inserting into {}".format(org_name, table))
        logging.error("{} {} - {}".format(thread, e, org_name))
        failed.append("{} failed inserting into {}".format(org_name, table))
        conn.rollback()
    cursor.close()
    return failed


def get_linked_xpanse_business_units():
    """
    Query API to retrieve data for all business units that link to an org.

    Return:
        All linked xpanse business units
    """
    # Endpoint info
    endpoint_url = pe_api_url + "linked_xpanse_business_units"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    try:
        result = requests.get(endpoint_url, headers=headers).json()
        # Process data and return
        return result
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


def api_was_report_insert(was_report_dict):
    """
    Insert an was report record.

    On conflict on last_scan_date, update the old record with the new data

    Args:
        was_report_dict: Dictionary of column names and values to be inserted

    Return:
        Status on if the record was inserted successfully
    """
    # Endpoint info
    endpoint_url = pe_api_url + "was_report_insert_or_update"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    # print(was_report_dict)
    data = json.dumps(was_report_dict, default=str)
    print(len(data.encode('utf-8')))
    print("converted_Success")
    # print(data)

    # LOGGER.info(data)
    try:
        # Call endpoint
        print('1')
        task_url = "was_report_insert_or_update"
        status_url = "was_report_insert_or_update/task/"
        # Make API call
        was_report_insert_result = task_api_call(task_url, status_url, data, 3)

        # was_report_insert_result = requests.put(
        #     endpoint_url, headers=headers, data=data
        # )
        # print(was_report_insert_result)
        # was_report_insert_result = was_report_insert_result.json()
        print('2')
        LOGGER.info(was_report_insert_result)
        # LOGGER.info(
        #     "Successfully inserted new record in xpanse_alerts table with associated assets and services"
        # )
        return was_report_insert_result
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


def api_was_finding_insert(finding_dict):
    """
    Insert a was finding record into the was_finding table.

    On conflict, update the old record with the new data

    Args:
        finding_dict: Dictionary of column names and values to be inserted

    Return:
        Status on if the record was inserted successfully
    """
    # Endpoint info
    endpoint_url = pe_api_url + "was_finding_insert_or_update"
    headers = {
        "Content-Type": "application/json",
        "access_token": pe_api_key,
    }
    data = json.dumps(finding_dict, default=str)

    LOGGER.info(data)
    try:
        # Call endpoint
        was_finding_insert_result = requests.put(
            endpoint_url, headers=headers, data=data
        ).json()
        
        LOGGER.info(
            "Successfully inserted new record in was_findings table."
        )
        return was_finding_insert_result
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
    except Exception as errg:
        LOGGER.error(errg)


def getRootdomain(domain):
    """Get the record for the specified root domain."""
    conn = connect()
    cur = conn.cursor()
    sql = """SELECT * FROM root_domains rd
        WHERE rd.root_domain = '{}'"""
    cur.execute(sql.format(domain))
    root = cur.fetchone()
    cur.close()
    return root

def get_execs_by_org_uid(org_uid):
    """Get executives for the specified organization_uid."""
    # Build query
    conn = connect()
    sql = f"""
    SELECT *
    FROM executives
    WHERE organizations_uid = '{org_uid}'
    """
    # Execute query
    df = pd.read_sql(sql, conn)
    conn.close()
    # Return results
    return df

def insert_flare_events(event_list):
    """Insert list of flare event dictionaries into the PE DB."""
    # Build query
    insert_vals = ""
    for event in event_list:
        # Extra formatting for certain fields
        keys_to_format = [
            "flare_uid",
            "title",
            "content",
            "actor",
            "category",
            "source",
            "url",
            "risk_scores",
        ]
        for key in keys_to_format:
            val = event.get(key)
            if val is not None:
                # Handle characters that need to be escaped
                event.update({key: event.get(key).replace("'", "''")})
        org_uid = event.get("organizations_uid")
        flare_uid = event.get("flare_uid") # escaped '
        event_type = event.get("event_type")
        event_date = event.get("event_date")
        collect_date = event.get("collection_date")
        title = event.get("title") # escaped '
        content = event.get("content") # escaped '
        content_hash = event.get("content_hash")
        actor = event.get("actor") # escaped '
        category = event.get("category") # escaped '
        source = event.get("source") # escaped '
        url = event.get("url") # escaped '
        risk_scores = event.get("risk_scores")
        related_ident = event.get("related_identifiers")
        related_ident_txt = event.get("related_identifiers_txt")
        data_source_uid = event.get("data_source_uid")
        severity = event.get("severity")
        insert_vals += f"(\'{org_uid}\', \'{flare_uid}\', \'{event_type}\', \'{event_date}\', \'{collect_date}\', \'{title}\', \'{content}\', \'{content_hash}\', \'{actor}\', \'{category}\', \'{source}\', \'{url}\', \'{risk_scores}\', {related_ident}, \'{data_source_uid}\', \'{severity}\', {related_ident_txt}),\n"

    insert_vals = insert_vals[:-2]
    sql = f"""
    INSERT INTO flare_events(organizations_uid, flare_uid, event_type, event_date, collection_date, title, content, content_hash, actor, category, source, url, risk_scores, related_identifiers, data_source_uid, severity, related_identifiers_txt)
    VALUES
    {insert_vals}
    ON CONFLICT (organizations_uid, flare_uid)
    DO UPDATE SET
    event_date = EXCLUDED.event_date,
    collection_date = EXCLUDED.collection_date,
    title = EXCLUDED.title,
    content = EXCLUDED.content,
    related_identifiers = EXCLUDED.related_identifiers,
    related_identifiers_txt = EXCLUDED.related_identifiers_txt
    """
    # Execute query
    conn = connect()
    cursor = conn.cursor()
    cursor.execute(sql)
    conn.commit()
    cursor.close()
    conn.close()

def insert_flare_breaches(breach_df):
    """Insert Flare credential breach data into the PE DB."""
    breach_df = breach_df.drop_duplicates(subset=["breach_name"])
    # Build query
    insert_vals = ""
    for idx, row in breach_df.iterrows():
        breach_name = row.get("breach_name")
        desc = row.get("description")
        breach_date = row.get("breach_date")
        add_date = row.get("added_date")
        mod_date = row.get("modified_date")
        pass_incl = row.get("password_included")
        source_uid = row.get("data_source_uid")
        # Escape special characters
        breach_name = breach_name.replace("'", "''")
        desc = desc.replace("'", "''")
        insert_vals += f"('{breach_name}', '{desc}', '{breach_date}', '{add_date}', '{mod_date}', {pass_incl}, '{source_uid}'),\n"
    insert_vals = insert_vals[:-2]
    sql = f"""
    INSERT INTO credential_breaches(breach_name, description, breach_date, added_date, modified_date, password_included, data_source_uid) VALUES 
    {insert_vals}
    ON CONFLICT (breach_name) 
    DO UPDATE SET
    password_included = EXCLUDED.password_included;
    """
    # Execute query
    try:
        conn = connect()
        cursor = conn.cursor()
        cursor.execute(sql)
        conn.commit()
        cursor.close()
        conn.close()
        LOGGER.info("Successfully inserted/updated Flare breaches into PE database.")
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error(error)
        conn.rollback()
        conn.close()

def get_cred_breach_uids(breach_name_list):
    """Get the credential breach uids for the specified list of breach names."""
    conn = connect()
    # Build query
    breach_name_str = "("
    for name in breach_name_list:
        name = name.replace("'","''")
        breach_name_str += f"'{name}',"
    breach_name_str = breach_name_str[:-1] + ")"
    sql = f"""
    SELECT credential_breaches_uid, breach_name
    FROM credential_breaches
    WHERE breach_name IN {breach_name_str}
    """
    # Execute query
    df = pd.read_sql(sql, conn)
    conn.close()
    # Return results
    return df

def insert_flare_credentials(cred_df):
    """Insert Flare credential exposure data into the PE DB."""
    cred_df = cred_df.drop_duplicates(subset=["breach_name", "email"])
    # Build query
    insert_vals = ""
    for idx, row in cred_df.iterrows():
        email = row.get("email")
        org_uid = row.get("organizations_uid")
        root = row.get("root_domain")
        sub = row.get("sub_domain")
        breach_name = row.get("breach_name")
        mod_date = row.get("modified_date")
        breach_uid = row.get("credential_breaches_uid")
        source_uid = row.get("data_source_uid")
        password = row.get("password")
        hash_type = row.get("hash_type")
        intelx_id = row.get("intelx_system_id")
        login_url = row.get("url")
        # Escape special characters
        email = email.replace("'", "''")
        breach_name = breach_name.replace("'", "''")
        password = password.replace("'", "''")
        insert_vals += f"('{email}', '{org_uid}', '{root}', '{sub}', '{breach_name}', '{mod_date}', '{breach_uid}', '{source_uid}', '{password}', '{hash_type}', '{intelx_id}', '{login_url}'),\n"
    insert_vals = insert_vals[:-2]
    sql = f"""
    INSERT INTO credential_exposures(email, organizations_uid, root_domain, sub_domain, breach_name, modified_date, credential_breaches_uid, data_source_uid, password, hash_type, intelx_system_id, login_url) VALUES 
    {insert_vals}
    ON CONFLICT (breach_name, email) 
    DO UPDATE SET
    modified_date = EXCLUDED.modified_date;
    """
    # Execute query
    try:
        conn = connect()
        cursor = conn.cursor()
        cursor.execute(sql)
        conn.commit()
        cursor.close()
        conn.close()
        LOGGER.info("Successfully inserted/updated Flare credentials into PE database.")
    except (Exception, psycopg2.DatabaseError) as error:
        LOGGER.error(error)
        conn.rollback()
        conn.close()

def get_pe_aliases(org_uid):
    """Get full name and abbreviation in the PE DB for the specified organization."""
    # Build query
    sql = f"""
    SELECT name, cyhy_db_name
    FROM organizations
    WHERE organizations_uid = '{org_uid}'
    """
    # Execute query
    conn = connect()
    df = pd.read_sql(sql, conn)
    conn.close()
    # Return result
    return df

def get_pe_roots(org_uid):
    """Get the current root domains in the PE DBfor the specified organization."""
    # Build query
    sql = f"""
    SELECT root_domain
    FROM root_domains
    WHERE 
        organizations_uid = '{org_uid}' AND
        enumerate_subs = True
    """
    # Execute query
    conn = connect()
    df = pd.read_sql(sql, conn)
    conn.close()
    # Return result
    return df

def get_pe_cidrs(org_uid):
    """Get the current CIDRs in the PE DB for the specified organization."""
    # Build query
    sql = f"""
    SELECT network
    FROM cidrs
    WHERE
        organizations_uid = '{org_uid}' AND
        current = True
    """
    # Execute query
    conn = connect()
    df = pd.read_sql(sql, conn)
    conn.close()
    # Return result
    return df

def get_pe_execs(org_uid):
    """Get the current executive names in the PE DB for the specified organization."""
    # Build query
    sql = f"""
    SELECT executive
    FROM executives
    WHERE organizations_uid = '{org_uid}'
    """
    # Execute query
    conn = connect()
    df = pd.read_sql(sql, conn)
    conn.close()
    # Return result
    return df

def query_all_shodan_cves(start_date, end_date):
    """Retrieve a list of all distinct CVEs across all stakeholders for the specified report period."""
    # Build query
    sql = f"""
    SELECT DISTINCT cve
    FROM
        (
            SELECT
                o.organizations_uid,
                o.cyhy_db_name,
                sv.timestamp,
                sv.type,
                UNNEST(sv.potential_vulns) as cve
            FROM 
                shodan_vulns sv JOIN
                organizations o ON
                sv.organizations_uid = o.organizations_uid
            WHERE
                o.report_on = True AND
                sv.timestamp BETWEEN '{start_date}' AND '{end_date}' AND
                sv.type != 'Insecure Protocol'
        ) q1
    ORDER BY
        cve DESC
    """
    # Execute query
    conn = connect()
    df = pd.read_sql(sql, conn)
    conn.close()
    # Return result
    return df

def insert_shodan_top_cves(top_cves):
    """Take dataframe of top 10 Shodan CVEs and insert into the top_cves_shodan table."""
    # Build query
    cve_list = top_cves.to_dict(orient="records")
    insert_vals = ""
    for record in cve_list:
        cve_id = record.get("cve_id")
        epss = record.get("epss")
        nvd = record.get("nvd_base_score").replace("'", "''")
        date = record.get("date")
        summary = record.get("summary").replace("'", "''")
        data_source_uid = record.get("data_source_uid")
        insert_vals += f"(\'{cve_id}\', \'{epss}\', \'{nvd}\', \'{date}\', \'{summary}\', \'{data_source_uid}\'),\n"
    insert_vals = insert_vals[:-2]
    sql = f"""
    INSERT INTO top_cves_shodan(cve_id, epss_score, nvd_base_score, collection_date, summary, data_source_uid)
    VALUES
    {insert_vals}
    ON CONFLICT (cve_id, collection_date)
    DO UPDATE SET
    epss_score = EXCLUDED.epss_score,
    nvd_base_score = EXCLUDED.nvd_base_score,
    summary = EXCLUDED.summary,
    data_source_uid = EXCLUDED.data_source_uid
    """
    # Execute query
    conn = connect()
    cursor = conn.cursor()
    cursor.execute(sql)
    conn.commit()
    cursor.close()
    conn.close()