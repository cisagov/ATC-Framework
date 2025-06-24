"""Collect Intelx credential leak data."""
# Standard Python Libraries
import datetime
import logging
import sys
import time

# Third-Party Libraries
import numpy as np
import pandas as pd
import requests

from .data.pe_db.config import get_params
from .data.pe_db.db_query_source import (
    get_data_source_uid,
    get_orgs,
    get_root_domains,
    insert_intelx_breaches,
    insert_intelx_credentials,
)

# Calculate Datetimes for collection period
TODAY = datetime.date.today()
DAYS_BACK = datetime.timedelta(days=16)
START_DATE = (TODAY - DAYS_BACK).strftime("%Y-%m-%d %H:%M:%S")
END_DATE = TODAY.strftime("%Y-%m-%d %H:%M:%S")
# Get data source uid
SOURCE_UID = get_data_source_uid("IntelX")

section = "intelx"
params = get_params(section)
api_key = params[0][1]

LOGGER = logging.getLogger(__name__)


class IntelX:
    """Fetch IntelX data."""

    def __init__(self, orgs_list):
        """Initialize IntelX class."""
        self.orgs_list = orgs_list

    def run_intelx(self):
        """Run IntelX api calls."""
        orgs_list = self.orgs_list

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
        # alphabetize org list for consistent order
        pe_orgs_final = sorted(pe_orgs_final, key=lambda d: d["cyhy_db_name"])

        # Run IntelX on each org
        success = 0
        failed = 0
        for org_idx, pe_org in enumerate(pe_orgs_final):
            cyhy_org_id = pe_org["cyhy_db_name"]
            pe_org_uid = pe_org["organizations_uid"]
            LOGGER.info(
                f"Running IntelX on {cyhy_org_id} ({org_idx + 1} of {len(pe_orgs_final)})"
            )
            print(
                f"Running IntelX on {cyhy_org_id} ({org_idx + 1} of {len(pe_orgs_final)})"
            )
            if self.get_credentials(cyhy_org_id, pe_org_uid) == 1:
                LOGGER.error("Failed to retrieve IntelX credentials for %s", cyhy_org_id)
                failed += 1
            else:
                success += 1

        # Log summary statistics
        LOGGER.info(
            f"IntelX scan ran successfully for {success}/{len(pe_orgs_final)} organizations"
        )

    def get_credentials(self, cyhy_org_id, pe_org_uid):
        """Get credentials for a provided org."""
        # Get the org root domains
        LOGGER.info(f"Retrieving root domains for {cyhy_org_id}")
        try:
            # conn = connect()
            roots_df = get_root_domains(pe_org_uid)
        except Exception as e:
            LOGGER.error("Failed fetching root domains for %s", cyhy_org_id)
            LOGGER.error(e)
            return 1

        # Catch situation where org has no eligble root domains
        if roots_df.empty:
            LOGGER.warning(f"{cyhy_org_id} does not have any eligible root domains for IntelX")
            return 1

        # Retrieve credential leaks from IntelX
        LOGGER.info(f"Retrieving IntelX findings for {cyhy_org_id}")
        leaks_json = self.find_credential_leaks(
            roots_df["root_domain"].values.tolist(), START_DATE, END_DATE
        )
        # Process and format results
        if len(leaks_json) < 1:
            LOGGER.info(f"No IntelX credentials found for {cyhy_org_id}")
            return 0
        creds_df, breaches_df = self.process_leaks_results(leaks_json, pe_org_uid, cyhy_org_id)
        # Insert breach data into the PE database
        LOGGER.info(f"Inserting IntelX breach data for {cyhy_org_id}")
        try:
            insert_intelx_breaches(breaches_df)
        except Exception as e:
            LOGGER.error("Failed inserting IntelX breach data for %s", cyhy_org_id)
            LOGGER.error(e)
            return 1
        # breach_dict = get_intelx_breaches(SOURCE_UID)
        # breach_dict = dict(breach_dict)
        # for cred_index, cred_row in creds_df.iterrows():
        #     breach_uid = breach_dict[cred_row["breach_name"]]
        #     creds_df.at[cred_index, "credential_breaches_uid"] = breach_uid
        # Insert credential data into the PE database
        LOGGER.info(f"Inserting IntelX credential data for {cyhy_org_id}")
        try:
            insert_intelx_credentials(creds_df)
        except Exception as e:
            LOGGER.error("Failed inserting IntelX credential data for %s", cyhy_org_id)
            LOGGER.error(e)
            return 1
        return 0

    def query_identity_api(self, domain, start_date, end_date):
        """Create an initial search and return the search id."""
        url = f"https://3.intelx.io/accounts/csv?selector={domain}&k={api_key}&datefrom={start_date}&dateto={end_date}"
        payload = {}
        headers = {}
        attempts = 0
        # Call IntelX endpoint to submit initial search query
        while attempts < 5:
            try:
                response = requests.request("GET", url, headers=headers, data=payload)
                response.raise_for_status()
                break
            except requests.exceptions.Timeout:
                time.sleep(5)
                attempts += 1
                if attempts == 5:
                    LOGGER.error("IntelX identity is not responding. Exiting program.")
                    sys.exit()
                LOGGER.info("IntelX Identity API response timed out. Trying again.")
            except Exception as e:
                LOGGER.error(f"Error occured geting search id: {e}")
                return 0
        time.sleep(5)
        return response.json()

    def get_search_results(self, id):
        """Search IntelX for email leaks."""
        # Call API
        url = f"https://3.intelx.io/live/search/result?id={id}&format=1&k={api_key}"
        payload = {}
        headers = {}
        resp = requests.request("GET", url, headers=headers, data=payload)
        # Retry clause in case API falters
        retry_count, max_retries, time_delay = 1, 10, 5
        while resp.status_code != 200 and retry_count <= max_retries:
            print(f"\tRetrying IntelX email leak API endpoint (code {resp.status_code}), attempt {retry_count} of {max_retries}")
            time.sleep(time_delay)
            resp = requests.request("GET", url, headers=headers, data=payload)
            retry_count += 1
        # Return results
        if retry_count == max_retries:
            LOGGER.error(f"Error: Failed to retrieve IntelX email leaks for {id}")
            return None
        else:
            return resp.json()

    def find_credential_leaks(self, domain_list, start_date, end_date):
        """Find leaks for a domain between two dates."""
        # Retrieve results for each domain
        all_results_list = []
        for dom_idx, domain in enumerate(domain_list):
            LOGGER.info(f"IntelX working on domain: {domain} {dom_idx+1}/{len(domain_list)}")
            print(f"IntelX working on domain: {domain} {dom_idx+1}/{len(domain_list)}")
            if not domain:
                continue
            response = self.query_identity_api(domain, start_date, end_date)
            if not response:
                continue
            search_id = response["id"]
            while True:
                # Retrieve full results for the search id
                results = self.get_search_results(search_id)
                if not results:
                    break
                # If status is 0, there are still more results to retrieve
                if results["status"] == 0:
                    current_results = results["records"]
                    if current_results:
                        # Add the root_domain to each result object
                        LOGGER.info(
                            f"Intelx returned {len(current_results)} more credentials for {domain}"
                        )
                        result = [
                            dict(item, **{"root_domain": domain})
                            for item in current_results
                        ]
                        all_results_list = all_results_list + result
                    time.sleep(3)
                # If status is 1, IntelX is still working on it (wait)
                elif results["status"] == 1:
                    # LOGGER.info("Intelx still searching for more credentials")
                    time.sleep(7)
                # if status is 2, collect the final remaining results and exit loop
                elif results["status"] == 2:
                    current_results = results["records"]
                    if current_results:
                        # Add the root_domain to each result object
                        LOGGER.info(
                            f"Intelx returned {len(current_results)} more credentials for {domain}"
                        )
                        result = [
                            dict(item, **{"root_domain": domain})
                            for item in current_results
                        ]
                        all_results_list = all_results_list + result
                    break
                # If status is 3, invalid search id error
                elif results["status"] == 3:
                    LOGGER.error("Search id not found")
                    break
        # Return all results
        return all_results_list

    def process_leaks_results(self, leaks_json, org_uid, cyhy_org_id):
        """Prepare and format credentials and breach dataframes."""
        # Convert json into a dataframe
        all_df = pd.DataFrame.from_dict(leaks_json)
        # format email to all lowercase and remove duplicates
        all_df["user"] = all_df["user"].str.lower()
        # Log stats
        num_email = all_df['user'].nunique()
        num_post = all_df['sourceshort'].nunique()
        all_df = all_df.drop_duplicates(subset=["user", "sourceshort"], keep="first")
        # num emails after removing duplicates in the same post
        num_email_dedupe = len(leaks_json)
        LOGGER.info(f"IntelX results {cyhy_org_id}: {num_email} unique emails, {num_post} unique posts, {num_email_dedupe} emails after dedupe")
        # Format date
        all_df["datetime"] = pd.to_datetime(all_df["date"])
        all_df["date"] = all_df["datetime"].dt.strftime("%Y-%m-%d")
        # Create boolean column for if password is included
        all_df["password_included"] = np.where(
            (pd.isna(all_df["password"])) | (all_df["password"] == ""), 0, 1
        )
        # Create new column for subdomain, organization uid, and data source uid
        all_df["sub_domain"] = all_df["user"].str.split("@").str[1]
        all_df["organizations_uid"] = org_uid
        all_df["data_source_uid"] = SOURCE_UID
        # rename fields to match database
        all_df.rename(
            columns={
                "user": "email",
                "sourceshort": "breach_name",
                "date": "modified_date",
                "systemid": "intelx_system_id",
                "passwordtype": "hash_type",
            },
            inplace=True,
        )
        # Select specific columns
        creds_df = all_df[
            [
                "email",
                "organizations_uid",
                "root_domain",
                "sub_domain",
                "breach_name",
                "modified_date",
                "data_source_uid",
                "password",
                "hash_type",
                "intelx_system_id",
            ]
        ].reset_index(drop=True)
        # group results by breaches
        breaches_df = all_df.groupby(
            ["breach_name", "modified_date", "bucket", "data_source_uid"]
        ).aggregate({"email": "count", "password_included": "sum"})
        breaches_df = breaches_df.reset_index()
        breaches_df["password_included"] = breaches_df["password_included"] > 0
        # Build breach description
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
            + " passwords. It falls in the following category: "
            + breaches_df["bucket"]
        )
        breaches_df["breach_date"] = breaches_df["modified_date"]
        breaches_df["added_date"] = breaches_df["modified_date"]
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
        # Return processed data
        return creds_df, breaches_df
