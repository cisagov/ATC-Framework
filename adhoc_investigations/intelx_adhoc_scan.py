"""Adhoc version of the IntelX scan."""
# Standard Python Libraries
import logging
import time

# Third-Party Libraries
from dateutil.parser import parse
import pandas as pd
import requests

# .ini Data
import adhoc_config

# Setup logging:
main_log = logging.getLogger(__name__)

# IntelX API Info
api_key = adhoc_config.get_ini_data().get("intelx")

def parse_datetime(date):
    """Parse datetime string for multiple formats."""
    return parse(date)

def query_identity_api(domain, start_date, end_date):
    """Create an initial search and return the search id."""
    url = f"https://3.intelx.io/accounts/csv?selector={domain}&k={api_key}&datefrom={start_date}&dateto={end_date}"
    payload={}
    headers = {}
    response = requests.request("GET", url, headers=headers, data=payload)
    # Retry if API fails
    retry_max = 10
    retry_count = 1
    while response.status_code != 200 and retry_count <= retry_max:
        main_log.error(f"IntelX API call failed, code: {response.status_code}")
        main_log.error(f"\tRetrying in 5 sec - retry {retry_count} of {retry_max}")
        time.sleep(5)
        response = requests.get(url, headers=headers, data=payload)
        retry_count += 1
    time.sleep(5)
    return response.json()


def get_search_results(id):
    """Search IntelX for email leaks."""
    url = f"https://3.intelx.io/live/search/result?id={id}&format=1&k={api_key}"
    payload={}
    headers = {}
    try:
        response = requests.request("GET", url, headers=headers, data=payload)
    except:
        print("Failed to get response")
        return 0
    response = response.json()
    return response


def get_intelx_data(org_abbrv, start_date, end_date, domains, save_file):
    """Retrieve IntelX data for the specified root domains."""
    main_log.info(f"=== {org_abbrv} IntelX Adhoc Scan Starting ===")
    # Overall result list
    overall_list = []
    # Retrieve intelx data for each domain
    for domain in domains:
        # Create initial search query and get search_id
        main_log.info(f"Running Intelx search on domain: {domain}")
        main_log.info("\tPinging Intelx API to create search id...")
        response = query_identity_api(domain, start_date, end_date)
        if response:
            # If good search response received, proceed
            main_log.info(f"\tSearch id successfully created for {domain}")
            search_id = response['id']
            # Repeatedly ping API until results are retrieved
            main_log.info("\tRetrieving results for search id...")
            curr_domain_list = []
            while True:
                # Retrieve actual results of search query
                results = get_search_results(search_id)
                if results['status'] == 0:
                    # Collect results then loop again
                    # main_log.info("\t\tStatus Code 0: Results partially retrieved")
                    current_results = results['records']
                    if current_results:
                        result = [dict(item, **{'root_domain':domain}) for item in current_results]
                        curr_domain_list = curr_domain_list + result
                    time.sleep(3)
                elif results['status'] == 1:
                    # Wait and loop again
                    # main_log.info("\t\tStatus Code 1: Waiting then retrying...")
                    time.sleep(5)
                elif results['status'] == 2:
                    # Collect results and exit
                    main_log.info("\t\tStatus Code 2: Results fully retrieved")
                    current_results = results['records']
                    if current_results:
                        result = [dict(item, **{'root_domain':domain}) for item in current_results]
                        curr_domain_list = curr_domain_list + result
                    break
                elif results['status'] == 3:
                    # If search id not found, exit
                    main_log.info("\t\tSearch id not found")
                    break
            # Add the results for this domain to the overall list
            main_log.info(f"\tIntelX search complete for {domain}")
            overall_list.extend(curr_domain_list)
        else:
            # If no search response received
            main_log.info(f"\tSearch id creation unsuccessful for {domain}")

    # Process data and save to file
    if len(overall_list) > 0:
        # Convert to dataframe and format data
        num_email = len(overall_list)
        all_df = pd.DataFrame.from_dict(overall_list)
        all_df['user'] = all_df['user'].str.lower()
        num_email_unique = all_df['user'].nunique()
        num_posts_unique = all_df['sourceshort'].nunique()
        # Drop duplicate data
        all_df = all_df.drop_duplicates(subset=['user', 'sourceshort'], keep='first')
        num_email_no_duplicates = len(overall_list)
        # Adjust datetime format
        all_df["date"] = all_df["date"].replace("z", "Z", regex=True) # fix varying z capitalization
        all_df["date"] = all_df["date"].str.strip() # remove leading/trailing spaces
        # all_df['datetime'] = pd.to_datetime(all_df['date'], format='mixed')
        # all_df['datetime'] = pd.to_datetime(all_df['date'])
        # all_df['datetime'] = pd.to_datetime(all_df['date'], format='ISO8601')
        all_df['datetime'] = all_df.date.apply(parse_datetime)
        all_df['date'] = all_df['datetime'].dt.strftime('%m/%d/%Y')
        all_df.reset_index(drop=True, inplace=True)

        # Print stats
        main_log.info(f"{num_email} emails found in breaches found")
        main_log.info(f"{num_email_unique} unique emails found")
        main_log.info(f"{num_posts_unique} unique posts")
        main_log.info(f"{num_email_no_duplicates} emails found after removing duplicates in the same post")

        # Save data to file
        main_log.info(f"Saving to file: {save_file}")
        all_df.to_csv(save_file)
        main_log.info(f"=== {org_abbrv} DNSTwist Adhoc Scan Complete ===")
        return 1
    else:
        main_log.info("No results found for any of the domains input")
        main_log.info(f"=== {org_abbrv} DNSTwist Adhoc Scan Complete ===")
        return 0