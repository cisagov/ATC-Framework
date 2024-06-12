"""Main file for running an adhoc organization investigation."""
# Standard Python Libraries
import datetime
from dateutil.relativedelta import relativedelta
import logging
import os
import textwrap
import time

# Third-Party Libraries
import pandas as pd

# Import Adhoc Data Source Scans
import adhoc_config
from adhoc_helpers import check_output_exists, convert_to_list_of_ips
import cybersixgill_adhoc_scan
import dnsmonitor_adhoc_scan
import dnstwist_adhoc_scan
import intelx_adhoc_scan
import shodan_adhoc_scan
import whoisxml_adhoc_scan

# Setup main logging file
logging.basicConfig(
    filename="./adhoc_logs/adhoc_main_logfile.log",
    filemode="a",
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%m/%d/%Y %I:%M:%S",
    level="INFO",
)
main_log = logging.getLogger(__name__)


# *** See the section at the bottom of this file for more info ***

def run_adhoc_investigation(scans_to_run, curr_date, num_prev_months, org_uid, org_name, org_abbrv, root_domains, ips, sixgill_query):
    """
    Main function to run adhoc investigation.
    
    Args:
        scans_to_run: Which scans should be run for this organization
        curr_date: The current date you're running the adhoc investigation on
        num_prev_months: How far back in time to get results (in months)
        org_uid: The organizations_uid for the organization
        org_name: The fully spelled out name of the organization
        org_abbrv: The abbreviation or acronym for the organization
        root_domains: A string list of all known root domains for the organization
        ips: A string list of all known ips for the organization

    Returns:
        All adhoc investigation results in a newly created results folder
    """
    main_log.info(f"=== *** {org_abbrv} Adhoc Investigation Starting *** ===")
    main_start_time = time.time()
    main_log.info(f"Running adhoc investigation on: {org_name}")
    main_log.info(f"Requested scans: {scans_to_run}")
    # Setup folder for results
    results_folder = f"./output_data/{org_abbrv}_adhoc_findings_{curr_date}"
    if not os.path.exists(results_folder):
        os.makedirs(results_folder)
    # Start/End date calculations
    end_date = curr_date
    end_date_obj = datetime.datetime.strptime(curr_date, "%Y-%m-%d").date()
    start_date_obj = end_date_obj+relativedelta(months=-num_prev_months)
    start_date = start_date_obj.strftime("%Y-%m-%d")
    main_log.info(f"Output folder created: {results_folder[2:]}")
    # Clean and dedupe root domain and ip lists
    root_domains = [x.strip() for x in root_domains]
    root_domains = list(dict.fromkeys(root_domains))
    ips = [x.strip() for x in ips]
    ips = list(dict.fromkeys(ips))

    # Gather Cybersixgill Data
    if "cybersixgill" in scans_to_run:
        main_log.info("Cybersixgill scan started...")
        cybersixgill_results = cybersixgill_adhoc_scan.get_cybersixgill_data(
            org_uid,
            org_abbrv,
            sixgill_query,
            start_date,
            end_date,
            200, # chunk size
            5, # time delay
            f"{results_folder}/{org_abbrv}_cybersixgill_data_{end_date}.csv"
        )
        main_log.info("Cybersixgill scan complete")

    # Gather DNSMonitor Data
    if "dnsmonitor" in scans_to_run:
        main_log.info("DNSMonitor scan started...")
        dnsmonitor_results = dnsmonitor_adhoc_scan.get_dnsmonitor_data(
            org_uid,
            org_abbrv,
            org_name,
            start_date,
            end_date,
            f"{results_folder}/{org_abbrv}_dnsmonitor_data_{end_date}.csv"
        )
        main_log.info("DNSMonitor scan complete")

    # Gather DNSTwist Data (this scan may take a LONG time)
    if "dnstwist" in scans_to_run:
        main_log.info("DNSTwist scan started...")
        dnstwist_results = dnstwist_adhoc_scan.get_dnstwist_data(
            org_uid,
            org_abbrv,
            root_domains,
            f"{results_folder}/{org_abbrv}_dnstwist_data_{end_date}.csv"
        )
        main_log.info("DNSTwist scan complete")

    # Gather HIBP Data
    # * unavailable

    # Gather IntelX Data (this scan may take a LONG time)
    if "intelx" in scans_to_run:
        main_log.info("IntelX scan started...")
        intelx_results = intelx_adhoc_scan.get_intelx_data(
            org_abbrv,
            start_date,
            end_date,
            root_domains,
            f"{results_folder}/{org_abbrv}_intelx_data_{end_date}.csv"
        )
        main_log.info("IntelX scan complete")

    # Gather Shodan Data
    if "shodan" in scans_to_run:
        main_log.info("Shodan scan started...")
        shodan_results = shodan_adhoc_scan.get_shodan_data(
            org_uid,
            org_abbrv,
            ips,
            f"{results_folder}/{org_abbrv}_shodan_data_{end_date}.csv"
        )
        main_log.info("Shodan scan complete")

    # Gather WhoisXML Data
    if "whoisxml" in scans_to_run:
        main_log.info("WhoisXML scan started...")
        whoisxml_results = whoisxml_adhoc_scan.get_whoisxml_data(
            org_uid,
            org_abbrv,
            root_domains,
            ips,
            f"{results_folder}/{org_abbrv}_whoisxml_data_{end_date}.csv"
        )
        main_log.info("WhoisXML scan complete")

    # Create written summary
    summary_string = f"""
    Adhoc investigation completed for:
        \"{org_name}\" ({org_abbrv})
    Includes data from:
        {start_date} to {end_date} (previous {num_prev_months} months)
    Scan results:
        Cybersixgill: {check_output_exists(org_abbrv, "cybersixgill", curr_date)}
        DNSMonitor: {check_output_exists(org_abbrv, "dnsmonitor", curr_date)}
        DNSTwist: {check_output_exists(org_abbrv, "dnstwist", curr_date)}
        IntelX: {check_output_exists(org_abbrv, "intelx", curr_date)}
        Shodan: {check_output_exists(org_abbrv, "shodan", curr_date)}
        WhoisXML: {check_output_exists(org_abbrv, "whoisxml", curr_date)}
    Results output to folder: 
        {results_folder[2:]}

        
    === Explanation of Results ===

    - Cybersixgill Data: The data in this CSV file is all of the 
    mentions Cybersixgill has found across the dark/clear web 
    for the specified time frame where this organization's 
    name/abbreviation was involved. A PDF overview of this data 
    is also included. 

    - DNSMonitor Data: The data in this CSV file is all of the domain 
    monitoring alerts found by DNSMonitor for this organization for 
    the specified time frame. If there are no results, it is most 
    likely due to the fact that this organization is not currently 
    registered with DNSMonitor, or that no domain monitoring alerts 
    were found for the specified time frame. 

    - DNSTwist Data: The data in this CSV file is a list of malicious 
    typo-squatting domains associated with this organization. 
    Essentially, these are domains that look very similar to the 
    legitimate domains that this organization actually owns that were 
    flagged as malicious by either DShield or Blocklist.de 

    - IntelX Data: The data in this CSV file is a list of all the 
    compromised credentials found by IntelX for the specified 
    time frame that were associated with this organization. 
    
    - Shodan Data: The data in this CSV file is a list of all the 
    asset information Shodan has on record for this organization 
    and its assets. 

    - WhoisXML Data: The data in this CSV file is a list of all 
    the assets WhoisXML has discovered that it believes are associated 
    with this organization. Initially, all of the assets that 
    have been confirmed to belong to this organization are fed 
    into WhoisXML. WhoisXML then goes out and searches for any 
    additional assets that may be connected to the list of assets
    that were input. 
    """
    # Save written summary to file
    summary_string = textwrap.dedent(summary_string)
    with open(f"{results_folder}/{org_abbrv}_adhoc_summary_{end_date}.txt", "w") as file:
        file.write(summary_string[1:])
    main_end_time = time.time()
    main_log.info(f"Execution time for adhoc investigation: {str(datetime.timedelta(seconds=(main_end_time - main_start_time)))} (H:M:S)")
    main_log.info(f"=== *** {org_abbrv} Adhoc Investigation Complete *** ===\n")
    # Print summary to terminal
    print(summary_string)
     

# --- Run Adhoc Investigation Script ---
# Fill in the following input parameters before running

# Choose which scans to run:
scans_to_run = [
    "cybersixgill",
    "dnsmonitor",
    "dnstwist",
    "intelx",
    "shodan",
    "whoisxml",
]

# Fill in organization and timeframe info:
test_date = "2024-06-10" # ex: "2024-05-23"
test_num_prev_months = 12 # ex: 12
test_org_uid = "" # ex: The organizations_uid column in the organizations table
test_org_name = "" # ex: "Acme Company"
test_org_abbrv = "" # ex: ACME
test_sixgill_query = "(\"\") AND ()" # ex: "(\"Acme Company\") AND (ACME)"

# Fill in root domain data manually or from csv file:
# test_root_domains = ["root_domain_1.com", "root_domain_2.com", ...]
test_root_domains = pd.read_csv("./input_data/...")["root_domain"].to_list()

# Fill in IP data manually or from csv file:
# test_ips = ["12.345.678.9", "10.111.213.1", ...]
test_ips = pd.read_csv("./input_data/...")["ip"].to_list()
# Use the code below if pulling IP data from cyhy_db_assets table since it may contain CIDR blocks
# test_ips = pd.read_csv("./input_data/....csv")["ip"].to_list()
# test_ips = convert_to_list_of_ips(test_ips)

# Runing the adhoc investigation...
run_adhoc_investigation(
    scans_to_run,
    test_date,
    test_num_prev_months,
    test_org_uid,
    test_org_name,
    test_org_abbrv,
    test_root_domains,
    test_ips,
    test_sixgill_query,
)

# The log file for the adhoc investigation procss can be found at:
# ./adhoc_logs/adhoc_main_logfile.log

# Adhoc investigation results will be written to an output folder with this naming scheme:
# ./output_data/<org_abbrv>_adhoc_findings_YYYY-MM-DD


# Additional Notes:
# - When adding an organization's root domain data from the PE database, download
#   it as a csv file and put it in the input_data folder.
# - When adding an organization's IP data from the PE database, download it as a
#   csv file and put it inthe input_data folder.
# - Once all input parameters are filled in above (either manually or via csv file), 
#   run the adhoc investigation using the command:
#   python3 adhoc_investigation.py
# - All of the adhoc scans will only create an output csv file if results are found.
#   If no results are found for that organization from that data source, no output
#   csv file will be created.
