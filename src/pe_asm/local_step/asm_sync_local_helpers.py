"""All helper functions needed for the ASM Sync local process."""

# Standard Python Libraries
import datetime
import os
import requests
import sys
import time

# Third-Party Libraries
from bs4 import BeautifulSoup
from configparser import ConfigParser
from io import StringIO
import logging
import pandas as pd
from pymongo import MongoClient
import psycopg2
from psycopg2 import OperationalError
from sshtunnel import SSHTunnelForwarder

# Import ASM Sync DB queries
from asm_sync_local_queries import (
    add_sector_hierachy,
    insert_assets,
    insert_contacts,
    insert_cyhy_agencies,
    insert_dotgov_domains,
    insert_sector_org_relationship,
    insert_sectors,
    query_pe_orgs,
    query_pe_sectors,
    update_child_parent_orgs,
    update_fceb_child_status,
    update_scan_status,
)

# Setup Logging
main_log = logging.getLogger(__name__)

# Specify .ini file location
ini_file = "./asm_sync_local.ini"


def parse_ini(ini, section):
    """Parse info from the specified section in the ini file."""
    parser = ConfigParser()
    parser.read(ini, encoding="utf-8")
    section_dict = dict()
    if parser.has_section(section):
        for key, value in parser.items(section):
            section_dict[key] = value
    else:
        main_log.error(f"Section '{section}' not found in {ini}")
    return section_dict


def check_accessor_running():
    """Check to make sure the Accessor is running."""
    try:
        # Kill all existing ssh connections
        os.popen("killall ssh")
        time.sleep(1)
        # Get current status of accessor
        vmID = os.getenv("INSTANCE_ID") # This needs to be setup in ~/.bashrc
        main_log.info(f"Checking if the Accessor is currently running (instance ID: {vmID})")
        checkAWS = os.popen(
            f"""
            export AWS_DEFAULT_PROFILE=cool-dns-sesmanagesuppressionlist-cyber.dhs.gov && 
            aws ec2 describe-instance-status --instance-ids {vmID}
            """
        )
        checkAWS = checkAWS.read().split("\n")
        checkAWS = checkAWS[3].split() # used to be 1
        checkAWS = checkAWS[2]
        if checkAWS == "running":
            # If Accessor is running, connect a screen
            os.popen("startEC2Connect") # This needs to be setup in ~/.bin
            main_log.info(
                "The Accessor is running and a screen has been connected"
            )
        else:
            # If Accessor isn't running, start it up
            os.popen(
                f"""export AWS_DEFAULT_PROFILE=cool-dns-sesmanagesuppressionlist-cyber.dhs.gov && 
                aws ec2 start-instances --instance-ids {vmID}"""
            )
            main_log.info("The Accessor was not running and needed to be started")
            main_log.info("Waiting 2 minutes before attempting to access Accessor...")
            time.sleep(120)
            # Recursive call until Accessor is running
            check_accessor_running()
    except (BrokenPipeError, IOError):
        sys.stderr.close()
        main_log.error(f"There was some abnormal operation related to stdout.{sys.stderr}")


def pe_db_connect():
    """Connect to PE database."""
    # Parse PE DB info from .ini
    conn_dict = parse_ini(ini_file, "pe_db")
    # Check that Accessor is running and connect a screen
    check_accessor_running()
    time.sleep(3)
    # Establish SSH tunnel to the staging environement
    main_log.info("Setting up SSH tunnel")
    server = SSHTunnelForwarder(
        ("localhost"),
        ssh_username="ubuntu",
        ssh_pkey=conn_dict["pkey_location"], 
        ssh_private_key_password=conn_dict["pkey_pass"],
        host_pkey_directories=[],
        remote_bind_address=(
            conn_dict["host"],
            int(conn_dict["port"]),
        ),
    )
    server.start()
    ssh_port = server.local_bind_port
    main_log.info("SSH tunnel has been setup")
    # Make connection to PE DB
    main_log.info("Attempting connection to PE DB")
    pe_db_conn = None
    try:
        # pe_db_conn = psycopg2.connect(**conn_dict)
        pe_db_conn = psycopg2.connect(
            host="localhost",
            user=conn_dict["user"],
            password=conn_dict["password"],
            dbname=conn_dict["database"],
            port=ssh_port,
        )
        main_log.info("PE DB connection successful")
    except OperationalError as err:
        err_type, err_obj, traceback = sys.exc_info()
        main_log.error(
            "Database connection error: %s on line number: %s", err, traceback.tb_lineno
        )
        pe_db_conn = None
    # Return PE DB connection
    return pe_db_conn


def cyhy_db_connect():
    """Connect to CyHy Mongo database."""
    # Parse CyHy DB info from .ini
    conn_dict = parse_ini(ini_file, "cyhy_db")
    try:
        # Create screen to make SSH connection to CyHy env
        main_log.info("Creating screen to connect to CyHy DB")
        os.popen("screenConnectCyHy") # nosec
        main_log.info("Screen to connect to CyHy DB has been created")
        time.sleep(3)

        # Make connection to CyHy DB
        main_log.info("Attempting connection to CyHy DB")
        host = conn_dict["host"]
        user = conn_dict["user"]
        password = conn_dict["password"]
        port = conn_dict["port"]
        dbname = conn_dict["database"]
        cyhy_conn_string = f"mongodb://{user}:{password}@{host}:{port}/{dbname}"
        mongo_client = MongoClient(cyhy_conn_string)
        main_log.info("CyHy DB connection successful")
        # Return cyhy database object
        return mongo_client["cyhy"]
    except Exception as e:
        main_log.error(e)
        main_log.error(
            "Failed connecting to the CyHy database. Make sure you have the ssh connection running"
        )

def local_db_connect():
    """Connect to local copy of PE database."""
    # Parse local DB info from .ini
    conn_dict = parse_ini(ini_file, "local_db")
    # Make connection to PE DB
    main_log.info("Attempting connection to local DB")
    local_db_conn = None
    try:
        # pe_db_conn = psycopg2.connect(**conn_dict)
        local_db_conn = psycopg2.connect(
            host=conn_dict["host"],
            user=conn_dict["user"],
            password=conn_dict["password"],
            dbname=conn_dict["database"],
            port=conn_dict["port"],
        )
        main_log.info("Local DB connection successful")
    except OperationalError as err:
        err_type, err_obj, traceback = sys.exc_info()
        main_log.error(
            "Database connection error: %s on line number: %s", err, traceback.tb_lineno
        )
        local_db_conn = None
    # Return local DB connection
    return local_db_conn

def dotgov_domains():
    """Get list of dotgov domains from the github repo."""
    # dotgov_url = "https://github.com/cisagov/dotgov-data/blob/main/current-federal.csv"
    dotgov_url = "https://raw.githubusercontent.com/cisagov/dotgov-data/main/current-federal.csv" # raw data url
    resp = requests.get(dotgov_url)
    soup_obj = BeautifulSoup(resp.content, features="lxml")
    # found_table = soup_obj.find_all("table")
    body_str = soup_obj.find("body").get_text()
    body_str = body_str.strip()
    # df = pd.read_html(str(found_table))[0]
    df = pd.read_csv(StringIO(body_str), sep=',')
    # df = df.drop(columns=["Unnamed: 0"])
    df = df.rename(
        columns={
            "Domain name": "domain_name",
            "Domain type": "domain_type",
            "Organization name": "agency",
            "Suborganization name": "organization",
            "City": "city",
            "State": "state",
            "Security contact email": "security_contact_email",
        }
    )
    return df

def retrieve_all_cyhy_data(cyhy_db):
    """Retrieve all data necessary for the ASM Sync from the CyHy database."""
    collection = cyhy_db["requests"]
    # Retrieve FCEB list CyHy DB
    fceb_query = {"_id": "EXECUTIVE"}
    fceb_doc = collection.find(fceb_query)
    for row in fceb_doc:
        fceb_list = row["children"]
    main_log.info("Retrieved FCEB list from CyHy DB")
    
    # Start retrieving organization data from CyHy DB
    cyhy_request_data = collection.find()
    # Create return variables
    assets = []
    child_parent_dict = {}
    contact_list = []
    cyhy_agencies = []
    sector_info_list = []
    sector_list = []
    # Loop through all CyHy agencies
    for cyhy_request in cyhy_request_data:
        # If the CyHy org has a type (and network?), proceed with data retrieval
        if cyhy_request["agency"].get("type"):
            curr_org = cyhy_request["agency"]["name"]
            print(f"Gathering CyHy DB data for organization: {curr_org}")
            # Get organization's general info
            agency = {
                "name": cyhy_request["agency"]["name"],
                "cyhy_db_name": cyhy_request["_id"],
                "password": cyhy_request["key"],
                "agency_type": cyhy_request["agency"].get("type"),
                "retired": cyhy_request.get("retired", False),
                "receives_cyhy_report": "CYHY" in cyhy_request["report_types"],
                "receives_bod_report": "BOD" in cyhy_request["report_types"],
                "receives_cybex_report": "CYBEX" in cyhy_request["report_types"],
                "is_parent": len(cyhy_request.get("children", [])) > 0,
                "fceb": cyhy_request["_id"] in fceb_list,
                "cyhy_period_start": cyhy_request.get("period_start"),
                # new fields
                "location_name": cyhy_request["agency"].get("location", {}).get("name", None),
                "county": cyhy_request["agency"].get("location", {}).get("county", None),
                "county_fips": cyhy_request["agency"].get("location", {}).get("county_fips", None),
                "state_abbreviation": cyhy_request["agency"].get("location", {}).get("state", None),
                "state_fips": cyhy_request["agency"].get("location", {}).get("state_fips", None),
                "state_name": cyhy_request["agency"].get("location", {}).get("state_name", None),
                "country": cyhy_request["agency"].get("location", {}).get("country", None),
                "country_name": cyhy_request["agency"].get("location", {}).get("country_name", None),
            }
            cyhy_agencies.append(agency)

            # Get organization's children/subsidiaries if it has any
            if cyhy_request.get("children"):
                for child in cyhy_request["children"]:
                    # Save child w/ the parent's cyhy_db_id
                    child_parent_dict[child] = cyhy_request["_id"]

            # Get organization's contact info
            for contact in cyhy_request["agency"]["contacts"]:
                if not contact.get("type"):
                    contact["type"] = "unspecified"
                contact_object = {
                    "org_id": cyhy_request["_id"],
                    "org_name": cyhy_request["agency"]["name"],
                    "phone": contact.get("phone"),
                    "contact_type": contact.get("type"),
                    "email": contact.get("email"),
                    "name": contact.get("name"),
                    "date_pulled": datetime.datetime.today().date(),
                }
                contact_list.append(contact_object)

            # Get organization's network/CIDR/IP info
            for network in cyhy_request["networks"]:
                cidr_dict = {
                    "org_id": cyhy_request["_id"],
                    "org_name": cyhy_request["agency"]["name"],
                    "contact": str(cyhy_request["agency"]["contacts"]),
                    "network": network,
                    "first_seen": datetime.datetime.today().date(),
                    "last_seen": datetime.datetime.today().date(),
                }
                if "/" in network:
                    cidr_dict["type"] = "cidr"
                else:
                    cidr_dict["type"] = "ip"
                assets.append(cidr_dict)

            # Unknown if this code is still needed:
            # Correct mismatching CyHy org ids. ex: "Treasury" should be "TREASURY"
            # if cyhy_request["_id"] in pe_org_map["cyhy_id"].values:
            #     new_org_id = pe_org_map.loc[
            #         pe_org_map["cyhy_id"] == cyhy_request["_id"], "pe_org_id"
            #     ].item()
            #     LOGGER.info("Replacing %s with %s", cyhy_request["_id"], new_org_id)
            #     cyhy_request["_id"] = new_org_id

        # If the CyHy org doesn't have a type (and network?), it's actually a sector/category and will be put in a separate table
        else:
            curr_sector = cyhy_request["_id"]
            print(f"Gathering CyHy DB data for sector: {curr_sector}")
            # Add sector id to sector_list
            sector_list.append(cyhy_request["_id"])

            # Create a dictionary of sector data
            sector_dict = {
                "id": cyhy_request["_id"],
                "acronym": cyhy_request["agency"].get("acronym", ""),
                "name": cyhy_request["agency"].get("name", "No Name"),
                "children": cyhy_request.get("children", []),
                "password": cyhy_request.get("key", ""),
                "retired": cyhy_request.get("retired", False),
            }

            # If no contact is found save "None"
            if len(cyhy_request["agency"]["contacts"]) == 0:
                print("\tNo contacts found")
                sector_dict["email"] = None
                sector_dict["contact_name"] = None
            # If only one contact is available save it to the dictionary
            elif len(cyhy_request["agency"]["contacts"]) == 1:
                print("\tOnly 1 contact found")
                sector_dict["email"] = cyhy_request["agency"]["contacts"][0]["email"]
                sector_dict["contact_name"] = cyhy_request["agency"]["contacts"][0][
                    "name"
                ]
            # If multiple contacts are identified save the DISTRO email to the dictionary
            elif len(cyhy_request["agency"]["contacts"]) > 1:
                print("\tMultiple contacts found")
                distro_email = None
                distro_name = None
                # Look for distro contact
                for i in range(len(cyhy_request["agency"]["contacts"])):
                    if cyhy_request["agency"]["contacts"][i]["type"] == "DISTRO":
                        distro_email = cyhy_request["agency"]["contacts"][i][
                            "email"
                        ]
                        distro_name = cyhy_request["agency"][
                            "contacts"
                        ][i]["name"]
                # If none of the contacts were marked as distros, just use the first contact
                if distro_email is None:
                    distro_email = cyhy_request["agency"]["contacts"][0][
                        "email"
                    ]
                    distro_name = cyhy_request["agency"][
                        "contacts"
                    ][0]["name"]
                # Add distro info to sector dict
                sector_dict["email"] = distro_email
                sector_dict["contact_name"] = distro_name

            # Since ROOT and DOD are not sectors ignore them
            if sector_dict["acronym"] in ["ROOT", "DOD"]:
                print("\tROOT/DOD detected, skipping...")
                continue
            else:
            # Otherwise, append dict for this sector to list
                sector_info_list.append(sector_dict)

    # Log stats
    main_log.info("Retrieved bulk data from CyHy DB")
    main_log.info(f"Total organizations retrieved from CyHyDB: {len(cyhy_agencies)}")
    main_log.info(f"Total organization assets retrieved from CyHy DB: {len(assets)}")
    main_log.info(f"Total sectors retrieved from CyHy DB: {len(sector_list)}")
    
    # Convert JSON lists to dataframes
    cyhy_agency_df = pd.DataFrame(cyhy_agencies)
    assets_df = pd.DataFrame(assets)
    contacts_df = pd.DataFrame(contact_list)

    # Return processed data
    return [
        assets_df,
        child_parent_dict,
        contacts_df, 
        cyhy_agency_df, 
        sector_info_list,
        sector_list,
    ]

def insert_all_cyhy_data(pe_db_conn, assets_df, child_parent_dict, contacts_df, cyhy_agency_df, sector_info_list, sector_list):
    """Take all the ASM Sync data retrieved from the CyHy database and insert/update it into the PE database."""
    # Get PE DB password key from .ini
    conn_dict = parse_ini(ini_file, "pe_db")
    db_pass = conn_dict.get("pe_db_password_key")
    
    # Insert all CyHy DB sector data into the PE DB
    insert_sectors(pe_db_conn, db_pass, sector_info_list)

    # Query all PE sectors
    pe_sectors = query_pe_sectors(pe_db_conn)
    # Create a list of sector ids where run_scorecards = True
    scorecard_sectors = pe_sectors[pe_sectors["run_scorecards"] == True][
        "id"
    ].values.tolist()
    # Create a list of all orgs belonging to sectors that are flagged to run_scorecards
    scorecard_orgs = []
    for sector in sector_info_list:
        if sector["id"] in scorecard_sectors:
            scorecard_orgs += sector["children"]
    # Add column marking scorecard orgs
    cyhy_agency_df["scorecard"] = cyhy_agency_df["cyhy_db_name"].isin(scorecard_orgs)

    # Insert CyHy DB asset data into the PE DB
    insert_assets(pe_db_conn, assets_df)
    
    # Deduplicate cyhy contact data
    contacts_df.drop_duplicates(
        subset=["org_id", "name", "contact_type", "email"],
        inplace=True,
        ignore_index=True,
    )
    # Insert CyHy DB contact data into PE DB
    insert_contacts(pe_db_conn, contacts_df)

    # Insert CyHy DB organziation data into the PE DB
    insert_cyhy_agencies(pe_db_conn, db_pass, cyhy_agency_df)

    # Query all PE organizations
    pe_orgs = query_pe_orgs(pe_db_conn)
    # Build sector child and sub-sector lists
    sector_child_list = []
    sub_sector_list = []
    for sec in sector_info_list:
        # save uid of the current sector
        sector_uid = pe_sectors.loc[
            pe_sectors["acronym"] == sec["acronym"], "sector_uid"
        ].item()
        # loop through this sector's children, they can be orgs or sectors
        for child_agency in sec["children"]:
            # If child is a sector
            if child_agency in sector_list:
                # ignore child if DOD
                if child_agency == "DOD":
                    continue
                # append sector-sector relationship
                sub_sector_list.append(
                    (
                        pe_sectors.loc[
                            pe_sectors["acronym"] == child_agency, "sector_uid"
                        ].item(),
                        sector_uid,
                    )
                )
            # if the child is an org
            else:
                # skip if no org_uid available ***
                if len(pe_orgs.loc[pe_orgs["cyhy_db_name"] == child_agency, "organizations_uid"].index) == 0:
                    continue
                # grab the org_uid
                child_uid = pe_orgs.loc[
                    pe_orgs["cyhy_db_name"] == child_agency, "organizations_uid"
                ].item()
                # append to child_sector relationship list
                if child_uid and sector_uid:
                    sector_child_list.append(
                        (
                            sector_uid,
                            child_uid,
                            datetime.datetime.today().date(),
                            datetime.datetime.today().date(),
                        )
                    )

    # Insert sector-org relationships into the PE DB
    insert_sector_org_relationship(pe_db_conn, sector_child_list)
    
    # Add relationship between sectors to the PE DB, not allowing duplicate parents
    child_list = []
    for relationship in sub_sector_list:
        if relationship[0] not in child_list:
            add_sector_hierachy(pe_db_conn, relationship[0], relationship[1])
            child_list.append(relationship[0])
        else:
            print(relationship[0] + " already has a sector parent")
            continue
    main_log.info("Parent_sector_uid fields updated successfully using add_sector_hierarchy()")

    # For each parent/child relationship,
    # add the parent's org_uid to the child org
    child_parent_ct = 0
    scan_status_ct = 0
    fceb_child_ct = 0
    for child_name, parent_name in child_parent_dict.items():
        # Get parent uid
        parent_uid = pe_orgs.loc[
            pe_orgs["cyhy_db_name"] == parent_name, "organizations_uid"
        ].item()
        # add parent uid to child org's record
        print(f"Updating {child_name}'s parent_org_uid field")
        update_child_parent_orgs(pe_db_conn, parent_uid, child_name)
        child_parent_ct += 1
        # Check if parent org is reported on
        parent_report_on = pe_orgs.loc[
            pe_orgs["cyhy_db_name"] == parent_name, "report_on"
        ].item()
        # Check if parent org is FCEB
        parent_fceb = pe_orgs.loc[pe_orgs["cyhy_db_name"] == parent_name, "fceb"].item()
        # Update child's run_scans field
        if parent_report_on:
            print(f"Updating {child_name}'s run_scans field")
            update_scan_status(pe_db_conn, child_name)
            scan_status_ct += 1
        # Update child's fceb_child field
        if parent_fceb:
            print(f"Updating {child_name}'s fceb_child field")            
            update_fceb_child_status(pe_db_conn, child_name)
            fceb_child_ct += 1
            
        # Unsure if this code is still needed:
        # # For orgs whose parent is a scorecard mark scorecard
        # parent_scorecard = pe_orgs.loc[pe_orgs["cyhy_db_name"] == parent_name, "scorecard"].item()
        # if parent_scorecard:
        #     updated_scorecard_child_status(pe_db_conn, child_name)

    main_log.info(f"{child_parent_ct} child-parent relationships updated successfully using update_child_parent_orgs()")
    main_log.info(f"{scan_status_ct} scan statuses updated successfully using update_scan_status()")
    main_log.info(f"{fceb_child_ct} FCEB child statuses updated successfully using update_fceb_child_status()")

    # Scrape dot gov domains and insert into P&E database
    dotgov_df = dotgov_domains()
    insert_dotgov_domains(pe_db_conn, dotgov_df)
