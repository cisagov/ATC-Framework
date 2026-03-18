#!/usr/bin/python3
"""Script for the part of the ASM sync process that needs to happen locally (not on the accessor)."""

# Standard Python Libraries
import datetime
import logging
import time

# Third-Party Libraries
import os

# Import ASM Sync helper functions
from asm_sync_local_helpers import (
    cyhy_db_connect,
    local_db_connect, # for testing
    pe_db_connect,
    retrieve_all_cyhy_data,
    insert_all_cyhy_data,
)

# Import ASM Sync DB queries
from asm_sync_local_queries import (
    identify_org_asset_changes,
)

# Setup Logging
os.makedirs("./asm_sync_local_logs", exist_ok=True)
logging.basicConfig(
    filename="./asm_sync_local_logs/asm_sync_logfile.log",
    filemode="a",
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%m/%d/%Y %I:%M:%S",
    level="INFO",
)
main_log = logging.getLogger(__name__)


def asm_sync_local_step(staging=False):
    """Run the ASM sync step that needs to occur locally."""
    main_log.info("")
    main_start_time = time.time()
    main_log.info(f"=== *** ASM Sync Local Process Starting *** ===")
    # Connect to the P&E database
    main_log.info(">>> Establishing connection to the PE database")
    # Connect to database
    if staging:
        print("*** Real PE DB connection requested ***")
        time.sleep(5) # time to cancel
        pe_db_conn = pe_db_connect() # PE DB connection
    else:
        print("*** Local DB connection requested ***")
        pe_db_conn = local_db_connect() # Local DB connection
    main_log.info(">>> PE database connection established")

    # Connect to the CyHy database
    main_log.info(">>> Establishing connection to CyHy Database")
    cyhy_db = cyhy_db_connect()
    main_log.info(">>> CyHy Database connection established")

    # Retrieve and process all neccessary data from the CyHy DB
    main_log.info(">>> CyHy DB Data Retrieval Starting")
    [
        assets_df,
        child_parent_dict,
        contacts_df,
        cyhy_agency_df,
        sector_info_list,
        sector_list,
    ] = retrieve_all_cyhy_data(cyhy_db)
    main_log.info(">>> CyHy DB Data Retrieval Complete")
    
    # Insert/Update all processed CyHy data into the PE DB
    main_log.info(">>> Insertion of CyHy Data into PE DB Starting")
    insert_all_cyhy_data(
        pe_db_conn,
        assets_df,
        child_parent_dict,
        contacts_df,
        cyhy_agency_df,
        sector_info_list,
        sector_list,
    )
    main_log.info(">>> Insertion of CyHy Data into PE DB Complete")
    
    # Identify which assets in cyhy_db_asset are/aren't current
    main_log.info(">>> Identification of cyhy_db_asset Changes Starting")
    identify_org_asset_changes(pe_db_conn)
    main_log.info(">>> Identification of cyhy_db_asset Changes Complete")

    # End ASM Sync and clean up
    pe_db_conn.close()
    os.popen("killall SCREEN")
    main_end_time = time.time()
    main_log.info(f"Execution time for ASM sync local process: {str(datetime.timedelta(seconds=(main_end_time - main_start_time)))} (H:M:S)")
    main_log.info(f"=== *** ASM Sync Local Process Complete *** ===")


def main():
    """Run local (macbook, not EC2) step of the ASM Sync process."""
    asm_sync_local_step(True)


if __name__ == "__main__":
    main()