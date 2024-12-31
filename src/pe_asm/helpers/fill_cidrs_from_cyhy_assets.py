"""Fill CIDRs table from cyhy assets."""

# Standard Python Libraries
import datetime
import logging

# Third-Party Libraries
import pandas as pd

# cisagov Libraries
from pe_asm.data.cyhy_db_query import (
    pe_db_connect,
    pe_db_staging_connect,
    query_pe_report_on_orgs,
)
from pe_reports.data.db_query import query_cyhy_assets

LOGGER = logging.getLogger(__name__)


def fill_cidrs(staging, orgs):
    """Fill CIDRs."""
    # Connect to database
    if staging:
        conn = pe_db_staging_connect()
    else:
        conn = pe_db_connect()

    # Fetch all reported orgs if not specified
    if not isinstance(orgs, pd.DataFrame):
        orgs = query_pe_report_on_orgs(conn)
    network_count = 0
    first_seen = datetime.datetime.today().date()
    last_seen = datetime.datetime.today().date()

    # Loop through organizations and insert current CIDRs
    for org_index, org_row in orgs.iterrows():
        org_id = org_row["organizations_uid"]
        # Retrieve cyhy assets for this org
        networks = query_cyhy_assets(org_row["cyhy_db_name"])
        for network_index, network in networks.iterrows():
            # Insert each cidr into the cidrs table
            network_count += 1
            net = network["network"]
            cur = conn.cursor()
            try:
                cur.callproc(
                    "insert_cidr",
                    (network["network"], org_id, "cyhy_db", first_seen, last_seen),
                )
            except Exception as e:
                LOGGER.error(e)
                continue
            conn.commit()
            cur.close()

    # Close database connection
    conn.close()
