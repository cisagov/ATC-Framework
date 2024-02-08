"""Fill CIDRs table from cyhy assets."""

# Standard Python Libraries
import datetime
import logging

# Third-Party Libraries
import pandas as pd

# cisagov Libraries
from pe_asm.data.cyhy_db_query import (
    identify_cidr_changes,
    pe_db_connect,
    pe_db_staging_connect,
    query_pe_report_on_orgs,
)
from pe_reports.data.db_query import query_cyhy_assets

LOGGER = logging.getLogger(__name__)


def fill_cidrs(orgs, staging):
    """Fill CIDRs."""
    # Connect to database
    if staging:
        conn = pe_db_staging_connect()
    else:
        conn = pe_db_connect()

    # Fetch all reporting on if not specified
    if not isinstance(orgs, pd.DataFrame):
        orgs = query_pe_report_on_orgs(conn)

    network_count = 0
    first_seen = datetime.datetime.today().date()
    last_seen = datetime.datetime.today().date()

    if staging:
        conn = pe_db_staging_connect()
    else:
        conn = pe_db_connect()

    # Loop through P&E organizations and insert current CIDRs
    for org_index, org_row in orgs.iterrows():
        org_id = org_row["organizations_uid"]
        networks = query_cyhy_assets(org_row["cyhy_db_name"])
        for network_index, network in networks.iterrows():
            network_count += 1
            net = network["network"]
            print(net)
            cur = conn.cursor()
            try:
                cur.callproc(
                    "insert_cidr",
                    (network["network"], org_id, "cyhy_db", first_seen, last_seen),
                )
            except Exception as e:
                print(e)
                continue

            row = cur.fetchone()
            print(row)
            conn.commit()
            cur.close()

    # Identify which CIDRs are current
    LOGGER.info("Identify CIDR changes")
    identify_cidr_changes(conn)
    conn.close()
