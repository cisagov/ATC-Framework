"""Scripts to calculate Tier 0 Score for organizations."""

# Third-Party Libraries
import pandas as pd


def get_org_asset_data(org_abbrv):
    """Retrieve Tier 0 asset data from the database for the specified org."""
    conn = None
    # Retrieve org root domains
    org_root_query = """
    SELECT *
    FROM
        tz_root_domains rd
        JOIN
        organizations o
        ON rd.organizations_uid = o.organizations_uid
    WHERE cyhy_db_name = '?'
    """
    root_df = pd.DataFrame()
    try:
        root_df = pd.read_sql(org_root_query, conn, params=(org_abbrv,))
        root_uids = root_df["tz_root_domains_uid"].unique()
    except Exception as e:
        print(f"Error: failed to retrieve root domains - {e}")
    # Retrieve org subdomains
    root_uids_str = ""
    for root_uid in root_uids:
        root_uids_str += f"'{root_uid}',"
    root_uids_str = root_uids_str[:-1]
    org_sub_query = """
    SELECT *
    FROM tz_root_domains
    WHERE tz_root_domains_uid in (?)
    """
    try:
        sub_df = pd.read_sql(org_sub_query, conn, params=(root_uids_str,))
    except Exception as e:
        print(f"Error: failed to retrieve subdomains - {e}")
        sub_df = pd.DataFrame()
    print(sub_df)


def calc_tier_zero_score(business_unit_name):
    """Calculate the tier 0 score for the specified organization."""
    # Retrieve current asset/vuln/service data for the org

    # Normalize metrics by converting to per-asset and percentages

    # Retrieve current stats for this org's CI sector

    # Use sector stats to re-scale values

    # Aggregate values

    # Return score
    return 0
