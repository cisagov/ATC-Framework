"""Collect Cybersixgill data."""

# Standard Python Libraries
from datetime import date, datetime, timedelta
import logging

# import sys
# import time
import traceback

# Third-Party Libraries
import pandas as pd

from .data.pe_db.db_query_source import (
    get_breaches,
    get_data_source_uid,
    get_orgs,
    insert_sixgill_alerts,
    insert_sixgill_breaches,
    insert_sixgill_credentials,
    insert_sixgill_mentions,
    insert_sixgill_topCVEs,
)
from .data.sixgill.api import get_sixgill_organizations
from .data.sixgill.source import (  # cve_summary,; get_alerts_content,
    alerts,
    alias_organization,
    all_assets_list,
    creds,
    mentions,
    root_domains,
    top_cves,
)

# Set todays date formatted YYYY-MM-DD and the start_date 30 days prior
TODAY = date.today()
DAYS_BACK = timedelta(days=30)
MENTIONS_DAYS_BACK = timedelta(days=20)
MENTIONS_START_DATE = str(TODAY - MENTIONS_DAYS_BACK)
END_DATE = str(TODAY)
DATE_SPAN = f"[{MENTIONS_START_DATE} TO {END_DATE}]"

# Set dates to YYYY-MM-DD H:M:S format
NOW = datetime.now()
START_DATE_TIME = (NOW - DAYS_BACK).strftime("%Y-%m-%d %H:%M:%S")
END_DATE_TIME = NOW.strftime("%Y-%m-%d %H:%M:%S")

# Set up logging
LOGGER = logging.getLogger(__name__)


class Cybersixgill:
    """Fetch Cybersixgill data."""

    def __init__(self, orgs_list, method_list, soc_med_included):
        """Initialize Cybersixgill class."""
        self.orgs_list = orgs_list
        self.method_list = method_list
        self.soc_med_included = soc_med_included

    def run_cybersixgill(self):
        """Run Cybersixgill api calls."""
        orgs_list = self.orgs_list
        method_list = self.method_list
        soc_med_included = self.soc_med_included

        # Retrieve full org info from PE database
        all_pe_orgs = get_orgs()
        pe_orgs_final = []
        if orgs_list == "all":
            for pe_org in all_pe_orgs:
                if pe_org["report_on"]:
                    pe_orgs_final.append(pe_org)
                else:
                    continue
        elif orgs_list == "DEMO":
            for pe_org in all_pe_orgs:
                if pe_org["demo"]:
                    pe_orgs_final.append(pe_org)
                else:
                    continue
        else:
            for pe_org in all_pe_orgs:
                if pe_org["cyhy_db_name"] in orgs_list:
                    pe_orgs_final.append(pe_org)
                else:
                    continue
        # alphabetize org list for consistent order
        pe_orgs_final = sorted(pe_orgs_final, key=lambda d: d["cyhy_db_name"])

        # Get Cybersixgill org info and data source uid
        sixgill_orgs = get_sixgill_organizations()
        source_uid = get_data_source_uid("Cybersixgill")
        # Keep track of any failed CSG scans
        failed = []

        # Run Top CVEs scan if requested
        if "topCVEs" in method_list:
            # Results are the same regardless of org list
            if self.get_topCVEs(source_uid) == 1:
                failed.append("Top CVEs")

        # Run any other requested Cybersixgill scans
        for org_idx, pe_org in enumerate(pe_orgs_final):
            org_id = pe_org["cyhy_db_name"]
            pe_org_uid = pe_org["organizations_uid"]
            # Get sixgill_org_id associated with this org
            try:
                sixgill_org_id = sixgill_orgs[org_id][0]
            except KeyError as err:
                LOGGER.warning(f"{org_id} is not registered in Cybersixgill, skipping")
                continue
        
            if "alerts" in method_list:
                # Run alerts scan
                LOGGER.info(f"Fetching alert data for {org_id} ({org_idx+1} of {len(pe_orgs_final)})")
                if (
                    self.get_alerts(
                        org_id,
                        sixgill_org_id,
                        pe_org_uid,
                        source_uid,
                        soc_med_included,
                    )
                    == 1
                ):
                    failed.append("%s alerts" % org_id)
            if "mentions" in method_list:
                # Run mentions scan
                LOGGER.info(f"Fetching mention data for {org_id} ({org_idx+1} of {len(pe_orgs_final)})")
                if (
                    self.get_mentions(
                        org_id,
                        sixgill_org_id,
                        pe_org_uid,
                        source_uid,
                        soc_med_included,
                    )
                    == 1
                ):
                    failed.append("%s mentions" % org_id)
            if "credentials" in method_list:
                # Run credentials scan
                LOGGER.info(f"Fetching credential data for {org_id} ({org_idx+1} of {len(pe_orgs_final)})")
                if (
                    self.get_credentials(
                        org_id, sixgill_org_id, pe_org_uid, source_uid
                    )
                    == 1
                ):
                    failed.append("%s credentials" % org_id)

        # Log any failures
        if len(failed) > 0:
            LOGGER.error("Failures: %s", failed)

    def get_alerts(
        self, org_id, sixgill_org_id, pe_org_uid, source_uid, soc_med_included
    ):
        """Get alerts."""
        soc_med_platforms = [
            "twitter",
            "Twitter",
            "reddit",
            "Reddit",
            "Parler",
            "parler",
            "linkedin",
            "Linkedin",
            "discord",
            "forum_discord",
            "raddle",
            "telegram",
            "jabber",
            "ICQ",
            "icq",
            "mastodon",
        ]
        # Fetch alerts using sixgill_org_id
        try:
            LOGGER.info("Fetching alerts for %s", org_id)
            alerts_df = alerts(org_id, sixgill_org_id)
            # exclude social media alerts if specified
            if not soc_med_included:
                alerts_df = alerts_df[~alerts_df["site"].isin(soc_med_platforms)]
            # Add additional columns and format
            alerts_df["organizations_uid"] = pe_org_uid
            alerts_df["data_source_uid"] = source_uid
            alerts_df = alerts_df.rename(columns={"id": "sixgill_id"})
        except Exception as e:
            LOGGER.error("Failed fetching alerts for %s", org_id)
            LOGGER.error(e)
            LOGGER.error(traceback.format_exc())
            return 1

        # Fetch additional data for the list of alerts
        try:
            LOGGER.info("Fetching additional alert data for %s", org_id)
            # Fetch organization assets
            org_assets_dict = all_assets_list(sixgill_org_id)
            for alert_index, alert_row in alerts_df.iterrows():
                try:
                    alert_id = alert_row["sixgill_id"]
                    # content_snip, asset_mentioned, asset_type = get_alerts_content(
                    #     sixgill_org_id, alert_id, org_assets_dict
                    # )
                    # alerts_df.at[alert_index, "content_snip"] = content_snip
                    # alerts_df.at[alert_index, "asset_mentioned"] = asset_mentioned
                    # alerts_df.at[alert_index, "asset_type"] = asset_type

                    alerts_df.at[alert_index, "content_snip"] = ""
                    alerts_df.at[alert_index, "asset_mentioned"] = ""
                    alerts_df.at[alert_index, "asset_type"] = ""
                except Exception as e:
                    # LOGGER.error(
                    #     "Failed fetching a specific alert content for %s", org_id
                    # )
                    # LOGGER.error(e)
                    # print(traceback.format_exc())
                    alerts_df.at[alert_index, "content_snip"] = ""
                    alerts_df.at[alert_index, "asset_mentioned"] = ""
                    alerts_df.at[alert_index, "asset_type"] = ""
        except Exception as e:
            LOGGER.error("Failed fetching additional alert data for %s", org_id)
            LOGGER.error(e)
            LOGGER.error(traceback.format_exc())
            return 1

        # Insert alert data into the PE database
        try:
            LOGGER.info("Inserting alert data for %s", org_id)
            insert_sixgill_alerts(alerts_df)
        except Exception as e:
            LOGGER.error("Failed inserting alert data for %s", org_id)
            LOGGER.error(e)
            return 1
        return 0

    def get_mentions(
        self, org_id, sixgill_org_id, pe_org_uid, source_uid, soc_med_included
    ):
        """Get mentions."""
        # Fetch aliases for this org from Cybersixgill
        try:
            LOGGER.info("Fetching aliases for %s", org_id)
            aliases = alias_organization(sixgill_org_id)
        except Exception as e:
            LOGGER.error("Failed fetching aliases for %s", org_id)
            LOGGER.error(e)
            LOGGER.error(traceback.format_exc())
            return 1

        # Fetch mention data
        mentions_df = None
        try:
            LOGGER.info("Fetching mentions for %s", org_id)
            # Make adjustments to aliases
            if org_id == "doi_os":
                aliases = [
                    "DOI Office of the Secretary",
                    "Department of the Interior Office of the Secretary",
                    "Department of Interior Office of the Secretary",
                    "Interior Office of the Secretary",
                ]
            if "dhs" in aliases:
                aliases.remove("dhs")
            # if "NRC" in aliases:
            #     aliases.remove("NRC")
            if "st" in aliases:
                aliases.remove("st")
            if "nih" in aliases:
                aliases.remove("nih")
            if "blm" in aliases:
                aliases.remove("blm")
            if "ed" in aliases:
                aliases.remove("ed")
            if "pt" in aliases:
                aliases.remove("pt")
            if "occ" in aliases:
                aliases.remove("occ")
            if "pc" in aliases:
                aliases.remove("pc")
            if "epa" in aliases:
                aliases = ["epa"]
            if "hhs" in aliases:
                aliases.remove("hhs")
            if "bls" in aliases:
                aliases.remove("bls")
            if "doi" in aliases:
                aliases.remove("doi")
            if "doe" in aliases:
                aliases.remove("doe")
            if "sss" in aliases:
                aliases.remove("sss")
            if "dot" in aliases:
                aliases.remove("dot")
            if "dos" in aliases:
                aliases.remove("dos")
            if "sba" in aliases:
                aliases.remove("sba")
            if "ssa" in aliases:
                aliases.remove("ssa")
            if "st" in aliases:
                aliases.remove("st")
            if "dol" in aliases:
                aliases.remove("dol")
            if "gsa" in aliases:
                aliases.remove("gsa")
            if "hud" in aliases:
                aliases.remove("hud")
            if "doc" in aliases:
                aliases.remove("doc")
            if "os" in aliases:
                aliases.remove("os")
            if "sec" in aliases:
                aliases.remove("sec")
            if "stb" in aliases:
                aliases.remove("stb")
                aliases.append("surface transportation")
            # Retrieve mention data
            mentions_df = mentions(org_id, DATE_SPAN, aliases, soc_med_included)
        except Exception as e:
            LOGGER.error("Failed fetching mentions for %s", org_id)
            LOGGER.error(e)
            LOGGER.error(traceback.format_exc())
            return 1

        # Catch no mentions found situation:
        if mentions_df.empty:
            LOGGER.info(f"No mention data found for {org_id}, moving on")
            return 0

        # Format data
        mentions_df = mentions_df.rename(columns={"id": "sixgill_mention_id"})
        mentions_df["organizations_uid"] = pe_org_uid
        mentions_df["data_source_uid"] = source_uid

        # Insert mention data into the PE database
        try:
            LOGGER.info("Inserting mention data for %s", org_id)
            insert_sixgill_mentions(mentions_df)
        except Exception as e:
            LOGGER.error("Failed inserting mention data for %s", org_id)
            LOGGER.error(e)
            LOGGER.error(traceback.format_exc)
            return 1
        return 0

    def get_credentials(self, org_id, sixgill_org_id, pe_org_uid, source_uid):
        """Get credentials."""
        # Fetch org root domains from Cybersixgill
        try:
            LOGGER.info("Fetching root domains for %s", org_id)
            roots = root_domains(sixgill_org_id)
            LOGGER.info(f"Got {org_id} roots:{roots}")
        except Exception as e:
            LOGGER.error("Failed fetching root domains for %s", org_id)
            LOGGER.error(e)
            return 1

        # Catch no root assets situation
        if len(roots) == 0:
            LOGGER.warning(
                f"{org_id} does not have any root domain assets in Cybersixgill"
            )
            return 0

        # Fetch credential data
        LOGGER.info("Fetching credential data for %s", org_id)
        if len(roots) > 100:
            # If >100 roots, break into chunks and fetch cred data
            LOGGER.warning(f"{org_id} has more than 100 root assets in cybersixgill, breaking into chunks of 100...")
            root_chunks = [roots[i:i + 100] for i in range(0, len(roots), 100)]
            creds_df = pd.DataFrame()
            for idx, chunk in enumerate(root_chunks):
                try:
                    print(f"Working on {len(chunk)} {org_id} domains (chunk {idx+1} of {len(root_chunks)})")
                    LOGGER.info(f"Working on {org_id} credentials, chunk {idx+1} of {len(root_chunks)}")
                    # Fetch cred data
                    chunk_creds_df = creds(chunk, START_DATE_TIME, END_DATE_TIME)
                    # Add dataframe cols
                    chunk_creds_df["organizations_uid"] = pe_org_uid
                    chunk_creds_df["data_source_uid"] = source_uid
                    creds_df = creds_df.append(chunk_creds_df, ignore_index=True)
                    LOGGER.info("Found %s credentials for this chunk", len(chunk_creds_df.index))
                except Exception as e:
                    LOGGER.error(f"Failed fetching credential data chunk {idx+1} for {org_id}")
                    LOGGER.error(e)
                    return 1
            LOGGER.info(f"Found {len(creds_df.index)} total credentials for {org_id}")
        else:
            # Otherwise, fetch all cred data
            try:
                print(f"Working on {len(roots)} {org_id} domains")
                LOGGER.info(f"Working on {org_id} credentials")
                # Fetch cred data
                creds_df = creds(roots, START_DATE_TIME, END_DATE_TIME)
                # Add dataframe cols
                creds_df["organizations_uid"] = pe_org_uid
                creds_df["data_source_uid"] = source_uid
                LOGGER.info(f"Found {len(creds_df.index)} total credentials for {org_id}")
            except Exception as e:
                LOGGER.error("Failed fetching credential data for %s", org_id)
                LOGGER.error(e)
                return 1

        # Catch no credentials found situation
        if creds_df.empty:
            LOGGER.info(f"No credential data found for {org_id}, moving on")
            return 0

        # Change empty and ambiguous breach names
        try:
            LOGGER.info("Formatting credential breach data for %s", org_id)
            creds_df.loc[
                creds_df["breach_name"] == "", "breach_name"
            ] = "Cybersixgill_" + creds_df["breach_id"].astype(str)
            creds_df.loc[
                creds_df["breach_name"] == "Automatic leaked credentials detection",
                "breach_name",
            ] = "Cybersixgill_" + creds_df["breach_id"].astype(str)
            creds_breach_df = creds_df[
                [
                    "breach_name",
                    "description",
                    "breach_date",
                    "password",
                    "data_source_uid",
                ]
            ].reset_index()
            # Create password_included column
            creds_breach_df["password_included"] = creds_breach_df["password"] != ""
            # Group breaches and count the number of credentials
            count_creds = creds_breach_df.groupby(
                [
                    "breach_name",
                    "description",
                    "breach_date",
                    "password_included",
                    "data_source_uid",
                ]
            ).size()
            creds_breach_df = count_creds.to_frame(
                name="exposed_cred_count"
            ).reset_index()
            creds_breach_df["modified_date"] = creds_breach_df["breach_date"]
            creds_breach_df.drop_duplicates(
                subset=["breach_name"], keep="first", inplace=True
            )
            creds_breach_df.drop(columns=["exposed_cred_count"], inplace=True)
        except Exception as e:
            LOGGER.error("Failed formatting credential breach data for %s", org_id)
            LOGGER.error(e)
            return 1

        # Insert breach data into the PE database
        try:
            LOGGER.info("Inserting credential breach data for %s", org_id)
            insert_sixgill_breaches(creds_breach_df)
        except Exception as e:
            LOGGER.error("Failed inserting credential breach data for %s", org_id)
            LOGGER.error(e)
            return 1

        # Get breach uids and match to credentials
        breach_dict = dict(get_breaches())
        for cred_index, cred_row in creds_df.iterrows():
            breach_uid = breach_dict[cred_row["breach_name"]]
            creds_df.at[cred_index, "credential_breaches_uid"] = breach_uid

        # Insert credential data into the PE database
        creds_df = creds_df.rename(
            columns={"domain": "sub_domain", "breach_date": "modified_date"}
        )
        creds_df = creds_df[
            [
                "modified_date",
                "sub_domain",
                "email",
                "hash_type",
                "name",
                "login_id",
                "password",
                "phone",
                "breach_name",
                "organizations_uid",
                "data_source_uid",
                "credential_breaches_uid",
            ]
        ]
        try:
            LOGGER.info("Inserting credential data for %s", org_id)
            insert_sixgill_credentials(creds_df)
        except Exception as e:
            LOGGER.error("Failed inserting credential data for %s", org_id)
            LOGGER.error(e)
            return 1
        return 0

    def get_topCVEs(self, source_uid):
        """Get top CVEs."""
        try:
            LOGGER.info(f"Fetching the current top CVEs")
            # Get top 10 cves
            top_cve_df = top_cves(10)
            # Add extra columns
            top_cve_df["date"] = END_DATE
            top_cve_df["nvd_base_score"] = top_cve_df["nvd_base_score"].astype("str")
            top_cve_df["data_source_uid"] = source_uid
            # Note: circl.lu (cve_summary()) is no longer being 
            # used b/c of API issues, CVE summaries are now 
            # coming from C6G
        except Exception as e:
            LOGGER.error("Failed fetching the current top CVEs")
            LOGGER.error(e)
            return 1

        # Insert top CVE data into the PE database
        try:
            LOGGER.info("Inserting top CVE data")
            insert_sixgill_topCVEs(top_cve_df)
        except Exception as e:
            LOGGER.error("Failed inserting top CVE data")
            LOGGER.error(e)
            return 1
        return 0