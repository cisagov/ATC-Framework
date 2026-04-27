"""Collect DNSMonitor data."""

# Standard Python Libraries
import datetime
import logging

# cisagov Libraries
from pe_source.data.dnsmonitor.source import (
    get_dns_records,
    get_domain_alerts,
    get_monitored_domains,
)
from pe_source.data.pe_db.config import dnsmonitor_token
from pe_source.data.pe_db.db_query_source import (
    addSubdomain,
    execute_dnsmonitor_alert_data,
    execute_dnsmonitor_data,
    get_data_source_uid,
    get_orgs,
    getSubdomain,
)

NOW = datetime.datetime.now()
DAYS_BACK = datetime.timedelta(days=20)
DAY = datetime.timedelta(days=1)
START_DATE = NOW - DAYS_BACK
END_DATE = NOW + DAY

LOGGER = logging.getLogger(__name__)


class DNSMonitor:
    """Fetch DNSMonitor data."""

    def __init__(self, orgs_list):
        """Initialize Shodan class."""
        self.orgs_list = orgs_list

    def run_dnsMonitor(self):
        """Run DNSMonitor calls."""
        orgs_list = self.orgs_list

        # Get orgs from PE database
        pe_orgs = get_orgs()

        # Filter orgs if specified
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

        # alphabetize orgs for consistent order
        pe_orgs_final = sorted(pe_orgs_final, key=lambda d: d["cyhy_db_name"])

        # Fetch the bearer token
        token = dnsmonitor_token()
        # Get all of the domains being monitored
        domain_df = get_monitored_domains(token)

        # Iterate over each org
        failed = []
        warnings = []
        for org_idx, org in enumerate(pe_orgs_final):
            org_uid = org["organizations_uid"]
            org_code = org["cyhy_db_name"]
            LOGGER.info(
                f"Running DNSMonitor on {org_code} ({org_idx+1} of {len(pe_orgs_final)})"
            )

            # Get the DNSMonitor domain IDs associated with this org
            domain_ids = domain_df[domain_df["org"] == org_code]
            LOGGER.info(
                f"Found {len(domain_ids)} root domains being monitored for {org_code}"
            )
            domain_ids = str(domain_ids["domainId"].tolist())

            # Get Alerts for the current org based on the list of domain IDs
            if domain_ids == "[]":
                LOGGER.warning(
                    f"No domains being monitored by DNSMonitor for {org_code}"
                )
                warnings.append(f"{org_code} - No domains being monitored")
                continue
            else:
                alerts_df = get_domain_alerts(token, domain_ids, START_DATE, END_DATE)
                LOGGER.info("Retrieved %s alerts", len(alerts_df.index))

            # If no alerts, continue
            if alerts_df.empty:
                LOGGER.warning(f"No DNSMonitor alerts found for {org_code}")
                warnings.append(f"{org_code} - No alerts found")
                continue

            # Process each alert
            for alert_index, alert_row in alerts_df.iterrows():
                # Get the subdomain_uid for this alert's domain
                root_domain = alert_row["rootDomain"]
                sub_domain_uid = getSubdomain(root_domain)

                # If subdomain isn't in PE DB yet, attempt to add it
                if (sub_domain_uid == -1) or (not sub_domain_uid):
                    LOGGER.info(
                        "Domain %s isn't in the subdomain table, attempting to add it",
                        root_domain,
                    )
                    try:
                        addSubdomain(root_domain, org_uid, True)  # api ver.
                        # addSubdomain(conn, root_domain, org_uid, True) # tsql ver.
                        LOGGER.info(
                            "Success adding %s to the subdomain table", root_domain
                        )
                    except Exception as e:
                        LOGGER.error("Failure adding domain to subdomain table")
                        LOGGER.error(e)
                        failed.append(
                            f"{org_code} - {root_domain} - Failed inserting into subdomain table"
                        )
                    # Once the new subdomain has been created, retrieve its uid
                    sub_domain_uid = getSubdomain(root_domain)

                # Add subdomain_uid to the alert record
                alerts_df.at[alert_index, "sub_domain_uid"] = sub_domain_uid

                # Get DNS records for each domain permutation
                dom_perm = alert_row["domainPermutation"]
                mx_list, ns_list, ipv4, ipv6 = get_dns_records(dom_perm)

                # Add records to the dataframe
                alerts_df.at[alert_index, "mail_server"] = mx_list
                alerts_df.at[alert_index, "name_server"] = ns_list
                alerts_df.at[alert_index, "ipv4"] = ipv4
                alerts_df.at[alert_index, "ipv6"] = ipv6

            # Set the data_source_uid and organization_uid
            alerts_df["data_source_uid"] = get_data_source_uid("DNSMonitor")
            alerts_df["organizations_uid"] = org_uid

            # Format domain_permutations dataframe
            alerts_df = alerts_df.rename(
                columns={
                    "domainPermutation": "domain_permutation",
                    "dateCreated": "date_observed",
                    "alertType": "alert_type",
                    "previousValue": "previous_value",
                    "newValue": "new_value",
                }
            )
            dom_perm_df = alerts_df[
                [
                    "organizations_uid",
                    "sub_domain_uid",
                    "data_source_uid",
                    "domain_permutation",
                    "ipv4",
                    "ipv6",
                    "mail_server",
                    "name_server",
                    "date_observed",
                ]
            ]
            dom_perm_df = dom_perm_df.drop_duplicates(
                subset=["domain_permutation"], keep="last"
            )
            # Insert into domain_permutations table
            try:
                LOGGER.info(f"Inserting DNSMonitor domain permutations for {org_code}")
                execute_dnsmonitor_data(dom_perm_df)  # api ver.
                # execute_dnsmonitor_data(dom_perm_df, "domain_permutations") # tsql ver.
            except Exception as e:
                LOGGER.error(
                    "Failed inserting DNSMonitor domain permutations for %s", org_code
                )
                LOGGER.error(e)
                failed.append(f"{org_code} - Failed inserting into domain_permutations")

            # Format domain alerts dataframe
            alerts_df = alerts_df.rename(columns={"date_observed": "date"})
            domain_alerts = alerts_df[
                [
                    "organizations_uid",
                    "sub_domain_uid",
                    "data_source_uid",
                    "alert_type",
                    "message",
                    "previous_value",
                    "new_value",
                    "date",
                ]
            ]
            # Insert into domain_alerts table
            try:
                LOGGER.info(f"Inserting DNSMonitor domain alerts for {org_code}")
                execute_dnsmonitor_alert_data(domain_alerts)  # api ver.
                # execute_dnsmonitor_alert_data(domain_alerts, "domain_alerts") # tsql ver.
            except Exception as e:
                LOGGER.error(
                    "Failed inserting DNSMonitor domain alerts for %s", org_code
                )
                LOGGER.error(e)
                failed.append(f"{org_code} - Failed inserting into domain_alerts")

        # Output any warnings
        if len(warnings) > 0:
            LOGGER.warning("Warnings: %s", warnings)

        # Output any failures
        if len(failed) > 0:
            LOGGER.error("Failures: %s", failed)

        # Output summary stats
        num_no_domain_monitor = sum("No domains being monitored" in s for s in warnings)
        num_no_alerts = sum("No alerts found" in s for s in warnings)
        num_success = (
            len(pe_orgs_final) - num_no_domain_monitor - num_no_alerts - len(failed)
        )
        num_fail = len(failed)
        LOGGER.info(
            f"{num_no_domain_monitor}/{len(pe_orgs_final)} orgs do not have domains being monitored by DNSMonitor"
        )
        LOGGER.info(
            f"{num_no_alerts}/{len(pe_orgs_final)} orgs have domains being monitored, but didn't have any new alerts"
        )
        LOGGER.info(
            f"{num_success}/{len(pe_orgs_final)} orgs had new DNSMonitor findings and successfully added them to the database"
        )
        LOGGER.info(
            f"{num_fail}/{len(pe_orgs_final)} orgs had a significant failure during the DNSMonitor scan"
        )
