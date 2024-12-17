"""A tool for gathering pe asm data.

Usage:
    pe-asm-sync METHOD [--log-level=LEVEL] [--staging] [--org=ORG]

Options:
  -h --help                         Show this message.
  METHOD                            Either scorecard or asm. Which data to collect.
  -v --version                      Show version information.
  -l --log-level=LEVEL              If specified, then the log level will be set to
                                    the specified value.  Valid values are "debug", "info",
                                    "warning", "error", and "critical". [default: info]
  -o --org=ORG                      The cyhy_db_name of the single organization to collect data for.
                                    This option is only used for the SQS version of the ASM Sync.
                                    Org name must match the ID in the cyhy-db. E.g. DHS,DHS_ICE,DOC.
                                    [default: all]
  -s --staging                      Run on the staging database. Otherwise will run on a local copy.
"""

# Standard Python Libraries
from datetime import timedelta
import logging
import sys
import time
from typing import Any, Dict

# Third-Party Libraries
import docopt
from schema import And, Schema, SchemaError, Use

# cisagov Libraries
import pe_reports

from ._version import __version__

# from .helpers.query_cyhy_port_scans import get_cyhy_port_scans
from .data.cyhy_db_query import (
    identified_sub_domains,
    identify_cidr_changes,
    identify_ip_changes,
    identify_ip_sub_changes,
    identify_sub_changes,
    pe_db_connect,
    pe_db_staging_connect,
    # SQS version imports
    sqs_query_org,
    sqs_identify_cidr_changes,
    sqs_identify_ip_changes,
    sqs_identify_sub_changes,
    sqs_identify_ip_sub_changes,
    sqs_identified_sub_domains,
)
from .helpers.enumerate_subs_from_root import get_subdomains
from .helpers.fill_cidrs_from_cyhy_assets import fill_cidrs
from .helpers.get_cyhy_assets import get_cyhy_assets
from .helpers.get_cyhy_scorecard_data import (
    get_cyhy_https_scan,
    get_cyhy_kevs,
    get_cyhy_snapshots,
    get_cyhy_sslyze,
    get_cyhy_tickets,
    get_cyhy_trustymail,
    get_cyhy_vuln_scans,
)
from .helpers.link_subs_and_ips_from_ips import connect_subs_from_ips
from .helpers.link_subs_and_ips_from_subs import connect_ips_from_subs
from .helpers.shodan_dedupe import dedupe
from .port_scans.run_port_scans import get_cyhy_port_scans

# Setup logging
LOGGER = logging.getLogger(__name__)


def run_asm_sync(staging, method, org):
    """Collect and sync ASM data."""
    if method == "asm":
        # Non-SQS version of ASM Sync
        LOGGER.info("--- ASM Sync Process Starting ---")
        asm_start = time.time()

        # --- Local Portion of ASM Sync ---
        # *** This portion of the ASM Sync process needs to be run locally
        # on a Macbook because the Accessor is not allowed to directly
        # connect to the CyHy environment. A dedicated python script is 
        # available for this "local step" of the ASM Sync

        # Fetch assets from the CyHy database and store them in the PE database
        # LOGGER.info("Retrieving assets from the CyHy database...")
        # get_cyhy_assets(staging) # <- needs to happen locally
        # LOGGER.info("Finished retrieving assets from the CyHy database")


        # --- Non-Local Portion of ASM Sync ---
        # *** This portion of the ASM Sync process can run remotely on the
        # Accessor because it does not require connecting to the CyHy environment
        print("*** Running ATC-Framework version of ASM Sync ***")

        # Fill the PE CIDRs table using the CyHy assets
        LOGGER.info("Filling the CIDRs table using the retrieved CyHy assets...")
        fill_cidrs(staging, "all_orgs")
        LOGGER.info("Finished filling the CIDRs table using the retrieved CyHy assets")
        # Identify which CIDRs are current
        LOGGER.info("Identifying CIDR changes...")
        identify_cidr_changes(staging)
        LOGGER.info("Finished identifying CIDR changes")

        # Fill root domains using the retrieved dot gov data
        LOGGER.info("Filling the root domains table using the retrieved dot gov data...")
        # TODO
        LOGGER.info("Finished filling the root domains table using the retrieved dot gov data")

        # Enumerate subdomains from roots
        LOGGER.info("Enumerating sub-domains from root domains...")
        get_subdomains(staging)
        LOGGER.info("Finished enumerating sub-domains from root domains")

        # Link subdomains and ips using ips
        LOGGER.info("Linking sub-domains and ips using ips...")
        connect_subs_from_ips(staging) # *** Takes a really long time ~16 days
        LOGGER.info("Finished linking sub-domains and ips using ips")

        # Link subdomains and ips using subdomains
        LOGGER.info("Linking sub-domains and ips using sub-domains...")
        connect_ips_from_subs(staging) # Takes a little more than a day
        LOGGER.info("Finished linking sub-domains and ips using sub-domains")

        # Identify which IPs, sub-domains, and connections are current
        LOGGER.info("Identify IP changes...")
        identify_ip_changes(staging)
        LOGGER.info("Finished identifying IP changes")
        LOGGER.info("Identifying sub-domain changes...")
        identify_sub_changes(staging)
        LOGGER.info("Finished identifying sub-domain changes")
        LOGGER.info("Identifying IP sub-domain link changes...")
        identify_ip_sub_changes(staging)
        LOGGER.info("Finished identifying IP sub-domain link changes")
        LOGGER.info("Updating identified sub-domains...")
        identified_sub_domains(staging)
        LOGGER.info("Finished updating identified sub-domains")

        # Run shodan dedupe
        LOGGER.info("Running Shodan dedupe...")
        dedupe(staging) # Takes about ~12hrs
        LOGGER.info("Finished running Shodan dedupe")

        asm_end = time.time()
        LOGGER.info(f"Execution time for ASM Sync: {str(timedelta(seconds=(asm_end - asm_start)))} (H:M:S)")
        LOGGER.info("--- ASM Sync Process Complete ---")

    if method == "asm-sqs":
        # SQS version of the ASM Sync (single org)
        LOGGER.info(f"--- SQS ASM Sync Process Starting for {org} ---")
        sqs_asm_start = time.time()

        # --- Local Portion of ASM Sync ---
        # *** Warning: The local portion of the ASM Sync process needs 
        # to be run locally on a Macbook before the following code can
        # run. A dedicated python script is available for this 
        # "local step" of the ASM Sync

        # --- Non-Local Portion of ASM Sync ---
        # *** This portion of the ASM Sync process can run remotely on the
        # Accessor because it does not require connecting to the CyHy environment

        # Retrieve additional info for the specified org
        org_df = sqs_query_org(staging, org)
        org_uid = org_df["organizations_uid"][0]

        # Fill the cidrs table with new data from the cyhy_db_assets
        LOGGER.info("Filling the CIDRs table using the retrieved CyHy assets...")
        fill_cidrs(staging, org_df) 
        LOGGER.info("Finished filling the CIDRs table using the retrieved CyHy assets")

        # Identify which CIDRs are current
        LOGGER.info("Identifying CIDR changes...")
        sqs_identify_cidr_changes(staging, org_uid) 
        LOGGER.info("Finished identifying CIDR changes")

        # Enumerate subdomains from roots
        LOGGER.info("Enumerating sub-domains from root domains...")
        get_subdomains(staging, org_df) 
        LOGGER.info("Finished enumerating sub-domains from root domains")

        # Enumerate subdomains from IPs
        LOGGER.info("Linking sub-domains and ips using ips...")
        connect_subs_from_ips(staging, org_df) 
        LOGGER.info("Finished linking sub-domains and ips using ips")

        # Enumerate IPs from subdomains
        LOGGER.info("Linking sub-domains and ips using sub-domains...")
        connect_ips_from_subs(staging, org_df) 
        LOGGER.info("Finished linking sub-domains and ips using sub-domains")

        # Identify which IPs, sub-domains, and connections are current
        LOGGER.info("Identify IP changes...")
        sqs_identify_ip_changes(staging, org_uid) 
        LOGGER.info("Finished identifying IP changes")
        LOGGER.info("Identifying sub-domain changes...")
        sqs_identify_sub_changes(staging, org_uid) 
        LOGGER.info("Finished identifying sub-domain changes")
        LOGGER.info("Identifying IP sub-domain link changes...")
        sqs_identify_ip_sub_changes(staging, org_uid) 
        LOGGER.info("Finished identifying IP sub-domain link changes")
        LOGGER.info("Updating identified sub-domains...")
        sqs_identified_sub_domains(staging, org_uid) 
        LOGGER.info("Finished updating identified sub-domains")

        # Run shodan dedupe
        LOGGER.info("Running Shodan dedupe...")
        dedupe(staging, org_df) 
        LOGGER.info("Finished running Shodan dedupe")

        sqs_asm_end = time.time()
        LOGGER.info(f"SQS ASM Sync execution time for {org}: {str(timedelta(seconds=(sqs_asm_end - sqs_asm_start)))} (H:M:S)")
        LOGGER.info(f"--- SQS ASM Sync Process Complete for {org} ---")

    elif method == "scorecard":
        LOGGER.info("STARTING")
        get_cyhy_port_scans(staging)
        get_cyhy_snapshots(staging)
        get_cyhy_tickets(staging)
        get_cyhy_vuln_scans(staging)
        get_cyhy_kevs(staging)
        get_cyhy_https_scan(staging)
        get_cyhy_trustymail(staging)
        get_cyhy_sslyze(staging)
        LOGGER.info("FINISHED")

    else:
        LOGGER.error(
            "Please specify either 'scorecard' or 'asm' in your command. i.e. pe-asm-sync scorecard"
        )


def main():
    """Set up logging and call the run_asm_sync function."""
    args: Dict[str, str] = docopt.docopt(__doc__, version=__version__)
    # Validate and convert arguments as needed
    schema: Schema = Schema(
        {
            "--log-level": And(
                str,
                Use(str.lower),
                lambda n: n in ("debug", "info", "warning", "error", "critical"),
                error="Possible values for --log-level are "
                + "debug, info, warning, error, and critical.",
            ),
            str: object,  # Don't care about other keys, if any
        }
    )

    try:
        validated_args: Dict[str, Any] = schema.validate(args)
    except SchemaError as err:
        # Exit because one or more of the arguments were invalid
        print(err, file=sys.stderr)
        sys.exit(1)

    # Assign validated arguments to variables
    log_level: str = validated_args["--log-level"]

    # Set up logging
    logging.basicConfig(
        filename=pe_reports.CENTRAL_LOGGING_FILE,
        filemode="a",
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%m/%d/%Y %I:%M:%S",
        level=log_level.upper(),
    )

    # Check for the staging option
    try:
        staging = validated_args["--staging"]
    except Exception as e:
        print(e)
        staging = False

    # Run ASM Sync
    run_asm_sync(staging, validated_args["METHOD"], validated_args["--org"])

    # Stop logging and clean up
    logging.shutdown()
