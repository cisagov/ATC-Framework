"""A tool for gathering pe source data.

Usage:
    pe-source DATA_SOURCE [--log-level=LEVEL] [--orgs=ORG_LIST] [--cybersix-methods=METHODS] [--soc_med_included]

Arguments:
    DATA_SOURCE                     Source to collect data from. Valid values are "cybersixgill",
                                    "dnsmonitor", "dnstwist", "intelx", "pshtt", "shodan", and "xpanse".

Options:
    -h --help                       Show this message.
    -v --version                    Show version information.
    -l --log-level=LEVEL            If specified, then the log level will be set to
                                    the specified value.  Valid values are "debug", "info",
                                    "warning", "error", and "critical". [default: info]
    -o --orgs=ORG_LIST              A comma-separated list of orgs to collect data for.
                                    If not specified, data will be collected for all
                                    orgs in the pe database. Orgs in the list must match the
                                    IDs in the cyhy-db. E.g. DHS,DHS_ICE,DOC. Enter DEMO to run all demo orgs
                                    [default: all]
    -csg --cybersix-methods=METHODS A comma-separated list of cybersixgill methods to run.
                                    If not specified, all will run. Valid values are "alerts",
                                    "credentials", "mentions", "topCVEs". E.g. alerts,mentions.
                                    [default: all]
    -sc --soc_med_included          Include social media posts from cybersixgill in data collection.
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
from .cybersixgill import Cybersixgill
from .dnsmonitor import DNSMonitor
from .dnstwistscript import run_dnstwist
from .hibp import Hibp
from .intelx_identity import IntelX
# from .pshtt_wrapper import launch_pe_pshtt
from .shodan_wrapper import Get_shodan
from .was_findings_sync import run_was_findings_sync
from .was_report_pull import run_was_report_pull
from .xpanse_alert_pull import run_xpanse_scans

LOGGER = logging.getLogger(__name__)


def run_pe_script(source, orgs_list, cybersix_methods, soc_med_included):
    """Collect data from the source specified."""
    # Determine list of organizations to run on
    if orgs_list != "all" and orgs_list != "DEMO" and source != "xpanse":
        # If list specified, use those orgs
        orgs_list = orgs_list.split(",")
        if len(orgs_list) == 1:
            orgs_list_short = orgs_list[0]
        else:
            orgs_list_short = f"{orgs_list[0]} - {orgs_list[-1]}"
    else:
        # If no list specified, use all orgs
        orgs_list_short = "All P&E Report orgs"

    # Determine which cybersixgill scans to run
    sixgill_scan_name = cybersix_methods.title()
    if cybersix_methods == "all":
        # If "all" run all cybersixgill scans
        cybersix_methods = ["alerts", "mentions", "credentials", "topCVEs"]
    else:
        # Otherwise run specified cybersixgill scans
        cybersix_methods = cybersix_methods.split(",")

    # Log scan start details
    scan_full_names = {
        "alerts": "Cybersixgill Alerts",
        "mentions": "Cybersixgill Mentions",
        "credentials": "Cybersixgill Credentials",
        "topCVEs": "Cybersixgill Top CVEs",
        "dnsmonitor": "DNSMonitor",
        "dnstwist": "DNSTwist",
        "hibp": "HaveIBeenPwned",
        "intelx": "IntelX",
        "pshtt": "Pshtt",
        "shodan": "Shodan",
        "was-findings-sync": "WAS Findings Sync",
        "was-report-pull": "WAS Report Pull",
        "xpanse": "Xpanse",
    }
    if source == "cybersixgill":
        scan_name = [scan_full_names[x] for x in cybersix_methods]
        if len(scan_name) > 1:
            scan_name = "(" + ", ".join(scan_name) + ")"
        else:
            scan_name = scan_name[0]
    else:
        scan_name = scan_full_names.get(source)
    LOGGER.info(f"--- {scan_name} Scan Starting ---")
    LOGGER.info(f"Running {scan_name} on these orgs: {orgs_list}")
    scan_start_time = time.time()
    
    # Run the specified scans
    if source == "cybersixgill":
        cybersix = Cybersixgill(orgs_list, cybersix_methods, soc_med_included)
        cybersix.run_cybersixgill()
    elif source == "dnsmonitor":
        dnsMonitor = DNSMonitor(orgs_list)
        dnsMonitor.run_dnsMonitor()
    elif source == "dnstwist":
        run_dnstwist(orgs_list)
    elif source == "hibp":
        hibp = Hibp(orgs_list)
        hibp.run_hibp()
    elif source == "intelx":
        intelx = IntelX(orgs_list)
        intelx.run_intelx()
    elif source == "pshtt":
        # launch_pe_pshtt()
        LOGGER.error("ERROR: Pshtt has been disabled due to failing tests. Do not reenable until fixed.")
    elif source == "shodan":
        shodan = Get_shodan(orgs_list)
        shodan.run_shodan()
    elif source == "was-findings-sync":
        run_was_findings_sync()
    elif source == "was-report-pull":
        run_was_report_pull()
    elif source == "xpanse":
        run_xpanse_scans("", orgs_list)
    else:
        LOGGER.error(
            "Not a valid script name."
        )
        sys.exit(1)
    
    # Log scan completion details
    scan_end_time = time.time()
    LOGGER.info(f"Execution time for {scan_name} scan ({orgs_list_short}): {str(timedelta(seconds=(scan_end_time - scan_start_time)))} (H:M:S)")
    LOGGER.info(f"--- {scan_name} Scan Complete ---")


def main():
    """Set up logging and call the run_pe_script function."""
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

    # Run pe script for the specified source
    run_pe_script(
        validated_args["DATA_SOURCE"],
        validated_args["--orgs"],
        validated_args["--cybersix-methods"],
        validated_args["--soc_med_included"],
    )

    # Stop logging and clean up
    logging.shutdown()