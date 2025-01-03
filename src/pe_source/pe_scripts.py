"""A tool for gathering pe source data.

Usage:
    pe-source DATA_SOURCE [--log-level=LEVEL] [--orgs=ORG_LIST] [--cybersix-methods=METHODS] [--soc_med_included]

Arguments:
  DATA_SOURCE                       Source to collect data from. Valid values are "cybersixgill",
                                    "dnstwist", "hibp", "intelx", "pshtt", and "shodan".

Options:
  -h --help                         Show this message.
  -v --version                      Show version information.
  -l --log-level=LEVEL              If specified, then the log level will be set to
                                    the specified value.  Valid values are "debug", "info",
                                    "warning", "error", and "critical". [default: info]
  -o --orgs=ORG_LIST                A comma-separated list of orgs to collect data for.
                                    If not specified, data will be collected for all
                                    orgs in the pe database. Orgs in the list must match the
                                    IDs in the cyhy-db. E.g. DHS,DHS_ICE,DOC. Enter DEMO to run all demo orgs
                                    [default: all]
  -csg --cybersix-methods=METHODS   A comma-separated list of cybersixgill methods to run.
                                    If not specified, all will run. Valid values are "alerts",
                                    "credentials", "mentions", "topCVEs". E.g. alerts,mentions.
                                    [default: all]
  -sc --soc_med_included            Include social media posts from cybersixgill in data collection.
"""

# Standard Python Libraries
import logging
import sys
import time
from typing import Any, Dict

# Third-Party Libraries
from datetime import timedelta
import docopt
from schema import And, Schema, SchemaError, Use

# cisagov Libraries
import pe_reports

from ._version import __version__
from .cybersixgill import Cybersixgill
from .dnsmonitor import DNSMonitor
from .dnstwistscript import run_dnstwist
from .intelx_identity import IntelX
from .pshtt_wrapper import launch_pe_pshtt
from .shodan_wrapper import Get_shodan

LOGGER = logging.getLogger(__name__)


def run_pe_script(source, orgs_list, cybersix_methods, soc_med_included):
    """Collect data from the source specified."""
    # If not "all", separate orgs string into a list of orgs
    if orgs_list != "all" and orgs_list != "DEMO":
        orgs_list = orgs_list.split(",")
        orgs_list_logging = f"{orgs_list[0]} - {orgs_list[-1]}"
    else:
        orgs_list_logging = "all P&E Report orgs"


    # If not "all", separate Cybersixgill methods string into a list
    sixgill_scan_name = cybersix_methods.title()
    if cybersix_methods == "all":
        cybersix_methods = ["alerts", "mentions", "credentials", "topCVEs"]
    else:
        cybersix_methods = cybersix_methods.split(",")

    # LOGGER.info("Running %s on these orgs: %s", source, orgs_list)

    if source == "cybersixgill":
        if sixgill_scan_name == "Topcves":
            sixgill_scan_name = "Top CVEs"
        LOGGER.info(f"--- Cybersixgill {sixgill_scan_name} Scan Starting ---")
        LOGGER.info(f"Running Cybersixgill {sixgill_scan_name} on these orgs: {orgs_list}")
        sixgill_start_time = time.time()
        cybersix = Cybersixgill(orgs_list, cybersix_methods, soc_med_included)
        cybersix.run_cybersixgill()
        sixgill_end_time = time.time()
        LOGGER.info(f"Execution time for Cybersixgill {sixgill_scan_name} scan ({orgs_list_logging}): {str(timedelta(seconds=(sixgill_end_time - sixgill_start_time)))} (H:M:S)")
        LOGGER.info(f"--- Cybersixgill {sixgill_scan_name} Scan Complete ---")
    elif source == "shodan":
        LOGGER.info("--- Shodan Scan Starting ---")
        LOGGER.info(f"Running Shodan on these orgs: {orgs_list}")
        shodan_start_time = time.time()
        shodan = Get_shodan(orgs_list)
        shodan.run_shodan()
        shodan_end_time = time.time()
        LOGGER.info(f"Execution time for Shodan scan: {str(timedelta(seconds=(shodan_end_time - shodan_start_time)))} (H:M:S)")
        LOGGER.info("--- Shodan Scan Complete ---")
    elif source == "dnsmonitor":
        LOGGER.info("--- DNSMonitor Scan Starting ---")
        LOGGER.info(f"Running DNSMonitor on these orgs: {orgs_list}")
        dnsmonitor_start_time = time.time()
        dnsMonitor = DNSMonitor(orgs_list)
        dnsMonitor.run_dnsMonitor()
        dnsmonitor_end_time = time.time()
        LOGGER.info(f"Execution time for DNSMonitor scan: {str(timedelta(seconds=(dnsmonitor_end_time - dnsmonitor_start_time)))} (H:M:S)")
        LOGGER.info("--- DNSMonitor Scan Complete ---")
    elif source == "dnstwist":
        LOGGER.info("--- DNSTwist Scan Starting ---")
        LOGGER.info(f"Running DNSTwist on these orgs: {orgs_list}")
        dnstwist_start_time = time.time()
        run_dnstwist(orgs_list)
        dnstwist_end_time = time.time()
        LOGGER.info(f"Execution time for DNSTwist scan: {str(timedelta(seconds=(dnstwist_end_time - dnstwist_start_time)))} (H:M:S)")
        LOGGER.info("--- DNSTwist Scan Complete ---")
    elif source == "intelx":
        LOGGER.info("--- IntelX Scan Starting ---")
        LOGGER.info(f"Running IntelX on these orgs: {orgs_list}")
        intelx_start_time = time.time()
        intelx = IntelX(orgs_list)
        intelx.run_intelx()
        intelx_end_time = time.time()
        LOGGER.info(f"Execution time for IntelX scan ({orgs_list_logging}): {str(timedelta(seconds=(intelx_end_time - intelx_start_time)))} (H:M:S)")
        LOGGER.info("--- IntelX Scan Complete ---")
    elif source == "pshtt":
        launch_pe_pshtt()
    else:
        logging.error(
            "Not a valid source name. Correct values are cybersixgill or shodan."
        )
        sys.exit(1)


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

    # Run pe script on specified source
    run_pe_script(
        validated_args["DATA_SOURCE"],
        validated_args["--orgs"],
        validated_args["--cybersix-methods"],
        validated_args["--soc_med_included"],
    )

    # Stop logging and clean up
    logging.shutdown()
