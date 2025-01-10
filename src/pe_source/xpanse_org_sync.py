"""Script to save Xpanse Business Units and link to cyhy orgs.

Usage:
  xpanse_org_sync.py XPANSE_ORG_CSV_PATH [--log-level=LEVEL]

Options:
  -h --help                         Show this message.
  XPANSE_ORG_CSV_PATH               The path to the XPANSE Business_unit CSV.
  -l --log-level=LEVEL              If specified, then the log level will be set to
                                    the specified value.  Valid values are "debug", "info",
                                    "warning", "error", and "critical". [default: info]
"""
# Standard Python Libraries
import csv
import datetime
import json
import logging
import sys
from typing import Any, Dict
import re

# Third-Party Libraries
from _version import __version__
from data.pe_db.db_query_source import (  # api_pull_xpanse_vulns,
    insert_or_update_business_unit,
)
import docopt
import pytz
import requests
from schema import And, Or, Schema, SchemaError, Use

# cisagov Libraries
import pe_reports
from pe_reports.data.config import staging_config

LOGGER = logging.getLogger(__name__)

def extract_last_substring_in_square_brackets(input_string):
    # Define the regular expression pattern
    pattern = r'\[([^\]]+)\]'  # Matches [ followed by any characters that are not ], followed by ]

    # Find all matches of the pattern in the input_string
    matches = re.findall(pattern, input_string)
    # Return the last match or None if no matches are found
    return matches[-1] if matches else None

def sync_orgs(orgs_csv):
    """Sync orgs to the database."""
    try:
        print(orgs_csv)
        orgs_reader = csv.DictReader(orgs_csv)
    except FileNotFoundError:
        LOGGER.error("No file found at provided filepath.")
    except Exception as e:
        LOGGER.error("Unknown error reading csv: %s", e)

    # map_dict = {}
    # try:
    #     file_path = 'xpanse_org_map.csv'
    #     with open(file_path, 'r', encoding='utf-8-sig') as csvfile:
    #         map_reader = csv.DictReader(csvfile)
            
    #         for d in map_reader:
    #             print(d)
    #             # Add key-value pair to the result dictionary
    #             print(d['Xpanse Business Unit Name'])
    #             print(d['CISA Short Code'])
    #             map_dict[d['Xpanse Business Unit Name']] = d['CISA Short Code']  # Print each row as a dictionary
    # except FileNotFoundError:
    #     print(f"Error: File '{file_path}' not found.")
    # except Exception as e:
    #     print(f"Error reading '{file_path}': {e}")
    # # Initialize an empty dictionary to store the result
    # print(map_dict)
    
    for org in orgs_reader:
        try:
            # if map_dict.get(org["Entity Name"].strip(), None) is not None:
            #     print(map_dict.get(org["Entity Name"].strip()))
            cyhy_db_name = extract_last_substring_in_square_brackets(org["Entity Name"].strip())
            if cyhy_db_name:
                print(cyhy_db_name)
            business_unit_dict = {
                "entity_name": org["Entity Name"].strip(),
                "state": org["State"].strip(),
                "county": org["County"].strip(),
                "city": org["City"].strip(),
                "sector": org["Sector"].strip(),
                "entity_type": org["Entity Type"].strip(),
                "region": org["Region"].strip(),
                "rating": int(org["Rating"].strip()),
                "cyhy_db_name": cyhy_db_name
            }

            response = insert_or_update_business_unit(business_unit_dict)
        except Exception as e:
            LOGGER.error('Failure saving %s', org["Entity Name"])
            LOGGER.error("Unknown error saving: %s", e)
            continue


def main():
    """Launch Xpanse scans."""
    args: Dict[str, str] = docopt.docopt(__doc__, version=__version__)
    
   
    schema: Schema = Schema(
        {
            "--log-level": And(
                str,
                Use(str.lower),
                lambda n: n in ("debug", "info", "warning", "error", "critical"),
                error="Possible values for --log-level are "
                + "debug, info, warning, error, and critical.",
            ),
            "XPANSE_ORG_CSV_PATH": Or(
                None,
                Use(open, error="XPANSE_ORG_CSV_PATH should point to a readable CSV"),
            )
        }
    )
    

    try:
        
        validated_args: Dict[str, Any] = schema.validate(args)
        
    except SchemaError as err:
        # Exit because one or more of the arguments were invalid
        print(err, file=sys.stderr)
        sys.exit(1)


    log_level: str = validated_args["--log-level"]

    logging.basicConfig(
        filename=pe_reports.CENTRAL_LOGGING_FILE,
        filemode="a",
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%m/%d/%Y %I:%M:%S",
        level=log_level.upper(),
    )

    sync_orgs(validated_args["XPANSE_ORG_CSV_PATH"])

if __name__ == "__main__":
    main()