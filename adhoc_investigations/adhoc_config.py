"""Configuration parser for adhoc investigation ini file."""

# Standard Python Libraries
from configparser import ConfigParser
import os

# Third-Party Libraries
from importlib_resources import files

INI_FILE = "./adhoc_investigation.ini"

def get_ini_data(filename=INI_FILE, section="adhoc_investigation"):
    """Parse adhoc investigation configuration details from ini file."""
    # Create config parser
    parser = ConfigParser()
    parser.read(filename, encoding="utf-8")
    # Parse ini variables
    result_dict = dict()
    if parser.has_section(section):
        for key, value in parser.items(section):
            result_dict[key] = value
    else:
        raise Exception(f"Section {section} not found in {filename}")
    # Return .ini variables as a dict
    return result_dict