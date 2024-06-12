"""File containing generalized helper functions for adhoc investigations."""
# Standard Python Libraries
import ipaddress
import math
from pathlib import Path


def calc_progress(total_len, curr_idx):
    """Generate progress string for logging."""
    if curr_idx == math.ceil(total_len/4):
        return "25% complete"
    elif curr_idx == math.ceil(total_len/2):
        return "50% complete"
    elif curr_idx == math.ceil(total_len * 0.75):
        return "75% complete"
    elif curr_idx == (total_len - 1):
        return "100% complete" 
    

def result_code_to_string(result_code):
    """Translate result code to string."""
    if result_code == 0:
        return "No results found"
    elif result_code == 1:
        return "Results found"
    elif result_code == 2:
        return "Scan skipped"
    

def check_output_exists(org_abbrv, scan_name, date):
    """Check if a result file exists for the specified org/scan/date."""
    output_file = Path(f"./output_data/{org_abbrv}_adhoc_findings_{date}/{org_abbrv}_{scan_name}_data_{date}.csv")
    if output_file.is_file():
        return "Results found"
    else:
        return "No results found"
    

def convert_to_list_of_ips(mixed_list):
    """Take a mixed list of cidr blocks and ips and covert to a list of all ips."""
    final_list = []
    for item in mixed_list:
        if "/" in item[-3:]:
            # If CIDR block, break into IPs and append
            cidr_list = [str(ip) for ip in ipaddress.IPv4Network(item)]
            final_list.extend(cidr_list)
        else:
            # If IP address, append
            final_list.append(item)
    return final_list