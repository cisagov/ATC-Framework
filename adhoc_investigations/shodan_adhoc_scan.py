"""Adhoc version of the Shodan scan."""
# Standard Python Libraries
import logging

# Third-Party Libraries
import pandas as pd
import shodan

# .ini Data
import adhoc_config

# Setup logging
main_log = logging.getLogger(__name__)

# Shodan API Info
api_key = adhoc_config.get_ini_data().get("shodan")


def get_shodan_data(org_uid, org_abbrv, ips, save_file):
    """Retrieve Shodan data for the specified IPs."""
    main_log.info(f"=== {org_abbrv} Shodan Adhoc Scan Starting ===")
    # Connect to Shodan API
    shodan_api = shodan.Shodan(api_key)

    # Break up IPs into chunks, shodan api max = 100 ips/call
    num_ips = len(ips)
    ip_chunks = [ips[i : i + 100] for i in range(0, num_ips, 100)]
    num_chunks = len(ip_chunks)
    main_log.info(f"Split {num_ips} total IPs into {num_chunks} chunks for {org_abbrv}")
    total_results = []

    # Feed all IP chunks through shodan
    for i, ip_chunk in enumerate(ip_chunks):
        main_log.info(f"On chunk {i+1} of {num_chunks}")
        # main_log.info("\tFetching Shodan data for these IP addresses:")
        # main_log.info("\t", ip_chunk)
        # Search for chunk using Shodan
        try:
            results = shodan_api.host(ip_chunk)
            # Ensure result is always a list
            if isinstance(results, dict):
                results = [results]
            # Iterate through all results
            for r in results:
                # Iterate through all data entries
                for d in r.get("data"):
                    # Grab relevant info
                    curr_os = d.get("os", None)
                    curr_vulns = d.get("vulns", None)
                    curr_port = d.get("port", None)
                    curr_ip = d.get("ip_str", None)
                    curr_time = d.get("timestamp", None)
                    curr_row = {
                        "ip": curr_ip,
                        "port": curr_port,
                        "os": curr_os,
                        "vulns": curr_vulns,
                        "timestamp": curr_time,
                    }
                    total_results.append(curr_row)
        except shodan.APIError as e:
            main_log.info('\t*** Error: {}'.format(e))
        main_log.info("\tChunk complete")

    # final aggregation
    final_df = pd.DataFrame(total_results)
    final_df.insert(0, "organizations_uid", org_uid)
    final_df.insert(1, "org_abbrv", org_abbrv)
    # report stats
    main_log.info(f"{len(final_df)} Shodan records found for the {num_ips} IPs input")
    if len(final_df) > 0:
        main_log.info(f"Saving to file: {save_file}")
        final_df.to_csv(save_file)
        main_log.info(f"=== {org_abbrv} Shodan Adhoc Scan Complete ===")
        return 1
    else:
        main_log.info("No results found, nothing to save")
        main_log.info(f"=== {org_abbrv} Shodan Adhoc Scan Complete ===")
        return 0