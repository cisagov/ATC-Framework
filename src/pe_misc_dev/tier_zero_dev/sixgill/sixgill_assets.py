"""Scripts to calculate Cybersixgill asset stats."""

# Standard Python Libraries
import asyncio
import csv
import ipaddress
import os

# Third-Party Libraries
from icmplib import async_multiping
import pandas as pd


async def bulk_ping_ip(ip_list):
    """Test if the specified list of IP addressses is responsive."""
    hosts = await async_multiping(ip_list, count=1)
    responsive_ips = [host.address for host in hosts if host.is_alive]
    return responsive_ips


def calc_responsive_ips(cidr_file, save_file):
    """Scan the specified CIDRs for responsive IP addresses."""
    # Load CIDR dataframe
    cidr_df = pd.read_csv(cidr_file, index_col=False)

    # Create save file if not exists
    if not os.path.exists(save_file):
        with open(save_file, "w", newline="") as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(["cyhy_db_name", "ip"])
        print(f"CSV save file '{save_file}' created\n")
    else:
        print(f"CSV save file '{save_file}' already exists, proceeding\n")

    # # Calc total number of IPs
    # total_ips = 0
    # for idx, row in cidr_df.iterrows():
    #     num_ips = ipaddress.ip_network(row["network"]).num_addresses
    #     total_ips += num_ips
    # print(f"Total IPs from CIDR: {total_ips}")

    # Calc total number of responsive IPs
    resp_ips_ct = 0
    for cidr_idx, row in cidr_df.iterrows():
        org_abbrv = row["cyhy_db_name"]
        # Convert CIDR to list of individual IPs
        cidr_ips = [str(ip) for ip in ipaddress.IPv4Network(row["network"])]
        # Break CIDR list into chunks
        chunk_size = 50
        ip_chunks = [
            cidr_ips[i : i + chunk_size] for i in range(0, len(cidr_ips), chunk_size)
        ]
        # Feed each chunk through icmplib to test responsiveness
        for chunk_idx, chunk in enumerate(ip_chunks):
            # chunk.extend(["1.1.1.1", "8.8.8.8"]) # testing
            # Log progress
            print(
                f"Working on IP chunk {chunk_idx+1} of {len(ip_chunks)}, overall CIDR {cidr_idx+1} of {len(cidr_df)} (csv_row_idx={cidr_idx})"
            )
            print(f"\t{chunk}")
            # Test IPs
            resp_results = asyncio.run(bulk_ping_ip(chunk))
            print(f"\tResponsive IPs: {resp_results}")
            # Save results
            resp_ips_ct += len(resp_results)
            chunk_list = [{"cyhy_db_name": org_abbrv, "ip": s} for s in resp_results]
            # Append this chunk's responsive IPs to the existing CSV
            if len(chunk_list) > 0:
                print("\tResponsive IPs found, writing to file...")
                with open(save_file, "a", newline="") as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=["cyhy_db_name", "ip"])
                    writer.writerows(chunk_list)
        if cidr_idx == 5:
            break


# # Calculate responsive IPs
# cidr_file_name = ""
# save_file_name = ""
# calc_responsive_ips(cidr_file_name, save_file_name)
