"""Script to consolidate multi-part execution time logs into a single file."""

from datetime import datetime
import os
import pandas as pd

def consolidate_exe_logs(source_list, date_list):
    """Consolidate exe logs for the specified data sources and dates."""
    # Iterate over each data source
    for source in source_list:
        # Consolidate exe logs for this data source and the specified dates
        print(f"Consolidating {source} exe. time logs for the following dates: {date_list}")
        # Get folder holding the exe log files
        exe_log_folder = os.path.dirname(os.path.abspath(__file__)) + f"/exe_time_logs/{source}_logs/"
        exe_log_files = os.listdir(exe_log_folder)
        exe_log_files.sort()
        # Get all exe log files in that folder for the specified dates 
        date_list = sorted(date_list, key=lambda date_str: datetime.strptime(date_str, "%Y-%m-%d"))
        target_log_files = []
        for date in date_list:
            file_substr = f"{source}_{date}"
            file_matches = [item for item in exe_log_files if file_substr in item]
            target_log_files.extend(file_matches)
        # Combine all target log files together
        print("Reading exe time data from the following files:")
        full_list = []
        for target_file in target_log_files:
            file_path = exe_log_folder + target_file
            current_df = pd.read_excel(file_path, engine='openpyxl')
            current_df.columns = ["timestamp", "org_abbrv", "exe_time"]
            current_list = current_df.to_dict(orient="records")
            full_list.extend(current_list)
            print(f"\t{target_file} - {len(current_list)} records")
        full_df = pd.DataFrame(full_list)
        # Drop duplicates, keep the longer exe time
        pre_dedupe_len = len(full_df)
        full_df.sort_values(by="exe_time", ascending=False, inplace=True)
        full_df.drop_duplicates(subset=["org_abbrv"], keep="first", inplace=True)
        full_df.sort_values(by="org_abbrv", inplace=True)
        full_df.reset_index(drop=True, inplace=True)
        post_dedupe_len = len(full_df)
        print(f"{pre_dedupe_len} exe time records found in total, {post_dedupe_len} records after dedupe")
        # Check to ensure 142 orgs
        if len(full_df) != 142:
            print(f"ERROR: {len(full_df)} orgs found instead of expected 142, aborting\n")
            return None
        # Save to file
        save_file_date = date_list[0]
        save_file = exe_log_folder + f"{source}_exe_times_{save_file_date}.xlsx"
        full_df.to_excel(save_file, engine="openpyxl", index=False)
        print(f"Saved consolidated exe time results to: {save_file}\n")
        
def group_orgs_by_exe_times(source, exe_time_file, num_groups, sort_method, num_api_keys):
    """Generate optimally distributed groups of organizations based on exe time logs."""
    # Load in exe time file
    exe_df = pd.read_excel(exe_time_file, engine="openpyxl", index_col=False)
    final_output = [[] for x in range(num_groups)]
    # Initial pass to fill groups with their first org
    for idx in range(0,num_groups):
        curr_org_name = exe_df.loc[idx]["org_abbrv"]
        curr_exe_time = exe_df.loc[idx]["exe_time"]
        final_output[idx].append({"org_abbrv": curr_org_name, "exe_time": curr_exe_time})
    # Iterate through remaining orgs and their exe times
    for row_idx, row in exe_df.iterrows():
        # skip past inital group orgs
        if row_idx in range(0,num_groups):
            continue
        # Determine which group currently has the smallest total exe time
        group_sums = []
        for group_idx, group in enumerate(final_output):
            group_total = 0
            for org in group:
                group_total += org.get("exe_time")
            group_sums.append(group_total)
        curr_min_group_num = group_sums.index(min(group_sums))
        # Add the current org to the current smallest group
        final_output[curr_min_group_num].append({"org_abbrv": row["org_abbrv"], "exe_time": row["exe_time"]})
    # Sort orgs within groups based on specified method
    if sort_method == "alphabetical":
        # alphabetize orgs 
        final_output = [sorted(item, key=lambda d: d["org_abbrv"]) for item in final_output]
    elif sort_method == "fastest_first":
        # Sort so that fastest executing orgs are put first
        final_output = [sorted(item, key=lambda d: d["exe_time"]) for item in final_output]
    else:
        print("ERROR: unrecognized sorting method \"{sort_style}\", aborting")
        return None
    # Output results
    for group_idx, group in enumerate(final_output):
        # Calculate list of orgs and total exe time 
        group_total = 0
        group_org_list = ""
        for org in group:
            group_total += org.get("exe_time")
            curr_org_name = org.get("org_abbrv")
            group_org_list += f"{curr_org_name},"
        group_org_list = group_org_list[:-1]
        group_total = round(group_total, 2)
        # Print results w/ full CLI command depending on source
        if source == "asm_sync":
            target_api_key = group_idx % num_api_keys
            print(f"> Group #{group_idx+1} ({len(group)} orgs, total est. exe. time: {group_total}s) - Use the following CLI command:")
            print(f"pe-asm-sync asm-seq --shodan_key={target_api_key} --orgs={group_org_list}\n")
        elif source == "flare_creds":
            target_api_key = group_idx % num_api_keys + 1
            print(f"> Group #{group_idx+1} ({len(group)} orgs, total est. exe. time: {group_total}s) - Use the following CLI command:")
            print(f"pe-source flare_creds --flare_key={target_api_key} --orgs={group_org_list}\n")
        elif source == "flare_events":
            target_api_key = group_idx % num_api_keys + 1
            print(f"> Group #{group_idx+1} ({len(group)} orgs, total est. exe. time: {group_total}s) - Use the following CLI command:")
            print(f"pe-source flare_events --flare_key={target_api_key} --orgs={group_org_list}\n")
        elif source == "intelx":
            print(f"> Group #{group_idx+1} ({len(group)} orgs, total est. exe. time: {group_total}s) - Use the following CLI command:")
            print(f"pe-source intelx --orgs={group_org_list}\n")

        

# # -- Consolidating Exe. Time Logs into a Single File --
# # Specify which data source you'd like to consolidate exe logs for
# # Options: asm_sync, flare_creds, flare_events, intelx
# sources = [
#     "asm_sync"
# ]
# # Specify the dates of the exe logs you'd like to consolidate
# dates = [
#     "2026-01-01",
#     "2026-01-02",
# ]
# # Begin consolidation script
# consolidate_exe_logs(sources, dates)


# # -- Use Consolidated Exe. Time Log File to Generate Org Groups --
# # Specify what script these exe times are for
# # Options: asm_sync, flare_creds, flare_events, intelx
# source = "asm_sync"
# # Specify consolidated exe time log file
# exe_log_file = f"./exe_time_logs/{source}_logs/{source}_exe_times_2026-01-01.xlsx"
# # Specify desired number of groups
# num_org_groups = 6
# # Specify how orgs should be sorted within groups
# # Options: alphabetical, fastest_first
# sort_method = "fastest_first"
# # Specify number of available API keys
# num_api_keys = 4
# # Begin org grouping script
# group_orgs_by_exe_times(source, exe_log_file, num_org_groups, sort_method, num_api_keys)