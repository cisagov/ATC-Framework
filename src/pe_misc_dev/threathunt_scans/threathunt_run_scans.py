"""Script to specify what Threat Hunt related scans to run."""
# Standard Python Libraries
import datetime
import logging
import os
import shutil
import time

# Third-Party Libraries
from threathunt_c6g_scans import keywords, keywords_hist_data, top_cves
from threathunt_mailer import send_email
from threathunt_pdf_generator import gen_line_chart, gen_pdf

# Setup Logging
logging.basicConfig(
    filename="./logging/threathunt_scans_log.log",
    filemode="a",
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%m/%d/%Y %I:%M:%S",
    level="INFO",
)
main_log = logging.getLogger(__name__)


def run_scans(scan_list, recipient):
    """Run the specified Threat Hunt scans."""
    main_log.info("=== *** Threat Hunt Scans Starting *** ===")
    main_log.info(f"Running these Threat Hunt Scans: {scan_list}")
    main_start_time = time.time()
    curr_date = datetime.datetime.today().strftime("%Y-%m-%d")
    scan_dict = {}

    # Create results folder for today's scans
    results_folder = f"./output_data/threathunt_scans_{curr_date}"
    if not os.path.exists(results_folder):
        os.makedirs(results_folder)
    # Create folder for today's figures/graphs
    if not os.path.exists(results_folder + "/figures"):
        os.makedirs(results_folder + "/figures")

    # Run scans & generate CSV files
    if "top_cves" in scan_list:
        main_log.info(">>> Threat Hunt Top CVEs scan starting")
        # Run Top CVEs scan
        top_cves_df = top_cves()
        # Save top cves data to csv file
        top_cves_csv_file = (
            f"{results_folder}/cybersixgill_top_cve_data_{curr_date}.csv.zip"
        )
        top_cves_df.to_csv(
            top_cves_csv_file, compression={"method": "zip", "compresslevel": 9}
        )
        scan_dict.update(top_cves=top_cves_csv_file)
        scan_dict["Top CVEs"] = scan_dict.pop("top_cves")
        main_log.info(">>> Threat Hunt Top CVEs scan complete")
    if "keywords" in scan_list:
        main_log.info(">>> Threat Hunt Keyword scan starting")
        # Run keywords scan
        keywords_df = keywords()
        # Save keywords data to csv file
        keywords_csv_file = (
            f"{results_folder}/cybersixgill_keywords_data_{curr_date}.csv.zip"
        )
        keywords_df.to_csv(
            keywords_csv_file, compression={"method": "zip", "compresslevel": 9}
        )
        scan_dict.update(Keywords=keywords_csv_file)
        # Generate line chart for PDF
        keyword_hist_df = keywords_hist_data()
        gen_line_chart(
            results_folder,  # save file
            keyword_hist_df,  # dataframe
            "Scan Date",  # x_label
            "Total Query Results",  # y_label
            16.51,  # width
            10,  # height
        )
        main_log.info(">>> Threat Hunt Keyword scan complete")
    if "test_scan" in scan_list:
        # Example of how to add another scan
        scan_dict.update(test_scan="./output_data/test_scan_data.csv")

    # Check that at least one scan ran
    if scan_dict:
        # Generate summary pdf
        gen_pdf(scan_dict, curr_date)
        scan_dict.update(pdf_report=f"{results_folder}/scan_results_{curr_date}.pdf")
        # Mail out results
        send_email(scan_dict, recipient)
    else:
        # If no scans ran, abort
        main_log.error("No scans have run, no email will be sent")

    # Delete old files to save space
    main_log.info("Removing old results to save space")
    output_dir = os.fsencode("./output_data/")
    for folder in os.listdir(output_dir):
        folder_name = os.fsdecode(folder)
        # Check if folder is an output data folder
        is_output_folder = True
        try:
            is_output_folder = bool(
                datetime.datetime.strptime(folder_name, "threathunt_scans_%Y-%m-%d")
            )
        except ValueError:
            is_output_folder = False
        # If it is, parse the date of the output data
        if is_output_folder:
            folder_date = datetime.datetime.strptime(
                folder_name, "threathunt_scans_%Y-%m-%d"
            ).date()
            past_7_days = (
                datetime.datetime.today() - datetime.timedelta(days=7)
            ).date()
            # *** If not within past 7 days and not the 15th of a month, delete
            if folder_date <= past_7_days and folder_date.day != 15:
                shutil.rmtree(f"./output_data/{folder_name}")

    # Log final stats
    main_end_time = time.time()
    main_log.info(
        f"Execution time for Threat Hunt Scans: {str(datetime.timedelta(seconds=(main_end_time - main_start_time)))} (H:M:S)"
    )
    main_log.info("=== *** Threat Hunt Scans Complete *** ===")


# # --- Execute Threat Hunt Scans ---
# # Specify which Threat Hunt scans to run
# scan_list = [
#     "top_cves",
#     "keywords",
#     # "test_scan", # Test scan example
# ]
# recipient = ""
# run_scans(scan_list, recipient)
