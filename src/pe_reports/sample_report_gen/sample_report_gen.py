"""Script to generate a sample PE report using a fake organization and data."""

# Imports
import datetime
import logging
import time

# Setup Logging
logging.basicConfig(
    filename="./sample_report_logs/sample_report_logfile.log",
    filemode="w",
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%m/%d/%Y %I:%M:%S",
    level="INFO",
)
main_log = logging.getLogger(__name__)

# Import database connection function
from pe_reports.data.db_query import connect
 
# Import Queries
from sample_report_queries import (
    # Placeholder data creation
    create_sample_org,
    create_sample_rootdomain,
    create_sample_subdomain,
    create_sample_cidr,
    create_sample_ip,
    create_sample_cred_breach,
    create_sample_cred_exp,
    create_sample_domain_alert,
    create_sample_domain_permu,
    create_sample_shodan_vuln,
    create_sample_shodan_asset,
    create_sample_mention,
    create_sample_alert,
    # Placeholder data deletion
    get_delete_info,
    delete_sample_org,
    delete_sample_rootdomain,
    delete_sample_subdomain,
    delete_sample_cidr,
    delete_sample_ip,
    delete_sample_cred_breach,
    delete_sample_cred_exp,
    delete_sample_domain_alert,
    delete_sample_domain_permu,
    delete_sample_shodan_vuln,
    delete_sample_shodan_asset,
    delete_sample_mention,
    delete_sample_alert,
)


def create_sample_report_data(curr_date_str):
    """Create all the fake placeholder data needed to generate a sample PE Report."""
    # Convert date string into date obj
    curr_date = datetime.datetime.strptime(curr_date_str, "%Y-%m-%d").date()
    main_log.info(f"=== Sample P&E Report: Placeholder Data Creation Starting ===")
    create_start_time = time.time()
    conn = connect()
    # Create sample organization
    sample_org_df = create_sample_org(conn, curr_date)
    sample_org_id = sample_org_df["organizations_uid"].values[0]
    # Create sample rootdomains, subdomains, and IPs 
    sample_root_df = create_sample_rootdomain(conn, sample_org_id)
    sample_root_id = sample_root_df["root_domain_uid"].values[0]
    sample_sub_df = create_sample_subdomain(conn, curr_date, sample_root_id)
    sample_sub_ids = sample_sub_df["sub_domain_uid"].tolist()
    sample_cidr_df = create_sample_cidr(conn, curr_date, sample_org_id)
    sample_cidr_id = sample_cidr_df["cidr_uid"].values[0]
    sample_ip_df = create_sample_ip(conn, curr_date, sample_org_id, sample_cidr_id)
    # Create sample cred breaches & exposures
    sample_cred_breach_df = create_sample_cred_breach(conn, curr_date)
    sample_cred_exp_df = create_sample_cred_exp(conn, curr_date, sample_org_id, sample_cred_breach_df)
    # Create sample domain alerts & suspected domains
    sample_domain_alert_df = create_sample_domain_alert(conn, curr_date, sample_sub_ids, sample_org_id)
    sample_domain_permu_df = create_sample_domain_permu(conn, curr_date, sample_org_id, sample_sub_ids)
    # Create insecure protocol & vulnerabilities
    sample_shodan_asset_df = create_sample_shodan_asset(conn, curr_date, sample_org_df, sample_ip_df)
    sample_shodan_vuln_df = create_sample_shodan_vuln(conn, curr_date, sample_org_df, sample_ip_df)
    # Create darkweb mentions/alerts
    sample_mention_df = create_sample_mention(conn, curr_date, sample_org_id)
    sample_alert_df = create_sample_alert(conn, curr_date, sample_org_id)
    conn.close()
    create_end_time = time.time()
    main_log.info(f"Execution time for placeholder data generation: {str(datetime.timedelta(seconds=(create_end_time - create_start_time)))} (H:M:S)")
    main_log.info(f"=== Sample P&E Report: Placeholder Data Creation Complete ===")


def delete_sample_report_data():
    """Delete all the fake placeholder data needed to generate a sample PE Report."""
    main_log.info(f"=== Sample P&E Report: Placeholder Data Deletion Starting ===")
    delete_start_time = time.time()
    conn = connect()
    # Retrieve info needed for deletion
    [org_id, root_id, cidr_id] = get_delete_info(conn)
    # Delete darkweb mentions/alerts
    delete_sample_alert(conn, org_id)
    delete_sample_mention(conn, org_id)
    # Delete insecure protocol & vulnerabilities
    delete_sample_shodan_vuln(conn, org_id)
    delete_sample_shodan_asset(conn, org_id)
    # Delete domain alerts & suspected domains
    delete_sample_domain_permu(conn, org_id)
    delete_sample_domain_alert(conn, org_id)
    # Delete sample cred breaches & exposures
    delete_sample_cred_exp(conn, org_id)
    delete_sample_cred_breach(conn)
    # Delete sample CIDRs/IPs
    delete_sample_ip(conn, cidr_id)
    delete_sample_cidr(conn, org_id)
    # Delete sample root/sub domains
    delete_sample_subdomain(conn, root_id)
    delete_sample_rootdomain(conn, org_id)
    # Delete sample organization
    # delete_sample_org(conn) # May take a long time
    conn.close()
    delete_end_time = time.time()
    main_log.info(f"Execution time for placeholder data deletion: {str(datetime.timedelta(seconds=(delete_end_time - delete_start_time)))} (H:M:S)")
    main_log.info(f"=== Sample P&E Report: Placeholder Data Deletion Complete ===")


def gen_sample_report(curr_date):
    main_log.info("")
    main_start_time = time.time()
    main_log.info(f"=== *** Sample P&E Report Generation Starting *** ===")
    # Create all placeholder data needed for sample PE Report
    create_sample_report_data(curr_date)
    # Generate sample report...
    
    # Delete all placeholder data needed for sample PE Report
    delete_sample_report_data()
    # Finish up and log results
    main_end_time = time.time()
    main_log.info(f"Overall execution time for sample P&E Report generation: {str(datetime.timedelta(seconds=(main_end_time - main_start_time)))} (H:M:S)")
    main_log.info(f"=== *** Sample P&E Report Generation Complete *** ===")




# --- Testing ---
# gen_sample_report("2024-11-15")
# Create smaple report data
# create_sample_report_data("2024-11-15")
# Delete sample report data
# delete_sample_report_data()