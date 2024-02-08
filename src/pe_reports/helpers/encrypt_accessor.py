"""cisagov/pe-reports: A tool for downloading and encrypting PE reports.

Usage:
  pe-reports REPORT_DATE OUTPUT_DIRECTORY [--ssh-rsa-file=FILENAME]

Options:
  -h --help                         Show this message.
  REPORT_DATE                       Last date of the report period, format YYYY-MM-DD
  OUTPUT_DIRECTORY                  The directory where the encrypted reports are downloaded
  -c --ssh-rsa-file=FILENAME        A YAML file containing the Cyber
                                    Hygiene database credentials.
"""
# Standard Python Libraries
import logging
import os
import traceback

# Third-Party Libraries
from docopt import docopt
import fitz

# cisagov Libraries
from pe_reports.data.config import db_password_key
from pe_reports.data.db_query import connect, get_orgs_pass

# Setup logging
LOGGER = logging.getLogger(__name__)
ACCESSOR_AWS_PROFILE = "cool-dns-sesmanagesuppressionlist-cyber.dhs.gov"
BUCKET_NAME = "cisa-crossfeed-staging-reports"
PASSWORD = db_password_key()


def encrypt(file, password, encrypted_file):
    """Encrypt files."""
    doc = fitz.open(file)
    # Add encryption
    perm = int(
        fitz.PDF_PERM_ACCESSIBILITY
        | fitz.PDF_PERM_PRINT  # permit printing
        | fitz.PDF_PERM_COPY  # permit copying
        | fitz.PDF_PERM_ANNOTATE  # permit annotations
    )
    encrypt_meth = fitz.PDF_ENCRYPT_AES_256
    doc.save(
        encrypted_file,
        encryption=encrypt_meth,  # set the encryption method
        user_pw=password,  # set the user password
        permissions=perm,  # set permissions
        garbage=4,
        deflate=True,
    )


def download_encrypt_reports(report_date, output_dir):
    """Fetch reports from S3 bucket."""
    # download_count = 0
    # total = len(pe_orgs)
    # print(total)

    # Encrypt the reports
    conn = connect()
    pe_org_pass = get_orgs_pass(conn, PASSWORD)
    conn.close()
    encrypted_count = 0
    for org_pass in pe_org_pass:
        print(org_pass)
        password = org_pass[1]
        if password is None:
            LOGGER.error("NO PASSWORD")
            continue
        # Check if file exists before encrypting
        current_file = f"{output_dir}/{org_pass[0]}/Posture_and_Exposure_Report-{org_pass[0]}-{report_date}.pdf"
        current_asm_file = f"{output_dir}/{org_pass[0]}/Posture-and-Exposure-ASM-Summary_{org_pass[0]}_{report_date}.pdf"
        if not os.path.isfile(current_file):
            LOGGER.error("%s report does not exist.", org_pass[0])
            continue
        if not os.path.isfile(current_asm_file):
            LOGGER.error("%s ASM summary does not exist.", org_pass[0])
            continue

        # Create encrypted path
        encrypt_dir = f"{output_dir}/encrypted_reports"
        if not os.path.exists(encrypt_dir):
            os.mkdir(encrypt_dir)
        encrypted_org_path = f"{output_dir}/encrypted_reports/{org_pass[0]}"
        if not os.path.exists(encrypted_org_path):
            os.mkdir(encrypted_org_path)
        encrypted_file = f"{encrypted_org_path}/Posture_and_Exposure_Report-{org_pass[0]}-{report_date}.pdf"
        asm_encrypted_file = f"{encrypted_org_path}/Posture-and-Exposure-ASM-Summary_{org_pass[0]}_{report_date}.pdf"

        # Encrypt the reports
        try:
            encrypt(current_file, password, encrypted_file)
            # Encrypt the summary
            encrypt(current_asm_file, password, asm_encrypted_file)
            encrypted_count += 1
        except Exception as e:
            LOGGER.error(e)
            print(traceback.format_exc())
            LOGGER.error("%s report failed to encrypt.", org_pass[0])
            continue

    LOGGER.info("%d/%d were encrypted.", encrypted_count, 134)


def main():
    """Download reports from S3 and encrypt."""
    # Parse command line arguments
    args = docopt(__doc__)
    report_date = args["REPORT_DATE"]
    output_dir = args["OUTPUT_DIRECTORY"]
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)
    print(report_date)
    print(output_dir)

    # Download the reports from S3
    download_encrypt_reports(report_date, output_dir)


if __name__ == "__main__":
    main()
