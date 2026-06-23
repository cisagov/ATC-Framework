"""Script to automatically mail data to Threat Hunt."""
# Standard Python Libraries
import datetime
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import logging
import os

# Third-Party Libraries
import boto3
from botocore.exceptions import ClientError

# Setup logging
main_log = logging.getLogger(__name__)

# Mailer ARN
mailer_arn = ""


def send_email(scan_dict, recipient):
    """Send email/data file to specified recipient."""
    # Assume role to use mailer
    sts_client = boto3.client("sts")
    assumed_role_object = sts_client.assume_role(
        RoleArn=mailer_arn, RoleSessionName="AssumeRoleSession1"
    )
    credentials = assumed_role_object["Credentials"]
    ses_client = boto3.client(
        "ses",
        region_name="us-east-1",
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )
    # Compose email
    curr_date = datetime.datetime.today().strftime("%Y-%m-%d")
    scan_list = scan_dict.keys()
    scan_list_text = ""
    scan_list_html = "<ul>"
    for scan in scan_list:
        if scan != "pdf_report":
            scan_list_text += f'\n\t- "{scan}" Scan - The raw data file for this scan is: {os.path.basename(scan_dict.get(scan))}'
            scan_list_html += f"<li><b>&quot;{scan}&quot;</b> Scan - The raw data file for this scan is: <b>{os.path.basename(scan_dict.get(scan))}</b></li>"
    scan_list_html += "</ul>"
    sender = "reports@cyber.dhs.gov"
    subject = f"P&E Automated Scan Results for {curr_date}"
    # Text version of email body
    body_text = f"""
        Greetings,

        The P&E scans listed below have been run. A PDF report containing the consolidated results
        of all the scans has been attached to this email. Additionally, the raw data files for each individual
        scan have also been included:
        {scan_list_text}

        This is an automated email. Please contact <email> if you have any questions or concerns!

        Thank you,
        The Posture & Exposure Team (CISA CyberHygiene)
    """
    # HTML version of email body
    body_html = f"""<html>
        <head></head>
        <body>
        <p>
            Greetings,<br/>
            <br/>
            The P&E scans listed below have been run. A PDF report containing the consolidated results
            of all the scans has been attached to this email. Additionally, the raw data files for each individual
            scan have also been included:<br/>
            {scan_list_html}<br/>
            <b>This is an automated email.</b> Please contact <email>
            if you have any questions or concerns!<br/>
            <br/>
            Thank you,<br/>
            The Posture & Exposure Team (CISA CyberHygiene)
        </p>
        </body>
        </html>
        """
    charset = "UTF-8"
    # Create multipart/mixed parent container
    msg = MIMEMultipart("mixed")
    # Add subject/from/to lines
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient
    # Create multipart/alternative child container
    msg_body = MIMEMultipart("alternative")
    # Encode text/html content
    textpart = MIMEText(body_text.encode(charset), "plain", charset)
    htmlpart = MIMEText(body_html.encode(charset), "html", charset)
    msg_body.attach(textpart)
    msg_body.attach(htmlpart)
    msg.attach(msg_body)
    # Add all attachments
    for key, value in scan_dict.items():
        att = MIMEApplication(open(value, "rb").read())
        att.add_header(
            "Content-Disposition", "attachment", filename=os.path.basename(value)
        )
        msg.attach(att)
    # Attempt to send email
    try:
        main_log.info(f"Attempting to send email to: {recipient}")
        resp = ses_client.send_raw_email(
            Source=sender,
            Destinations=[recipient],
            RawMessage={
                "Data": msg.as_string(),
            },
        )
    except ClientError as e:
        main_log.error("Error: Failed to send automated email")
        main_log.error(e.resp["Error"]["Message"])
    else:
        mssg_id = resp["MessageId"]
        main_log.info(f"Automated email successfully sent! Message ID: {mssg_id}")
