"""Script for running SQS scans specifically for P&E.

Usage:
    pe_sqs.py [--scans=SCANS] [--orgs_file=ORGS_FILE]

Options:
    -h --help                   Show this message.
    -s --scans=SCANS            A comma separated list of the names of the SQS scripts you'd like
                                to run.
    -o --orgs_file=ORGS_FILE    The name of the JSON file to get the list of organizations from.
"""

# Standard Python Libraries
import json
import sys
import time

# Third-Party Libraries
# Imports
import boto3
import docopt

# All available SQS scans:
scan_dict = {
    "asm_sync": {  # WIP
        "scan": "asmSync",
        "count": 2,
        "apiKeys": "",
    },
    "csg_alerts": {  # WIP
        "scan": "cybersixgill-alerts",
        "count": 4,
    },
    "csg_creds": {  # WIP
        "scan": "cybersixgill-credentials",
        "count": 4,
    },
    "csg_mentions": {  # WIP
        "scan": "cybersixgill-mentions",
        "count": 4,
    },
    "csg_topcves": {  # WIP
        "scan": "cybersixgill-topcves",
        "count": 1,
    },
    "dnsmonitor": {  # WIP
        "scan": "dnsmonitor",
        "count": 1,
    },
    "dnstwist": {"scan": "dnstwist", "count": 142},  # Functioning
    "intelx": {  # Functioning
        "scan": "intelx",
        "count": 10,
    },
    "shodan": {"scan": "shodan", "count": 3, "apiKeys": ""},  # Functioning
    # V --- Test Versions of Scans: --- V
    "asm_sync_test": {
        "scan": "asmSync",
        "count": 1,
        "apiKeys": "",
    },
    "csg_alerts_test": {
        "scan": "cybersixgill-alerts",
        "count": 1,
    },
    "csg_creds_test": {
        "scan": "cybersixgill-credentials",
        "count": 1,
    },
    "csg_mentions_test": {
        "scan": "cybersixgill-mentions",
        "count": 1,
    },
    "csg_topcves_test": {
        "scan": "cybersixgill-topcves",
        "count": 1,
    },
    "dnsmonitor_test": {
        "scan": "dnsmonitor",
        "count": 1,
    },
    "dnstwist_test": {
        "scan": "dnstwist",
        "count": 1,
    },
    "intelx_test": {
        "scan": "intelx",
        "count": 1,
    },
    "shodan_test": {"scan": "shodan", "count": 1, "apiKeys": ""},
}


def load_org_list(filename):
    """Load organization list from JSON file."""
    with open(filename) as file:
        return json.load(file)


def queue_messages(sqs_client, scan_list, org_list):
    """Queue up messags for the specified SQS scripts."""
    # For each scan, queue up messages
    for scan in scan_list:
        scan_name = scan.get("scan")
        print(
            f"Queuing up messages for {scan_name} script running on {len(org_list)} organization(s)"
        )
        queue_url = f'{scan["scan"]}'
        # For each org, send a message
        for org in org_list:
            # Define the message you want to send
            message_body = '{"org":"' + org + '"}'
            # Send the message to the SQS queue
            response = sqs_client.send_message(
                QueueUrl=queue_url, MessageBody=message_body
            )
            # Print the message ID to confirm it was sent
            print(
                f'Message sent to {scan_name} queue for {org}, MessageId: {response["MessageId"]}'
            )
            time.sleep(1)


def create_containers(scan_list):
    """Create containers for the specified SQS scripts."""
    # For each scan, create the specified number of containers
    for scan in scan_list:
        scan_name = scan.get("scan")
        scan_num_cont = scan.get("count")
        print(f"Creating {scan_num_cont} containers for {scan_name} script")
        lambda_client = boto3.client("lambda", region_name="us-east-1")
        # Container creation varies depending on the scan
        if scan["scan"] in ["shodan", "asmSync"]:
            # Both Shodan and ASM Sync scripts need Shodan API keys
            response = lambda_client.invoke(
                FunctionName="crossfeed-staging-scanExecution",
                Payload='{"desiredCount": '
                + str(scan["count"])
                + ', "scanType": "'
                + scan["scan"]
                + '", "apiKeyList": "'
                + scan["apiKeys"]
                + '"}',
            )
        else:
            response = lambda_client.invoke(
                FunctionName="crossfeed-staging-scanExecution",
                Payload='{"desiredCount": '
                + str(scan["count"])
                + ', "scanType": "'
                + scan["scan"]
                + '"}',
            )
        # Log response for container creation
        resp_status_code = response["StatusCode"]
        print(
            f"Containers have been created for {scan_name} script (code: {resp_status_code})"
        )


def run_pe_sqs_scripts(scan_names, org_list_file):
    """Run the specified P&E SQS scripts."""
    print(f"{len(scan_names)} SQS script(s) requested: {scan_names}")
    print(f"Running on organization list from the file: {org_list_file}")

    # Get details for the requested scans
    scan_list = [scan_dict[scan] for scan in scan_names if scan in scan_dict]

    # Load desired list of organizations
    org_list = load_org_list(f"/var/www/SQS_pe/org_lists/{org_list_file}")

    # Create an SQS client
    sqs = boto3.client("sqs", region_name="us-east-1")

    # Populate queue with messages
    queue_messages(sqs, scan_list, org_list)

    # Create Fargate containers
    create_containers(scan_list)

    print("Queues and containers have been created for all requested SQS scripts")


def main():
    """Set up and call the run_pe_sqs_scripts() function."""
    args: dict[str, str] = docopt.docopt(__doc__)
    args["--scans"] = args.get("--scans").split(",")

    # Validate arguments
    if not set(args.get("--scans")) <= set(scan_dict.keys()):
        print(f"ERROR: Possible values for --scans are: {list(scan_dict.keys())}")
        sys.exit(1)
    if args["--orgs_file"][-5:] != ".json":
        print("ERROR: organization list file must be .json")
        sys.exit(1)

    # Run specified SQS scripts
    run_pe_sqs_scripts(
        args["--scans"],
        args["--orgs_file"],
    )


if __name__ == "__main__":
    main()
