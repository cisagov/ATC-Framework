"""Script to queue up SQS messages and launch fargate containers for P&E SQS scans."""

# Standard Python Libraries
import json
import time

# Third-Party Libraries
import boto3

scan_types = [
    # {"scan": "xpanse", "count": 5},
    # {"scan": "dnstwist", "count": 2},
    # {"scan": "cybersixgill", "count": 3},
    {"scan": "intelx", "count": 10},
    {"scan": "shodan", "count": 3, "apiKeys": ""},
    # {"scan": "asmSync", "count": 2}, # max 3 containers?
    # {"scan": "qualys". "count": 1},
]


# Load organization lists from JSON files
def load_organizations(filename):
    """Load the specified org list json file."""
    with open(filename) as file:
        return json.load(file)


def launch_sqs_scans(scan_types):
    """Launch desired sqs scans."""
    # pe_orgs = load_organizations('/var/www/SQS_test/pe_orgs.json')
    pe_orgs = load_organizations(
        "/var/www/SQS_test/pe_orgs_all_report_on.json"
    )  # All 142 report_on=true orgs (PE Reports)
    # pe_orgs = load_organizations('/var/www/SQS_test/sqs_asm_sync_test_orgs.json') # For SQS ASM Sync testing
    xpanse_orgs = load_organizations("/var/www/SQS_test/xpanse_orgs.json")

    # Check for any running tasks

    # ecs_client = boto3.client('ecs', region_name="us-east-1")

    # task_arns = ecs_client.list_tasks(
    #     cluster="pe-staging-worker",
    #     desiredStatus='RUNNING'  # Filter to show only running tasks
    # )['taskArns']

    # if not task_arns:
    #     print("No running tasks found.")
    # else:
    #     # Step 2: Describe the tasks to get detailed information
    #     tasks = ecs_client.describe_tasks(
    #         cluster="pe-staging-worker",
    #         tasks=task_arns
    #     )['tasks']

    #     # Print detailed information about each running task
    #     for task in tasks:
    #         print(f"Task ARN: {task['taskArn']}")
    #         print(f"Task Definition: {task['taskDefinitionArn']}")
    #         print(f"Last Status: {task['lastStatus']}")
    #         print(f"Desired Status: {task['desiredStatus']}")
    #         print(f"Task Group: {task['group']}")
    #         print(f"Started At: {task['startedAt']}")
    #         print(f"Container Instance ARN: {task['containerInstanceArn']}")
    #         print(f"Containers: {task['containers']}")
    #         print("-" * 40)

    # Create an SQS client
    sqs = boto3.client("sqs", region_name="us-east-1")

    for scan in scan_types:
        queue_url = f'{scan["scan"]}'

        if scan["scan"] == "xpanse":
            organizations = xpanse_orgs
        else:
            organizations = pe_orgs

        print(len(organizations))

        for org in organizations:
            # Define the message you want to send
            message_body = '{"org":"' + org + '"}'

            # Send the message to the SQS queue
            response = sqs.send_message(QueueUrl=queue_url, MessageBody=message_body)

            # Print the message ID to confirm it was sent
            print(f'Message sent with MessageId: {response["MessageId"]}')
            time.sleep(1)

    # Create the concurrent containers that read from SQS
    for scan in scan_types:
        lambda_client = boto3.client("lambda", region_name="us-east-1")
        if scan["scan"] == "asm":
            scan["scan"] = "asmSync"

        if scan["scan"] == "shodan":
            response = lambda_client.invoke(
                FunctionName="crossfeed-staging-cd-scanExecution",
                Payload='{"desiredCount": '
                + str(scan["count"])
                + ', "scanType": "'
                + str(scan["scan"])
                + '", "apiKeyList": "'
                + str(scan["apiKeys"])
                + '"}',
            )
        else:
            response = lambda_client.invoke(
                FunctionName="crossfeed-staging-cd-scanExecution",
                Payload='{"desiredCount": '
                + str(scan["count"])
                + ', "scanType": "'
                + str(scan["scan"])
                + '"}',
            )

        print(response["StatusCode"])
