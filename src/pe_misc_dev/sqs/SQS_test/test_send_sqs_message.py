"""Script to send messages to SQS queue."""

# Standard Python Libraries
import time

# Third-Party Libraries
import boto3


def send_sqs_message():
    """Test sending SQS message to queue."""
    # Create an SQS client
    sqs = boto3.client("sqs", region_name="us-east-1")

    # Specify the URL of your SQS queue
    queue_url = ""  # Replace with your actual SQS queue URL

    organizations = [""]
    print(len(organizations))

    for org in organizations:
        # Define the message you want to send
        message_body = '{"scriptType": "dnstwist", "org":"' + org + '"}'
        print(message_body)

        # Send the message to the SQS queue
        response = sqs.send_message(QueueUrl=queue_url, MessageBody=message_body)

        # Print the message ID to confirm it was sent
        print(f'Message sent with MessageId: {response["MessageId"]}')
        time.sleep(1)
