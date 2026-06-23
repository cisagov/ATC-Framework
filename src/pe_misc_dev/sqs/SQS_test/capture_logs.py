"""Script to retrieve SQS logs to be viewed locally."""

# Standard Python Libraries
from datetime import datetime, timedelta
import time

# Third-Party Libraries
import boto3


def get_log_events(log_group_name, start_time, end_time):
    """Retrieve log evens from specified group name and time frame."""
    client = boto3.client("logs", region_name="us-east-1")
    next_token = None

    while start_time < end_time:
        kwargs = {"logGroupName": log_group_name, "startTime": start_time}
        if next_token:
            kwargs["nextToken"] = next_token

        try:
            response = client.filter_log_events(**kwargs)
        except Exception as e:
            print(f"Error fetching logs: {e}")
            break

        events = response.get("events", [])

        if events:
            for event in events:
                yield event["message"]

        next_token = response.get("nextToken")
        if not next_token:
            break

        max_timestamp = max(
            (event["timestamp"] for event in events), default=start_time
        )
        start_time = max_timestamp + 1  # Update start time for next iteration


def capture_logs():
    """Capture SQS logs demo."""
    # Set the start time to 24 hours ago
    start_time = (
        int((datetime.now() - timedelta(days=3)).timestamp()) * 1000
    )  # milliseconds since epoch
    end_time = int(time.time() * 1000)  # current time in milliseconds since epoch

    print(f"Start Time (timestamp): {start_time}")
    print(f"End Time (timestamp): {end_time}")
    print(
        f"Start Time (ISO): {datetime.utcfromtimestamp(start_time / 1000).isoformat()}"
    )
    print(f"End Time (ISO): {datetime.utcfromtimestamp(end_time / 1000).isoformat()}")

    log_group_name = "pe-staging-worker"
    log_file_path = "pe_staging_worker_logs_test2.log"

    with open(log_file_path, "a") as log_file:
        for log_event in get_log_events(log_group_name, start_time, end_time):
            log_file.write(log_event + "\n")
