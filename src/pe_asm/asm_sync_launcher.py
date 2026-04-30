"""Script to automatically launch all parallel instances of the ASM Sync process."""

# Standard Python Libraries
from datetime import date
import subprocess  # nosec
import sys
import time


def run_bash_in_screen(screen_name, bash_path):
    """Create a screen and run the specified bash script inside of it."""
    # Create screen session
    create_command = ["screen", "-d", "-m", "-S", screen_name, "/bin/bash"]
    try:
        print("\tCreating screen session...")
        subprocess.run(
            create_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )  # nosec
        print(f'\tScreen "{screen_name}" successfully created')
    except subprocess.CalledProcessError as e:
        print(f"\tError creating screen: {e.stderr.decode()}")
        return
    # Tell the screen session to run the specified bash script
    script_command = f"bash {bash_path}\n"
    send_command = ["screen", "-S", screen_name, "-X", "stuff", script_command]
    try:
        print("\tSending bash script to screen...")
        subprocess.run(
            send_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )  # nosec
        print(f'\tBash script sent to screen "{screen_name}" successfully')
    except subprocess.CalledProcessError as e:
        print(f"\tError sending bash script to screen session: {e.stderr.decode()}")


def launch_asm_sync_parts(num_parts):
    """Launch each of the parallel instances of the ASM Sync process using the scripts in the bash_scripts folder."""
    print(f"Launching {num_parts} ASM Sync script instances to run in parallel...")
    for i in range(1, num_parts + 1):
        curr_date = date.today().strftime("%Y-%m-%d")
        screen_name = f"asmsync_pt{i}_{curr_date}"
        bash_path = f"./bash_scripts/asm_sync_pt{i}.sh"
        print(f"Launching ASM Sync Instance {i}")
        print(f"\tScreen Name: {screen_name}")
        print(f"\tBash Script: {bash_path}")
        run_bash_in_screen(screen_name, bash_path)
        time.sleep(30)
    print(
        "All ASM Sync script instances launched, monitor central logging file for progress"
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 asm_sync_launcher.py <number_of_parts>")
        sys.exit(1)
    num_parts = int(sys.argv[1])
    launch_asm_sync_parts(num_parts)
