import os
import subprocess
import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

slack_webhook = os.getenv('slack_webhook')
poc_file_name = 'abhiunix_poc.html'

def send_slack_notification(message):
    """
    Sends a notification to Slack using the configured webhook.
    """
    payload = {"text": message}
    try:
        response = requests.post(slack_webhook, json=payload)
        if response.status_code != 200:
            print(f"Failed to send message to Slack: {response.status_code}, {response.text}")
        else:
            return
    except requests.exceptions.RequestException as e:
        print(f"Error sending message to Slack: {e}")

def create_poc_file():
    """
    Creates the PoC file if it does not already exist.
    """
    if not os.path.exists(poc_file_name):
        with open(poc_file_name, 'w') as f:
            f.write("This file was created for proof of concept by Security Team. If you found this file then please contact https://x.com/abhiunix")
        print(f"{poc_file_name} created successfully.")
    else:
        print(f"{poc_file_name} already exists.")

def checking_write_access(line):
    """
    Checks for WRITE access on the specified S3 bucket.
    """
    print(f"Checking for WRITE Access on {line}")
    
    commands = [
        ['aws', 's3', 'cp', poc_file_name, f's3://{line}/security_test/', '--no-sign-request'],
        ['aws', 's3', 'cp', poc_file_name, f's3://{line}/'],
        ['aws', 's3', 'cp', poc_file_name, f's3://{line}', '--profile=test'],
        ['aws', 's3', 'cp', poc_file_name, f's3://{line}', '--profile=labs']
    ]
    cases = ['Case-1', 'Case-2', 'Case-3', 'Case-4']

    for i, command in enumerate(commands):
        result = subprocess.run(command, stderr=subprocess.PIPE, text=True)
        temp_value = result.stderr
        
        if 'upload:' in temp_value:
            alert_message = f"The {line} bucket has public WRITE/DELETE access. Potential data exposure risk. Please review your bucket policy again. Contact Security Team for any support."
            case_number = f"The {line} bucket has public WRITE/DELETE access. Potential data exposure risk. Please review you bucket policy again. Check out {cases[i]}."
            print(f"\033[31m{case_number}\033[m")            
            send_slack_notification(alert_message)
            with open('ohoVulnerable.txt', 'a') as vuln_file:
                vuln_file.write(line + '\n')
        else:
            print(f"Manual Test-{i+1} Pass")

def checking_read_access(line):
    """
    Checks for READ access on the specified S3 bucket.
    """
    print(f"\nChecking for READ Access on {line}")
    
    commands = [
        ['aws', 's3', 'ls', f's3://{line}', '--no-sign-request'],
        ['aws', 's3', 'ls', f's3://{line}'],
        ['aws', 's3', 'ls', f's3://{line}', '--profile=test'],
        ['aws', 's3', 'ls', f's3://{line}', '--profile=labs']
    ]
    cases = ['Case-5', 'Case-6', 'Case-7', 'Case-8']

    for i, command in enumerate(commands):
        result = subprocess.run(command, stderr=subprocess.PIPE, text=True)
        temp_value = result.stderr
        
        if any(keyword in temp_value for keyword in ["AccessDenied", "NoSuchBucket", "InvalidAccessKeyId", "IllegalLocationConstraintException", "could not be found"]):
            print(f"Manual Test-{i+5} Pass")
        else:
            alert_message = f"The {line} bucket has public READ access. Potential data exposure risk. Please review your bucket policy again. Contact Security Team for any support."
            case_number = f"The {line} bucket has public READ access. Potential data exposure risk. Please review you bucket policy again. Check out {cases[i]}."
            print(f"\033[31m{case_number}\033[m")
            send_slack_notification(alert_message)
            with open('ohoVulnerable.txt', 'a') as vuln_file:
                vuln_file.write(line + '\n')

def manual_scans():
    """
    Performs manual scans for S3 buckets listed in alls3.txt.
    """
    create_poc_file()
    
    with open('alls3.txt', 'r') as file:
        for line in file:
            line = line.strip()
            print(f"\nChecking \033[31m{line}\033[m\n")
            checking_write_access(line)
            checking_read_access(line)
# ------------------------------------------------------------------- Automated -----------------------------------------------------------------
def scanning_with_s3scanner():
    print("Scanning with s3scanner, it can take time. Sit back and relax.")

    with open('alls3.txt', 'r') as file:
        for line in file:
            line = line.strip()
            print(f"Scanning with s3scanner on \033[31m{line}\033[m")

            # Run s3scanner and capture the output
            result = subprocess.run(['s3scanner', '-bucket', line], capture_output=True, text=True)
            temp_value = result.stdout
            
            # Check if any of the vulnerabilities are present
            if any(keyword.lower() in temp_value.lower() for keyword in ["Read", "Write", "ReadACP", "WriteACP", "FullControl"]):
                alert_message = f"The {line} bucket has public READ/WRITE/DELETE access. Potential data exposure risk. Please review your bucket policy again. Contact Security Team for any support."
                case_number = f"The {line} bucket has public READ/WRITE/DELETE access. Check with s3scanner."
                print(f"\033[31m{case_number}\033[m")

                # Send a notification to Slack
                send_slack_notification(alert_message)

                # Log the vulnerable bucket to a file
                with open('ohoVulnerable.txt', 'a') as vuln_file:
                    vuln_file.write(line + '\n')
            else:
                print(f"Test-0 Pass for {line}")

    print("Scanning with s3scanner completed.")
    
if __name__ == "__main__":
    scanning_with_s3scanner()
    manual_scans()
