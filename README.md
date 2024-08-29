# s3vulnScanner
This tool is built to scan for s3 buckets vulnerabilities.

# Prerequisite
- Update webhook url of slack in .env

## Usage:

Step-1: You need to save all your s3 buckets name in alls3.txt file.

Step-2: Run the below commands for scanning single bucket:
```
python3 s3vulnScanner_direct.py <bucket-name>
```

Step-3: Run the below commands for scanning multiple buckets stored in alls3.txt file:
```
python3 s3vulnScanner_direct.py alls3.txt
```
All your vulnerable buckets will be aggregated to ohoVulnerable.txt file.

For any query, contact @abhiunix [https://x.com/abhiunix]
