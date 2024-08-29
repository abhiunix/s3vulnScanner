from flask import Flask, request, jsonify
import os
import threading
import requests
from dotenv import load_dotenv
import pytz
import s3vulnScanner_single 

load_dotenv()

SLACK_WEBHOOK_URL = os.getenv("slack_webhook")
app = Flask(__name__)

IST = pytz.timezone('Asia/Kolkata')

def send_to_slack(text, channel_id=None, user_id=None):
    """
    Sends a message to a Slack channel using the provided webhook URL.
    """
    payload = {
        "text": text
    }
    if channel_id:
        payload["channel"] = channel_id
    if user_id:
        payload["user"] = user_id
    
    headers = {'Content-Type': 'application/json'}
    try:
        response = requests.post(SLACK_WEBHOOK_URL, json=payload, headers=headers)
        response.raise_for_status()  
    except requests.exceptions.RequestException as e:
        print(f"Error sending message to Slack: {e}")
    return response.text

def scan_bucket(bucket_name):
    """
    Run the single bucket scan from s3vulnScanner_single script.
    """
    s3vulnScanner_single.main(bucket_name)  

@app.route('/home', methods=['GET'])
def home():
    print('home')
    return 'home'

@app.route('/scan_s3bucket', methods=['POST'])
def scan_s3bucket():
    data = request.form
    bucket_name = data.get('text')
    user_name = data.get('user_name')
    user_id = data.get('user_id')
    team_domain = data.get('team_domain')
    channel_id = data.get('channel_id')
    channel_name = data.get('channel_name')

    # print(data)
    if team_domain == "quince":
        thread = threading.Thread(target=scan_bucket, args=(bucket_name,))
        thread.start()
        return jsonify({
            'response_type': 'in_channel',  
            'text': f'<@{user_id}> has started the bucket scanning for {bucket_name}'    
        })
    else:
        print(f"Unauthorized attempt by {user_name} in {team_domain}")
        
        send_to_slack(f"<@{user_id}> is trying to use the bot from {channel_name} channel. ")
        return jsonify({
            'response_type': 'ephemeral',  
            'text': 'You are not authorized to perform this action from this channel. Please ask @security-team to add you in appropriate channel.'
        })


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8004, debug=True)
