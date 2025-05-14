#!/usr/bin/env python
import sys
import json
import requests
import logging
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(
    filename='/var/ossec/logs/debug-custom-telegram.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Read configuration parameters
try:
    alert_file = sys.argv[1]
    bot_token = sys.argv[3]  # From hook_url in ossec.conf
    chat_id = sys.argv[2]    # From api_key in ossec.conf
    logging.debug("Successfully read command-line arguments: alert_file=%s, bot_token=%s, chat_id=%s", alert_file, bot_token, chat_id)
except IndexError as e:
    logging.error("Failed to read command-line arguments: %s", str(e))
    sys.exit(1)

# Read the alert file
try:
    with open(alert_file, 'r') as f:
        alert = json.load(f)
    logging.info("Successfully read and parsed alert file: %s", alert_file)
    logging.debug("RAW JSON: %s", json.dumps(alert))  # Debug-level for full JSON
except FileNotFoundError as e:
    logging.warning("Alert file not found: %s", str(e))
    sys.exit(1)
except json.JSONDecodeError as e:
    logging.error("Failed to parse JSON from alert file: %s", str(e))
    sys.exit(1)
except Exception as e:
    logging.error("Unexpected error reading alert file: %s", str(e))
    sys.exit(1)

def send_to_telegram(message, bot_token, chat_id):
    """
    Sends message to Telegram using the provided bot token and chat ID.
    """
    try:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {"chat_id": chat_id, "text": message, "parse_mode": "Markdown"}
        response = requests.post(url, data=payload)
        response.raise_for_status()  # Raises an exception for 4xx/5xx status codes
        logging.info("Successfully sent message to Telegram: status_code=%s", response.status_code)
        print("Message sent successfully")
    except requests.exceptions.RequestException as e:
        logging.error("Failed to send message to Telegram: %s", str(e))
        sys.exit(1)
    except Exception as e:
        logging.error("Unexpected error sending message to Telegram: %s", str(e))
        sys.exit(1)

if 'opencti' in alert.get('rule', {}).get('groups', []):
    # Extract data fields
    try:
        description = alert.get('rule', {}).get('description', 'N/A')
        agent_name = alert.get('agent', {}).get('name', 'N/A')
        indicator_id = alert.get('data', {}).get('opencti', {}).get('indicator', {}).get('id', 'N/A')
        indicator_score = alert.get('data', {}).get('opencti', {}).get('indicator', {}).get('x_opencti_score', 'N/A')
        indicator_labels = alert.get('data', {}).get('opencti', {}).get('indicator', {}).get('labels', 'N/A')
        src_ip = alert.get('data', {}).get('opencti', {}).get('source', {}).get('src_ip', 'N/A')
        dest_ip = alert.get('data', {}).get('opencti', {}).get('source', {}).get('dest_ip', 'N/A')
        dest_port = alert.get('data', {}).get('opencti', {}).get('source', {}).get('dest_port', 'N/A')
        category = alert.get('data', {}).get('opencti', {}).get('source', {}).get('alert', {}).get('category', 'N/A')
        signature = alert.get('data', {}).get('opencti', {}).get('source', {}).get('alert', {}).get('signature', 'N/A')
        timestamp_str = alert.get('timestamp', 'N/A')
        # Convert timestamp to GMT +7
        timestamp = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S.%f%z')
        timestamp_gmt7 = timestamp + timedelta(hours=7)
        timestamp_gmt7_str = timestamp_gmt7.strftime('%Y-%m-%d %H:%M:%S')
        logging.debug("Successfully extracted alert fields: description=%s, agent_name=%s, indicator_id=%s, indicator_score=%s, indicator_labels=%s, src_ip=%s, dest_ip=%s, dest_port=%s, category=%s, signature=%s, timestamp_gmt7_str=%s", description, agent_name, indicator_id, indicator_score, indicator_labels, src_ip, dest_ip, dest_port, category, signature, timestamp_gmt7_str)
    except Exception as e:
        logging.error("Error extracting alert fields: %s", str(e))
        sys.exit(1)

    # Construct the message
    try:
        message = (
            f"\U0001F6A8 *OpenCTI Event Alert:*\n"
            f"Description: {description}\n"
            f"Indicator ID: {indicator_id}\n"
            f"Indicator Score: {indicator_score}\n"
            f"Indicator Labels: {', '.join(indicator_labels)}\n"
            f"Source IP: {src_ip}\n"
            f"Dest IP: {dest_ip}\n"
            f"Dest Port: {dest_port}\n"
            f"Category: {category}\n"
            f"Signature: {signature}\n"
            f"Agent: {agent_name}\n"
            f"Timestamp (GMT +7): {timestamp_gmt7_str}\n"
            f"---------"
        )
        logging.info("Successfully constructed message: %s", message)
        # Send the message to Telegram
        send_to_telegram(message, bot_token, chat_id)
    except Exception as e:
        logging.error("Error constructing message: %s", str(e))
        sys.exit(1)

else:
    # Extract data fields
    try:
        title = alert.get('rule', {}).get('description', 'N/A')
        agent = alert.get('agent', {}).get('name', 'N/A')
        full_log = alert.get('full_log', 'N/A')
        timestamp_str = alert.get('timestamp', 'N/A')

        # Convert timestamp to GMT +7
        timestamp = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S.%f%z')
        timestamp_gmt7 = timestamp + timedelta(hours=7)
        timestamp_gmt7_str = timestamp_gmt7.strftime('%Y-%m-%d %H:%M:%S')

        logging.debug("Successfully extracted alert fields: full_log=%s, title=%s, timestamp_gmt7_str=%s, agent=%s", full_log, title, timestamp_gmt7_str, agent)
    except Exception as e:
        logging.error("Error extracting alert fields: %s", str(e))
        sys.exit(1)

    # Construct the message
    try:
        message = (
            f"Description: {title}\n"
            f"Detail: {full_log}\n"
            f"Agent: {agent}\n"
            f"Timestamp (GMT+7): {timestamp_gmt7_str}\n"
            f"---------"
        )
        logging.info("Successfully constructed message: %s", message)
        send_to_telegram(message, bot_token, chat_id)
    except Exception as e:
        logging.error("Error constructing message: %s", str(e))
        sys.exit(1)
