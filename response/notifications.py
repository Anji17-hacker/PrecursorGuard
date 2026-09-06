#!/usr/bin/env python3
"""
response/notifications.py

STUB — not wired into live_watcher.py yet. This is where an email or
Slack/Teams webhook notification would go once an alert fires, so a
SOC analyst doesn't have to be staring at the console.

Left unimplemented deliberately rather than half-built with a fake
"success" return, so it's obvious this hasn't been built or tested
yet. To wire it in: import send_slack_alert (or write send_email_alert
following the same shape) into response/alerts.py's log_alert(), and
add the webhook URL / SMTP credentials to your environment — never
commit them to the repo.
"""


def send_slack_alert(result, webhook_url):
    """
    NOT IMPLEMENTED. Sketch of what this would do:

        import requests
        text = f"PrecursorGuard ALERT — risk score {result['risk_score']}"
        requests.post(webhook_url, json={"text": text}, timeout=5)

    Left as a stub — add the `requests` dependency and real error
    handling (timeouts, retries, webhook failures) before using this
    for anything beyond a demo.
    """
    raise NotImplementedError("Slack notifications are not implemented yet — see module docstring.")
