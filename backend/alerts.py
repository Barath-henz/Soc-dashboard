import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email_alert(alert):
    """
    Sends an email notification for a critical alert.
    Requires SMTP_EMAIL and SMTP_PASSWORD to be set in .env
    """
    sender_email = os.environ.get("SMTP_EMAIL")
    sender_password = os.environ.get("SMTP_PASSWORD")
    
    if not sender_email or not sender_password or sender_email == "your-email@gmail.com":
        print("SMTP credentials not configured. Skipping email alert.")
        return

    # Using the same email for recipient for demonstration
    receiver_email = sender_email 

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = f"CRITICAL SOC ALERT: {alert.rule_triggered}"

    body = f"""
    Security Operations Center - Critical Alert Detected!
    
    Rule Triggered: {alert.rule_triggered}
    Severity: {alert.severity.upper()}
    Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
    
    Description:
    {alert.description}
    
    Please investigate immediately.
    """
    
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Connect to Gmail SMTP server
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
        print(f"Email alert sent successfully for: {alert.rule_triggered}")
    except Exception as e:
        print(f"Failed to send email alert: {e}")
