import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
from datetime import datetime

# Load environment variables
load_dotenv()

# Email configuration
EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", "587"))
EMAIL_USERNAME = os.getenv("EMAIL_USERNAME", "")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")
EMAIL_FROM = os.getenv("EMAIL_FROM", "pyramideducation@example.com")
EMAIL_SENDER_NAME = os.getenv("EMAIL_SENDER_NAME", "Pyramid Education")

# Enable/disable email functionality
EMAIL_ENABLED = os.getenv("EMAIL_ENABLED", "True").lower() == "true"

def send_email(to_email, subject, html_content, text_content=None):
    """
    Sends an email with both HTML and plain text versions.
    """
    if not EMAIL_ENABLED:
        logging.info(f"Email sending disabled. Would have sent '{subject}' to {to_email}")
        return False

    if not EMAIL_USERNAME or not EMAIL_PASSWORD:
        logging.error("Email credentials not configured. Please set EMAIL_USERNAME and EMAIL_PASSWORD.")
        return False

    try:
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"{EMAIL_SENDER_NAME} <{EMAIL_FROM}>"
        msg['To'] = to_email

        # Create plain text version if not provided
        if text_content is None:
            # Simple conversion from HTML to plain text
            text_content = html_content.replace('<br>', '\n').replace('<p>', '\n').replace('</p>', '\n')
            # Strip remaining HTML tags
            import re
            text_content = re.sub('<[^<]+?>', '', text_content)

        # Attach parts
        part1 = MIMEText(text_content, 'plain')
        part2 = MIMEText(html_content, 'html')
        msg.attach(part1)
        msg.attach(part2)

        # Send email
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
            server.send_message(msg)
            
        logging.info(f"Email sent successfully to {to_email}: {subject}")
        return True
        
    except Exception as e:
        logging.error(f"Failed to send email to {to_email}: {str(e)}")
        return False

# Email Templates

def get_appointment_created_email(appointment):
    """
    Generate email content for a new appointment confirmation.
    """
    subject = "Your Pyramid Education Appointment Confirmation"
    
    html_content = f"""
    <html>
    <body>
        <h2>Your appointment with Pyramid Education has been confirmed</h2>
        <p>Dear {appointment.client_first_name} {appointment.client_last_name},</p>
        <p>Thank you for scheduling an appointment with Pyramid Education. Your appointment details are:</p>
        
        <ul>
            <li><strong>Date:</strong> {appointment.appointment_date}</li>
            <li><strong>Time:</strong> {appointment.appointment_time}</li>
            <li><strong>Representative:</strong> {appointment.representative_name}</li>
            <li><strong>Reason:</strong> {appointment.reason}</li>
        </ul>
        
        <p>If you need to reschedule or have any questions, please contact us.</p>
        <p>We look forward to working with you!</p>
        <p>Sincerely,<br>The Pyramid Education Team</p>
    </body>
    </html>
    """
    
    return subject, html_content

def get_appointment_updated_email(appointment, changes=None):
    """
    Generate email content for an updated appointment.
    
    Args:
        appointment: The updated appointment object
        changes: Optional dictionary of fields that changed {field: [old_value, new_value]}
    """
    subject = "Your Pyramid Education Appointment Has Been Updated"
    
    changes_html = ""
    if changes:
        changes_html = "<h3>Changes to your appointment:</h3><ul>"
        for field, (old_val, new_val) in changes.items():
            # Format the field name for display
            field_name = field.replace('_', ' ').title()
            changes_html += f"<li><strong>{field_name}:</strong> Changed from '{old_val}' to '{new_val}'</li>"
        changes_html += "</ul>"
    
    html_content = f"""
    <html>
    <body>
        <h2>Your appointment with Pyramid Education has been updated</h2>
        <p>Dear {appointment.client_first_name} {appointment.client_last_name},</p>
        <p>Your appointment with Pyramid Education has been updated.</p>
        
        {changes_html}
        
        <h3>Current appointment details:</h3>
        <ul>
            <li><strong>Date:</strong> {appointment.appointment_date}</li>
            <li><strong>Time:</strong> {appointment.appointment_time}</li>
            <li><strong>Representative:</strong> {appointment.representative_name}</li>
            <li><strong>Reason:</strong> {appointment.reason}</li>
        </ul>
        
        <p>If you have any questions or need further assistance, please contact us.</p>
        <p>Sincerely,<br>The Pyramid Education Team</p>
    </body>
    </html>
    """
    
    return subject, html_content

def get_appointment_rescheduled_email(appointment, old_date, old_time):
    """
    Generate email content for a rescheduled appointment.
    """
    subject = "Your Pyramid Education Appointment Has Been Rescheduled"
    
    html_content = f"""
    <html>
    <body>
        <h2>Your appointment with Pyramid Education has been rescheduled</h2>
        <p>Dear {appointment.client_first_name} {appointment.client_last_name},</p>
        <p>Your appointment with Pyramid Education has been rescheduled from {old_date} at {old_time} to:</p>
        
        <ul>
            <li><strong>New Date:</strong> {appointment.appointment_date}</li>
            <li><strong>New Time:</strong> {appointment.appointment_time}</li>
            <li><strong>Representative:</strong> {appointment.representative_name}</li>
            <li><strong>Reason:</strong> {appointment.reason}</li>
        </ul>
        
        <p>If this new time doesn't work for you, please contact us to find a more suitable arrangement.</p>
        <p>Sincerely,<br>The Pyramid Education Team</p>
    </body>
    </html>
    """
    
    return subject, html_content

def get_appointment_cancelled_email(appointment):
    """
    Generate email content for a cancelled appointment.
    """
    subject = "Your Pyramid Education Appointment Has Been Cancelled"
    
    html_content = f"""
    <html>
    <body>
        <h2>Your appointment with Pyramid Education has been cancelled</h2>
        <p>Dear {appointment.client_first_name} {appointment.client_last_name},</p>
        <p>We're writing to inform you that your appointment scheduled for {appointment.appointment_date} 
           at {appointment.appointment_time} has been cancelled.</p>
        
        <p>If you would like to reschedule or have any questions, please contact us.</p>
        <p>We apologize for any inconvenience this may cause.</p>
        <p>Sincerely,<br>The Pyramid Education Team</p>
    </body>
    </html>
    """
    
    return subject, html_content

def get_security_alert_email(alert_type, username, details):
    """
    Generate email content for a security alert.
    
    Args:
        alert_type: Type of security alert (e.g., 'brute_force', 'rate_limit')
        username: Username associated with the alert
        details: Detailed description of the alert
    
    Returns:
        tuple: (subject, html_content) for the email
    """
    alert_type_friendly = alert_type.replace('_', ' ').title()
    
    subject = f"SECURITY ALERT: {alert_type_friendly} - Pyramid Education System"
    
    html_content = f"""
    <html>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-left: 5px solid #d9534f;">
            <h2 style="color: #d9534f;">Security Alert: {alert_type_friendly}</h2>
            
            <p>A potential security issue has been detected in the Pyramid Education appointment system.</p>
            
            <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd; font-weight: bold;">Alert Type:</td>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd;">{alert_type_friendly}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd; font-weight: bold;">User:</td>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd;">{username}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd; font-weight: bold;">Time:</td>
                    <td style="padding: 8px; border-bottom: 1px solid #ddd;">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td>
                </tr>
            </table>
            
            <div style="background-color: #f8f8f8; padding: 15px; border-left: 3px solid #d9534f;">
                <h3 style="margin-top: 0;">Details:</h3>
                <p>{details}</p>
            </div>
            
            <p style="margin-top: 30px; font-size: 12px; color: #777;">
                This is an automated message from the Pyramid Education security system. 
                Please investigate this issue and take appropriate action if needed.
            </p>
        </div>
    </body>
    </html>
    """
    
    return subject, html_content