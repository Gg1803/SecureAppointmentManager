import random
import string
import time
import threading
import logging
from email_module import send_email

# Store OTPs with their creation timestamps and expiration time (in seconds)
OTP_STORE = {}  # {email: {"otp": "123456", "created_at": timestamp}}
OTP_EXPIRY = 300  # 5 minutes

# Cleanup thread to remove expired OTPs
def cleanup_expired_otps():
    while True:
        try:
            current_time = time.time()
            expired_emails = []
            
            for email, data in OTP_STORE.items():
                if current_time - data["created_at"] > OTP_EXPIRY:
                    expired_emails.append(email)
            
            for email in expired_emails:
                OTP_STORE.pop(email, None)
                logging.info(f"Expired OTP removed for {email}")
                
            time.sleep(60)  # Check every minute
        except Exception as e:
            logging.error(f"Error in OTP cleanup: {str(e)}")

# Start cleanup thread
cleanup_thread = threading.Thread(target=cleanup_expired_otps, daemon=True)
cleanup_thread.start()

def generate_otp(length=6):
    """Generate a numeric OTP of specified length"""
    return ''.join(random.choices(string.digits, k=length))

def store_otp(email, otp):
    """Store an OTP with creation timestamp"""
    OTP_STORE[email] = {
        "otp": otp,
        "created_at": time.time()
    }
    logging.info(f"OTP stored for {email}")

def verify_otp(email, provided_otp):
    """Verify if the provided OTP matches and is not expired"""
    if email not in OTP_STORE:
        logging.warning(f"No OTP found for {email}")
        return False
    
    otp_data = OTP_STORE[email]
    current_time = time.time()
    
    # Check if OTP is expired
    if current_time - otp_data["created_at"] > OTP_EXPIRY:
        OTP_STORE.pop(email, None)
        logging.warning(f"OTP expired for {email}")
        return False
    
    # Check if OTP matches
    if otp_data["otp"] == provided_otp:
        # Remove OTP after successful verification (one-time use)
        OTP_STORE.pop(email, None)
        logging.info(f"OTP verified successfully for {email}")
        return True
    else:
        logging.warning(f"Invalid OTP provided for {email}")
        return False

def send_otp_email(email, username=None, action="login"):
    """Generate OTP and send via email"""
    otp = generate_otp()
    store_otp(email, otp)
    
    # Customize subject and message based on action
    if action == "login":
        subject = "Your Pyramid Education Login Code"
        message = f"""
        <html>
        <body>
            <h2>Pyramid Education - Two-Factor Authentication</h2>
            <p>Hello {username or ""},</p>
            <p>Your one-time verification code is: <strong>{otp}</strong></p>
            <p>This code will expire in 5 minutes.</p>
            <p>If you did not attempt to log in, please contact the administrator immediately.</p>
            <p>Regards,<br>Pyramid Education Team</p>
        </body>
        </html>
        """
    elif action == "register":
        subject = "Complete Your Pyramid Education Registration"
        message = f"""
        <html>
        <body>
            <h2>Pyramid Education - Complete Registration</h2>
            <p>Hello {username or ""},</p>
            <p>Your account has been created. To complete the registration, please use this verification code: <strong>{otp}</strong></p>
            <p>This code will expire in 5 minutes.</p>
            <p>Regards,<br>Pyramid Education Team</p>
        </body>
        </html>
        """
    else:  # Generic message
        subject = "Your Pyramid Education Verification Code"
        message = f"""
        <html>
        <body>
            <h2>Pyramid Education - Verification Code</h2>
            <p>Hello {username or ""},</p>
            <p>Your verification code is: <strong>{otp}</strong></p>
            <p>This code will expire in 5 minutes.</p>
            <p>Regards,<br>Pyramid Education Team</p>
        </body>
        </html>
        """
    
    success = send_email(email, subject, message)
    return success