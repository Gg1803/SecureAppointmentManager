import sys
import hashlib
import requests
from urllib.parse import quote_plus
from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import QLabel
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import Qt
import os
from dotenv import load_dotenv
import re
import logging
import tempfile
from datetime import datetime, timedelta
import functools  

from email_module import *
from platformdirs import user_data_dir 
from otp_module import *
from reminder_Service import *
from intrusion_detector import *


background_color = "#FFFFFF"  # White background
text_color = "#333333"         # Dark text color
button_color = "#4A90E2"       # Button background color
button_hover_color = "#3A80D2" # Button hover color
   
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("pyramid_app.log"),
        logging.StreamHandler()
    ]
)

load_dotenv()
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SECURITY_ALERT_EMAIL = os.getenv("SECURITY_ALERT_EMAIL")

ids = IntrusionDetector(
    rate_limit_count=5,                  # Trigger alert after 5 actions in window
    rate_limit_window=timedelta(minutes=5),  # 5-minute window for rate limiting
    business_hours=(9, 17),              # Business hours 9 AM to 5 PM
    alert_email=SECURITY_ALERT_EMAIL     # Email to send security alerts to
)

ROLE_ADMIN = 'admin'
ROLE_USER = 'user'

import os
import requests
from pathlib import Path

def get_app_data_dir():
    base_dir = Path(os.getenv('LOCALAPPDATA') or Path.home() / '.local' / 'share')
    app_dir = base_dir / "PyramidAppointmentSystem"
    app_dir.mkdir(parents=True, exist_ok=True)
    return app_dir

def download_logo():
    url = "https://pyramidgroups.com.au/img/logo.png"
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "image/png,image/*;q=0.8,*/*;q=0.5"
    }
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            logo_path = get_app_data_dir() / "logo.png"
            with open(logo_path, "wb") as f:
                f.write(response.content)
            return logo_path
        else:
            print(f"Logo download failed. Status code: {response.status_code}")
            return None
    except Exception as e:
        print(f"Logo download failed: {e}")
        return None

def hash_password(password: str) -> str:
    """Hash a password for storing."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_password(stored_hash: str, provided_password: str) -> bool:
    """Verify a stored password against one provided by user"""
    return stored_hash == hash_password(provided_password)

def is_valid_phone(phone):
            return re.match(r"^\+?\d{7,15}$", phone) is not None

def sanitize_input(input_string: str) -> str:
    """Sanitize input to prevent injection attacks and validate names."""
    # Remove potentially dangerous characters
    sanitized_string = re.sub(r'[<>;\'"\\]', '', input_string)
    
    # Validate names (only allow letters and spaces)
    if not re.match(r'^[a-zA-Z\s]+$', sanitized_string):
        raise ValueError("Invalid name format. Only letters and spaces are allowed.")
    
    return sanitized_string

def sanitize_reason(input_string: str) -> str:
    """Sanitize reason input to allow a broader range of characters."""
    # Allow letters, numbers, spaces, and some punctuation
    sanitized_string = re.sub(r'[<>;\'"\\]', '', input_string)  # Remove potentially dangerous characters
    return sanitized_string  # Return the sanitized string

def is_valid_email(email):
    """Validate email format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def is_valid_appointment_date(appointment_date: str) -> bool:
    """Check if the appointment date is today or in the future."""
    today = datetime.now().date()
    appointment_date_obj = datetime.strptime(appointment_date, '%Y-%m-%d').date()
    return appointment_date_obj >= today

def is_strong_password(password: str) -> bool:
    return (
        len(password) >= 8 and
        re.search(r'[A-Z]', password) and
        re.search(r'[a-z]', password) and
        re.search(r'\d', password) and
        re.search(r'[!@#$%^&*(),.?":{}|<>]', password)
    )

class User:
    def __init__(self, user_id, username, password_hash, role, email):
        self.user_id = user_id
        self.username = username
        self.password_hash = password_hash
        self.role = role
        self.email = email

class FilterDialog(QtWidgets.QDialog):
    def __init__(self, db, current_user):
        super().__init__()
        self.setWindowTitle("Filter Appointments")
        self.setFixedWidth(400)
        self.db = db
        self.current_user = current_user
        
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {background_color};
                color: {text_color};
            }}
            QLabel, QRadioButton, QCheckBox, QGroupBox {{
                color: {text_color};
            }}
            QPushButton {{
                background-color: {button_color};
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: {button_hover_color};
            }}
            QLineEdit, QDateEdit, QTimeEdit, QComboBox {{
                border: 1px solid #CCCCCC;
                border-radius: 4px;
                padding: 4px;
                background-color: #FFFFFF;  /* Set a light background for better visibility */
                color: {text_color};
            }}
            QRadioButton::indicator {{
                width: 20px;
                height: 20px;
                border: 1px solid {text_color};  /* Border color for radio button */
            }}
            QComboBox {{
                border: 1px solid #CCCCCC;
                border-radius: 4px;
                padding: 4px;
                background-color: #FFFFFF;  /* Set a light background for better visibility */
                color: {text_color};  /* Text color */
            }}
            QComboBox QAbstractItemView {{
                background-color: #FFFFFF;  /* Background color of the dropdown items */
                color: {text_color};  /* Text color of the dropdown items */
            }}
            QRadioButton::indicator:checked {{
                background-color: {button_color};  /* Background color when checked */
                border: 1px solid {text_color};  /* Border color when checked */
            }}
        """)

        layout = QtWidgets.QVBoxLayout(self)
        
        date_group = QtWidgets.QGroupBox("Date Range")
        date_layout = QtWidgets.QVBoxLayout()
        
        self.date_all_radio = QtWidgets.QRadioButton("All Dates")
        self.date_range_radio = QtWidgets.QRadioButton("Custom Range")
        self.date_upcoming_radio = QtWidgets.QRadioButton("Upcoming")
        self.date_past_radio = QtWidgets.QRadioButton("Past")
        
        self.date_all_radio.setChecked(True)
        
        date_layout.addWidget(self.date_all_radio)
        date_layout.addWidget(self.date_range_radio)
        date_layout.addWidget(self.date_upcoming_radio)
        date_layout.addWidget(self.date_past_radio)
        
        date_range_widget = QtWidgets.QWidget()
        date_range_layout = QtWidgets.QFormLayout(date_range_widget)
        
        self.start_date = QtWidgets.QDateEdit(QtCore.QDate.currentDate().addDays(-30))
        self.start_date.setCalendarPopup(True)
        self.end_date = QtWidgets.QDateEdit(QtCore.QDate.currentDate().addDays(30))
        self.end_date.setCalendarPopup(True)
        
        date_range_layout.addRow("From:", self.start_date)
        date_range_layout.addRow("To:", self.end_date)
        date_range_widget.setEnabled(False)
        
        self.date_range_radio.toggled.connect(date_range_widget.setEnabled)
        
        date_layout.addWidget(date_range_widget)
        date_group.setLayout(date_layout)
        layout.addWidget(date_group)
        
        if current_user.role == 'admin':
            rep_group = QtWidgets.QGroupBox("Representative")
            rep_layout = QtWidgets.QVBoxLayout()
            
            self.rep_all_radio = QtWidgets.QRadioButton("All Representatives")
            self.rep_specific_radio = QtWidgets.QRadioButton("Specific Representative")
            self.rep_all_radio.setChecked(True)
            
            rep_layout.addWidget(self.rep_all_radio)
            rep_layout.addWidget(self.rep_specific_radio)
            
            self.rep_combo = QtWidgets.QComboBox()
            self.populate_representatives()
            rep_layout.addWidget(self.rep_combo)
            self.rep_combo.setEnabled(False)
            
            self.rep_specific_radio.toggled.connect(self.rep_combo.setEnabled)
            
            rep_group.setLayout(rep_layout)
            layout.addWidget(rep_group)
        
        keyword_group = QtWidgets.QGroupBox("Keyword Search")
        keyword_layout = QtWidgets.QFormLayout()
        self.keyword_input = QtWidgets.QLineEdit()
        keyword_layout.addRow("Search term:", self.keyword_input)
        keyword_group.setLayout(keyword_layout)
        layout.addWidget(keyword_group)
        
        button_layout = QtWidgets.QHBoxLayout()
        self.apply_btn = QtWidgets.QPushButton("Apply Filters")
        self.clear_btn = QtWidgets.QPushButton("Clear Filters")
        self.cancel_btn = QtWidgets.QPushButton("Cancel")
        
        button_layout.addWidget(self.apply_btn)
        button_layout.addWidget(self.clear_btn)
        button_layout.addWidget(self.cancel_btn)
        
        self.apply_btn.clicked.connect(self.accept)
        self.clear_btn.clicked.connect(self.clear_filters)
        self.cancel_btn.clicked.connect(self.reject)
        
        layout.addLayout(button_layout)

    
    def populate_representatives(self):
        """Populate the representatives dropdown with users"""
        self.rep_combo.clear()
        for user in self.db.get_all_users():
            self.rep_combo.addItem(user.username)
    
    def clear_filters(self):
        """Reset all filters to default"""
        self.date_all_radio.setChecked(True)
        self.start_date.setDate(QtCore.QDate.currentDate().addDays(-30))
        self.end_date.setDate(QtCore.QDate.currentDate().addDays(30))
        self.keyword_input.clear()
        
        if self.current_user.role == 'admin':
            self.rep_all_radio.setChecked(True)
    
    def get_filter_params(self):
        """Return the filter parameters as a dict"""
        params = {}
        
        if self.date_range_radio.isChecked():
            params['start_date'] = self.start_date.date().toString('yyyy-MM-dd')
            params['end_date'] = self.end_date.date().toString('yyyy-MM-dd')
        elif self.date_upcoming_radio.isChecked():
            params['start_date'] = QtCore.QDate.currentDate().toString('yyyy-MM-dd')
            params['end_date'] = None  # No upper limit
        elif self.date_past_radio.isChecked():
            params['start_date'] = None  # No lower limit
            params['end_date'] = QtCore.QDate.currentDate().toString('yyyy-MM-dd')
        
        if self.current_user.role == 'admin' and self.rep_specific_radio.isChecked():
            params['representative'] = self.rep_combo.currentText()
        
        if self.keyword_input.text().strip():
            params['keyword'] = self.keyword_input.text().strip()
        
        return params

class Appointment:
    def __init__(self, appointment_id, representative_name,
                 client_first_name, client_last_name, client_email, client_phone,
                 appointment_date, appointment_time, reason, school_preferences, notes):
        self.appointment_id = appointment_id
        self.representative_name = representative_name
        self.client_first_name = client_first_name
        self.client_last_name = client_last_name
        self.client_email = client_email
        self.client_phone = client_phone
        self.appointment_date = appointment_date
        self.appointment_time = appointment_time
        self.reason = reason
        self.school_preferences = school_preferences
        self.notes = notes

class DatabaseManager:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "apikey":       SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
            "Content-Type":  "application/json"
        })

    def close(self):
        """Close the HTTP session."""
        self.session.close()

    def get_user_by_username(self, username):
        username = sanitize_input(username)
        url = f"{SUPABASE_URL}/rest/v1/users"
        params = {"username": f"eq.{quote_plus(username)}"}
        r = self.session.get(url, params=params, verify=True)
        r.raise_for_status()
        data = r.json()
        if not data:
            return None
        u = data[0]
        return User(u['user_id'], u['username'], u['password_hash'], u['role'], u['email'])

    def get_all_users(self):
        url = f"{SUPABASE_URL}/rest/v1/users"
        r = self.session.get(url, verify=True)
        r.raise_for_status()
        return [User(u['user_id'], u['username'], u['password_hash'], u['role'], u['email']) for u in r.json()]

    def add_user(self, username, password, email, role=ROLE_USER):
        username = sanitize_input(username)
        url = f"{SUPABASE_URL}/rest/v1/users"
        payload = {
            'username': username,
            'password_hash': hash_password(password),
            'email': email,
            'role': role
            
        }
        r = self.session.post(url, json=payload, verify=True)
        if r.status_code in (200, 201):
            return True, None
        return False, r.text

    def delete_user(self, user_id):
        url = f"{SUPABASE_URL}/rest/v1/users"
        params = {'user_id': f'eq.{user_id}'}
        r = self.session.delete(url, params=params, verify=True)
        r.raise_for_status()
        
    def delete_user_by_username(self, username):
        """Delete a user by username."""
        user = self.get_user_by_username(username)
        if user:
            self.delete_user(user.user_id)
            return True
        return False

    def update_user_password(self, user_id, new_password):
        url = f"{SUPABASE_URL}/rest/v1/users"
        params = {'user_id': f'eq.{user_id}'}
        payload = {'password_hash': hash_password(new_password)}
        r = self.session.patch(url, params=params, json=payload)
        r.raise_for_status()

    def add_appointment(self, appt: Appointment):
        url = f"{SUPABASE_URL}/rest/v1/appointments"
        payload = {
            "representative_name": appt.representative_name,
            "client_first_name":   appt.client_first_name,
            "client_last_name":    appt.client_last_name,
            "client_email":        appt.client_email,
            "client_phone":        appt.client_phone,
            "appointment_date":    appt.appointment_date,
            "appointment_time":    appt.appointment_time,
            "reason":              appt.reason,
            "school_preferences":  appt.school_preferences,
            "notes":               appt.notes
        }
        headers = {"Prefer": "return=representation"}
        r = self.session.post(url, json=payload, headers=headers)
        r.raise_for_status()
        row = r.json()[0]
        return row["appointment_id"]

    def get_appointments(self, search_filter=None, username=None, filter_params=None):
        """
        Retrieve appointments from Supabase using PostgREST syntax.
        
        Args:
            search_filter (str): Text to search for in appointment fields
            username (str): Username to filter appointments by (for non-admin users)
            filter_params (dict): Additional filters like date range, representative, etc.
        """
        url = f"{SUPABASE_URL}/rest/v1/appointments"
        
        # Base parameters
        params = {
            'select': '*',
            'order': 'appointment_date.desc,appointment_time.desc'
        }
        
        # Handle username filter (representative name)
        if username:
            params['representative_name'] = f"eq.{username}"
        
        # Handle date and representative filters
        if filter_params:
            if 'start_date' in filter_params and filter_params['start_date']:
                params['appointment_date'] = f"gte.{filter_params['start_date']}"
                
            if 'end_date' in filter_params and filter_params['end_date']:
                # If we already have a start_date filter, we need to use and() for the end_date
                if 'appointment_date' in params:
                    params['and'] = f"(appointment_date.lte.{filter_params['end_date']})"
                else:
                    params['appointment_date'] = f"lte.{filter_params['end_date']}"
            
            if 'representative' in filter_params and filter_params['representative']:
                params['representative_name'] = f"eq.{filter_params['representative']}"
        
        # Handle search term (main search or keyword filter)
        search_term = None
        if search_filter:
            search_term = search_filter.strip()
        elif filter_params and 'keyword' in filter_params:
            search_term = filter_params.get('keyword', '').strip()
        
        if search_term:
            # Check if search term contains a space (possibly first and last name)
            terms = search_term.split()
            
            if len(terms) >= 2:
                # Handle multi-word search (likely first and last name)
                first_name = terms[0]
                last_name = ' '.join(terms[1:])  # Join remaining terms as last name
                
                # Create specific conditions for first+last name combination
                first_encoded = f"ilike.*{first_name}*"
                last_encoded = f"ilike.*{last_name}*"
                full_term_encoded = f"ilike.*{search_term}*"
                
                # Search for first+last name combination, or full term in any field
                params['or'] = (
                    f"(and(client_first_name.{first_encoded},client_last_name.{last_encoded}),"
                    f"client_first_name.{full_term_encoded},"
                    f"client_last_name.{full_term_encoded},"
                    f"client_email.{full_term_encoded},"
                    f"client_phone.{full_term_encoded})"
                )
                
                logging.info(f"Multi-word search: first='{first_name}', last='{last_name}', full='{search_term}'")
            else:
                # Single word search - use simple pattern matching
                encoded_term = f"ilike.*{search_term}*"
                
                # PostgREST uses a specific format for OR conditions
                params['or'] = (
                    f"(client_first_name.{encoded_term},"
                    f"client_last_name.{encoded_term},"
                    f"client_email.{encoded_term},"
                    f"client_phone.{encoded_term})"
                )
                
                logging.info(f"Single-word search term: '{search_term}', encoded as: '{encoded_term}'")
        
        # Log the complete request details
        logging.info(f"API request URL: {url}")
        logging.info(f"API request params: {params}")
        
        try:
            # Make the request
            r = self.session.get(url, params=params)
            r.raise_for_status()
            
            # Process the results
            results = r.json()
            logging.info(f"Search returned {len(results)} appointments")
            
            return [Appointment(**a) for a in results]
            
        except requests.exceptions.HTTPError as e:
            logging.error(f"HTTP error: {e}")
            # Extract more detailed error information if available
            try:
                error_detail = e.response.json()
                logging.error(f"API error details: {error_detail}")
            except:
                pass
            raise e
        except Exception as e:
            logging.exception(f"Error fetching appointments: {str(e)}")
            raise e



    def update_appointment(self, appt: Appointment, old_appt=None):
        url = f"{SUPABASE_URL}/rest/v1/appointments"
        params = {'appointment_id': f'eq.{appt.appointment_id}'}
        payload = appt.__dict__
        r = self.session.patch(url, params=params, json=payload)
        r.raise_for_status()       
        changes = {}
        
        # Check if old_appt is provided
        if old_appt is not None:
            for attr, new_val in appt.__dict__.items():
                old_val = getattr(old_appt, attr)
                if old_val != new_val and attr != 'appointment_id':
                    changes[attr] = (old_val, new_val)
            # Email notification logic
            if appt.client_email:
                logging.info(f"Preparing to send email notification for appointment ID {appt.appointment_id} to {appt.client_email}.")
                if appt.appointment_date != old_appt.appointment_date or \
                appt.appointment_time != old_appt.appointment_time:
                    # If it's a reschedule
                    subject, html_content = get_appointment_rescheduled_email(
                        appt, old_appt.appointment_date, old_appt.appointment_time)
                else:
                    # If it's an update
                    subject, html_content = get_appointment_updated_email(appt, changes)
            
            if send_email(appt.client_email, subject, html_content):
                logging.info(f"Update notification email sent to {appt.client_email}.")
            else:
                logging.error(f"Failed to send update notification to {appt.client_email}.")
                QtWidgets.QMessageBox.warning(None, "Email Error", 
                                        "Appointment updated but email notification failed.")
        return changes
   
    def delete_appointment(self, appointment_id):
        url = f"{SUPABASE_URL}/rest/v1/appointments"
        params = {'appointment_id': f'eq.{appointment_id}'}
        r = self.session.delete(url, params=params)
        r.raise_for_status()
    def add_feedback(self, appointment_id, feedback_text):
        """Add feedback to an appointment's notes."""
        url = f"{SUPABASE_URL}/rest/v1/appointments"
        params = {'appointment_id': f'eq.{appointment_id}'}
        r = self.session.get(url, params=params)
        r.raise_for_status()       
        data = r.json()
        if not data:
            return False, "Appointment not found"       
        current_notes = data[0].get('notes', '')
        timestamp = datetime.now().strftime("%Y-%m-%d %I:%M:%S %p")  # 12-hour format with AM/PM
        new_notes = f"{current_notes}\n\n[FEEDBACK - {timestamp}]\n{feedback_text}"        
        update_params = {'appointment_id': f'eq.{appointment_id}'}
        update_payload = {'notes': new_notes}
        r = self.session.patch(url, params=update_params, json=update_payload)        
        if r.status_code in (200, 204):
            return True, None
        return False, r.text

class OTPVerificationDialog(QtWidgets.QDialog):
    def __init__(self, email, username, action="login"):
        super().__init__()
        self.setWindowTitle("Verify Your Identity")
        self.setFixedSize(350, 150)
        self.email = email
        self.username = username
        self.action = action        
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {background_color};
                color: {text_color};
            }}
            QLabel {{
                color: {text_color};
            }}
            QLineEdit {{
                border: 1px solid #CCCCCC;
                border-radius: 4px;
                padding: 4px;
                background-color: {background_color};
                color: {text_color};
            }}
            QPushButton {{
                background-color: {button_color};
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: {button_hover_color};
            }}
        """)
                
        self.otp_input = QtWidgets.QLineEdit()
        self.otp_input.setPlaceholderText("Enter 6-digit code")
        self.verify_button = QtWidgets.QPushButton("Verify")
        self.resend_button = QtWidgets.QPushButton("Resend Code")        
        form = QtWidgets.QFormLayout()
        form.addRow("Enter verification code:", self.otp_input)        
        button_layout = QtWidgets.QHBoxLayout()
        button_layout.addWidget(self.verify_button)
        button_layout.addWidget(self.resend_button)        
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(QtWidgets.QLabel(f"A verification code has been sent to {email}"))
        layout.addLayout(form)
        layout.addLayout(button_layout)       
        self.setLayout(layout)        
        self.verify_button.clicked.connect(self.verify_otp)
        self.resend_button.clicked.connect(self.resend_otp)
        
        self.send_otp()   
    def send_otp(self):
        if send_otp_email(self.email, self.username, self.action):
            self.resend_button.setEnabled(False)
            QtCore.QTimer.singleShot(30000, lambda: self.resend_button.setEnabled(True))
        else:
            QtWidgets.QMessageBox.warning(self, "Error", 
                "Failed to send verification code. Please check email configuration.")
    def resend_otp(self):
        self.send_otp()
        QtWidgets.QMessageBox.information(self, "Code Sent", 
            f"A new verification code has been sent to {self.email}")    
    def verify_otp(self):
        provided_otp = self.otp_input.text().strip()
        if not provided_otp:
            QtWidgets.QMessageBox.warning(self, "Input Error", "Please enter the verification code.")
            return
        
        if verify_otp(self.email, provided_otp):
            self.accept()
        else:
            QtWidgets.QMessageBox.warning(self, "Verification Failed", 
                "Invalid or expired verification code. Please try again.")            
class LoginDialog(QtWidgets.QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Pyramid Education - Login")
        self.setWindowFlags(QtCore.Qt.Window | QtCore.Qt.WindowTitleHint | QtCore.Qt.WindowSystemMenuHint | QtCore.Qt.WindowMinMaxButtonsHint)
        self.showFullScreen()

        # Logo Setup
        logo_label = QLabel()
        logo_label.setAlignment(Qt.AlignCenter)
        logo_path = download_logo()
        if logo_path and logo_path.exists():
            pixmap = QtGui.QPixmap(str(logo_path))
            # Increased logo size by 1.3x
            logo_label.setPixmap(pixmap.scaledToWidth(390, QtCore.Qt.SmoothTransformation))  # 300 * 1.3 = 390
            self.logo_path = logo_path  # Save for cleanup
        
        # Create a container widget to limit form width to 70% of screen width
        form_widget = QtWidgets.QWidget()
        form_widget.setMaximumWidth(int(self.width() * 0.7))
        
        form = QtWidgets.QFormLayout()

        # Inputs
        self.username_input = QtWidgets.QLineEdit()
        self.username_input.setMinimumWidth(300)
        self.password_input = QtWidgets.QLineEdit()
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password_input.setMinimumWidth(300)
        self.login_button = QtWidgets.QPushButton("Login")
        self.login_button.setMinimumWidth(150)

        # Form
        form.addRow("Username:", self.username_input)
        form.addRow("Password:", self.password_input)

        form_container = QtWidgets.QVBoxLayout()
        form_container.addLayout(form)
        form_container.addSpacing(10)
        form_container.addWidget(self.login_button, alignment=Qt.AlignCenter)
        
        # Apply form layout to the container widget
        form_widget.setLayout(form_container)

        # Main Layout
        main_layout = QtWidgets.QVBoxLayout()
        main_layout.addStretch(2)  # Increase stretch factor to push logo higher
        main_layout.addWidget(logo_label)
        main_layout.addSpacing(20)
        main_layout.addWidget(form_widget, alignment=Qt.AlignCenter)  # Center align the form widget
        main_layout.addStretch(3)  # Larger stretch at bottom to push content up
        self.setLayout(main_layout)

        # Stylesheet (assumes these variables are defined)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {background_color};
                color: {text_color};
                font-size: 18px;
            }}
            QLabel {{
                color: {text_color};
                font-size: 24px;
            }}
            QLineEdit {{
                border: 1px solid #CCCCCC;
                border-radius: 4px;
                padding: 8px;
                background-color: {background_color};
                color: {text_color};
                font-size: 18px;
            }}
            QPushButton {{
                background-color: {button_color};
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 4px;
                font-size: 18px;
            }}
            QPushButton:hover {{
                background-color: {button_hover_color};
            }}
        """)

        self.login_button.clicked.connect(self.try_login)
        self.user = None

    def closeEvent(self, event):
        if hasattr(self, 'logo_path') and self.logo_path.exists():
            try:
                os.remove(self.logo_path)
            except Exception as e:
                print(f"Error deleting logo: {e}")
        super().closeEvent(event)

    def try_login(self):
        username = sanitize_input(self.username_input.text().strip())
        password = self.password_input.text()
        if not username or not password:
            QtWidgets.QMessageBox.warning(self, "Error", "Please enter both username and password.")
            return
        db = DatabaseManager()
        user = db.get_user_by_username(username)
        db.close()
        if user and verify_password(user.password_hash, password):
            ids.record_event(username, "login attempt")
            ids.reset_consecutive_failed_logins(username)
            if user.email:
                otp_dialog = OTPVerificationDialog(user.email, user.username)
                if otp_dialog.exec_() == QtWidgets.QDialog.Accepted:
                    self.user = user
                    logging.info(f"Login successful for user: {username} (2FA verified)")
                    ids.record_event(user.username, "login attempt")
                    db.close()
                    self.accept()
                else:
                    logging.warning(f"OTP verification failed for user: {username}")
                    db.close()
            else:
                QtWidgets.QMessageBox.warning(self, "Warning", 
                    "No email configured for 2FA. Please contact administrator.")
                self.user = user
                logging.info(f"Login successful for user: {username} (no 2FA)")
                db.close()
                self.accept()
        else:
            ids.record_event(username, "failed login")
            logging.warning(f"Login failed for username: {username}")
            db.close()
            QtWidgets.QMessageBox.warning(self, "Error", "Invalid username or password.")

class AppointmentDialog(QtWidgets.QDialog):
    def __init__(self, appointment=None):
        super().__init__()
        self.setWindowTitle("Appointment Details")
        self.setFixedSize(450, 600)
        self.db = DatabaseManager()
        self.appointment = appointment
        self.original_appointment = appointment  # Keep original for change tracking       
        self.rep_combo = QtWidgets.QComboBox()
        for u in self.db.get_all_users():
            self.rep_combo.addItem(u.username)
        self.client_first_edit = QtWidgets.QLineEdit()
        self.client_last_edit = QtWidgets.QLineEdit()
        self.client_email_edit = QtWidgets.QLineEdit()
        self.client_phone_edit = QtWidgets.QLineEdit()
        self.date_edit = QtWidgets.QDateEdit(QtCore.QDate.currentDate())
        self.date_edit.setCalendarPopup(True)
        self.time_edit = QtWidgets.QTimeEdit()  # Initialize without current time
        self.time_edit.setTime(QtCore.QTime.currentTime())
        self.reason_edit = QtWidgets.QTextEdit()
        self.pref_edit = QtWidgets.QTextEdit()
        self.notes_edit = QtWidgets.QTextEdit()  
        if self.appointment is None:  # Check if this is a new appointment
            self.notes_edit.setPlainText("UNDONE")      
        self.send_email_checkbox = QtWidgets.QCheckBox("Send email notification to client")
        self.send_email_checkbox.setChecked(True)  # Default to sending emails       
        form = QtWidgets.QFormLayout()
        form.addRow("Representative:", self.rep_combo)
        form.addRow("Client First Name:", self.client_first_edit)
        form.addRow("Client Last Name:", self.client_last_edit)
        form.addRow("Client Email:", self.client_email_edit)
        form.addRow("Client Phone:", self.client_phone_edit)
        form.addRow("Date:", self.date_edit)
        form.addRow("Time:", self.time_edit)
        form.addRow("Reason:", self.reason_edit)
        form.addRow("School Preferences:", self.pref_edit)
        form.addRow("Notes:", self.notes_edit)
        form.addRow("", self.send_email_checkbox)        
        save_btn = QtWidgets.QPushButton("Save")
        cancel_btn = QtWidgets.QPushButton("Cancel")
        btn_layout = QtWidgets.QHBoxLayout()
        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(cancel_btn)
        main_layout = QtWidgets.QVBoxLayout(self)
        main_layout.addLayout(form)
        main_layout.addLayout(btn_layout)
        save_btn.clicked.connect(self.save)
        cancel_btn.clicked.connect(self.reject)
        if appointment:
            self.load()


    def load(self):
        a = self.appointment
        self.original_date = a.appointment_date
        self.original_time = a.appointment_time       
        idx = self.rep_combo.findText(a.representative_name)
        if idx >= 0:
            self.rep_combo.setCurrentIndex(idx)
        self.client_first_edit.setText(a.client_first_name)
        self.client_last_edit.setText(a.client_last_name)
        self.client_email_edit.setText(a.client_email)
        self.client_phone_edit.setText(a.client_phone)
        self.date_edit.setDate(QtCore.QDate.fromString(a.appointment_date, 'yyyy-MM-dd'))
        
        # Directly set the time using QTime.fromString
        # Ensure the time format matches the database format
        time_obj = QtCore.QTime.fromString(a.appointment_time, 'HH:mm:ss')
        if not time_obj.isValid():
            # Try alternative format if the first one fails
            time_obj = QtCore.QTime.fromString(a.appointment_time, 'HH:mm')

        if time_obj.isValid():
            self.time_edit.setTime(time_obj)  # Set the valid QTime object
        else:
            logging.warning(f"Invalid time format for appointment ID {a.appointment_id}: {a.appointment_time}")
            self.time_edit.setTime(QtCore.QTime(0, 0))  # Set to a default value if invalid
        self.reason_edit.setPlainText(a.reason)
        self.pref_edit.setPlainText(a.school_preferences)
        self.notes_edit.setPlainText(a.notes)



    def save(self):
        ids.record_event(self.rep_combo.currentText(), "create appointment")
        if not all([self.rep_combo.currentText().strip(),
                    self.client_first_edit.text().strip(),
                    self.client_last_edit.text().strip(),
                    self.client_email_edit.text().strip(),
                    self.client_phone_edit.text().strip()]):
            QtWidgets.QMessageBox.warning(self, "Validation Error", "Representative and client fields are required.")
            return
        # Validate appointment date
        appointment_date = self.date_edit.date().toString('yyyy-MM-dd')
        if not is_valid_appointment_date(appointment_date):
            QtWidgets.QMessageBox.warning(self, "Validation Error", "Appointments cannot be created for past dates.")
            return

        # Validate appointment time
        appointment_time = self.time_edit.time().toString('HH:mm')
        current_time = QtCore.QTime.currentTime()
        
        if appointment_date == datetime.now().date().strftime('%Y-%m-%d') and \
        QtCore.QTime.fromString(appointment_time, 'HH:mm') < current_time:
            QtWidgets.QMessageBox.warning(self, "Validation Error", "Appointments cannot be scheduled in the past.")
            return
         
        # Validate email
        email = self.client_email_edit.text().strip()
        if not is_valid_email(email):
            QtWidgets.QMessageBox.warning(self, "Validation Error", "Invalid email format.")
            return
        # Validate phone number
        phone = self.client_phone_edit.text().strip()
        if not is_valid_phone(phone):
            QtWidgets.QMessageBox.warning(self, "Validation Error", "Invalid phone number.")
            return
        


        a = Appointment(
        appointment_id=(self.appointment.appointment_id if self.appointment else None),
        representative_name=sanitize_input(self.rep_combo.currentText().strip()),
        client_first_name=sanitize_input(self.client_first_edit.text().strip()),
        client_last_name=sanitize_input(self.client_last_edit.text().strip()),
        client_email=email,  # Use the validated email
        client_phone=phone,   # Use the validated phone
        appointment_date=appointment_date,
        appointment_time=self.time_edit.time().toString('HH:mm'),
        reason=sanitize_reason(self.reason_edit.toPlainText()),  # Use the new reason sanitizer
        school_preferences=sanitize_reason(self.pref_edit.toPlainText()),
        notes=sanitize_reason(self.notes_edit.toPlainText())
        )
        self.appointment = a        
        self.accept()
class UserManagementDialog(QtWidgets.QDialog):
    def __init__(self, current_user):
        super().__init__()
        self.setWindowTitle("User Management")
        self.resize(600, 400)
        self.current_user = current_user
        self.db = DatabaseManager()
        self.table = QtWidgets.QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["User ID", "Username", "Role", "Actions"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        is_admin = (self.current_user.role == ROLE_ADMIN)
        if is_admin:
            self.username_input = QtWidgets.QLineEdit()
            self.password_input = QtWidgets.QLineEdit()
            self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
            self.email_input = QtWidgets.QLineEdit()  # ✅ New email input field
            self.email_input.setPlaceholderText("user@example.com")
            self.role_combo = QtWidgets.QComboBox()
            self.role_combo.addItems([ROLE_USER, ROLE_ADMIN])
            self.add_btn = QtWidgets.QPushButton("Add User")
            self.add_btn.clicked.connect(self.add_user)
            form = QtWidgets.QFormLayout()
            form.addRow("Username:", self.username_input)
            form.addRow("Password:", self.password_input)
            form.addRow("Email:", self.email_input)  # ✅ Add email to the form
            form.addRow("Role:", self.role_combo)
            h = QtWidgets.QHBoxLayout()
            h.addLayout(form)
            h.addWidget(self.add_btn)
        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self.table)
        if is_admin:
            layout.addLayout(h)
        self.setLayout(layout)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {background_color};
                color: {text_color};
            }}
            QLabel {{
                color: {text_color};
            }}
            QLineEdit {{
                border: 1px solid #CCCCCC;
                border-radius: 4px;
                padding: 4px;
                background-color: {background_color};
                color: {text_color};
            }}
            QPushButton {{
                background-color: {button_color};
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: {button_hover_color};
            }}
        """)

        self.load_users()
    def load_users(self):
        self.table.setRowCount(0)
        for user in self.db.get_all_users():
            if self.current_user.role != ROLE_ADMIN and user.user_id != self.current_user.user_id:
                continue
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(str(user.user_id)))
            self.table.setItem(row, 1, QtWidgets.QTableWidgetItem(user.username))
            self.table.setItem(row, 2, QtWidgets.QTableWidgetItem(user.role))
            edit_btn = QtWidgets.QPushButton("Change Password")
            edit_btn.clicked.connect(lambda _, uid=user.user_id: self.change_password(uid))
            cell = QtWidgets.QWidget()
            hl = QtWidgets.QHBoxLayout(cell)
            hl.addWidget(edit_btn)
            hl.setContentsMargins(0, 0, 0, 0)
            if self.current_user.role == ROLE_ADMIN and user.user_id != self.current_user.user_id:
                del_btn = QtWidgets.QPushButton("Delete")
                del_btn.clicked.connect(lambda _, uid=user.user_id, name=user.username: self.delete_user(uid, name))
                hl.addWidget(del_btn)
            self.table.setCellWidget(row, 3, cell)
    def add_user(self):
        def is_valid_username(username):
            return re.match(r"^[a-zA-Z0-9_.-]{3,32}$", username)        
        def is_strong_password(password):
            return (
                len(password) >= 8 and
                re.search(r'[A-Z]', password) and
                re.search(r'[a-z]', password) and
                re.search(r'\d', password) and
                re.search(r'[!@#$%^&*(),.?":{}|<>]', password)
            )       
        def is_valid_email(email):
            return re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email)
        u = sanitize_input(self.username_input.text().strip())
        p = self.password_input.text()
        r = self.role_combo.currentText()
        e = sanitize_input(self.email_input.text().strip())
        if not u or not p:
            QtWidgets.QMessageBox.warning(self, "Input Error", "Please fill username and password.")
            return
        if not is_valid_username(u):
            QtWidgets.QMessageBox.warning(self, "Validation Error", "Username must be 3–32 characters long and contain only letters, numbers, dots, underscores, or hyphens.")
            return       
        if not is_strong_password(p):
            QtWidgets.QMessageBox.warning(self, "Weak Password",
                                      "Password must be at least 8 characters long and include an uppercase letter, a lowercase letter, a number, and a special character.")
            return        
        if not is_valid_email(e):
            QtWidgets.QMessageBox.warning(self, "Invalid Email", "Please enter a valid email address.")
            return   
        otp_dialog = OTPVerificationDialog(e, u, "register")
        if otp_dialog.exec_() == QtWidgets.QDialog.Accepted:
            ok, err = self.db.add_user(u, p, e, r)  # Updated to include email
            if not ok:
                logging.error(f"Failed to add user '{u}': {err}")
                QtWidgets.QMessageBox.warning(self, "Error", err)
                return
            logging.info(f"User '{u}' added and verified by {self.current_user.username}")
            QtWidgets.QMessageBox.information(self, "Success", "User added successfully.")
            self.username_input.clear()
            self.password_input.clear()                
            self.email_input.clear()
            self.load_users()
        else:
            self.db.delete_user_by_username(u)  # We need to add this method to DatabaseManager
            logging.warning(f"User '{u}' registration canceled - OTP verification failed")
            QtWidgets.QMessageBox.warning(self, "Registration Incomplete", 
                    "User registration was not completed. The verification code was not confirmed.")
    def change_password(self, user_id):
        new_pwd, ok = QtWidgets.QInputDialog.getText(
            self, "Change Password", "Enter new password:", QtWidgets.QLineEdit.Password
        )
        if ok and new_pwd:
            if not is_strong_password(new_pwd):
                QtWidgets.QMessageBox.warning(
                    self, "Weak Password",
                    "Password must be at least 8 characters long and include an uppercase letter, a lowercase letter, a number, and a special character."
            )
                logging.warning(f"Rejected weak password change for user ID {user_id} by {self.current_user.username}")
                return
            self.db.update_user_password(user_id, new_pwd)
            QtWidgets.QMessageBox.information(self, "Success", "Password updated.")
            logging.info(f"Password changed for user ID {user_id} by {self.current_user.username}")
    def delete_user(self, user_id, username):
        reply = QtWidgets.QMessageBox.question(
            self, "Confirm Delete",
            f"Delete user '{username}'?",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No
        )
        if reply == QtWidgets.QMessageBox.Yes:
            self.db.delete_user(user_id)
            self.load_users()
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, current_user):
        super().__init__()
        self.setWindowTitle("Pyramid Education Manager")
        self.setWindowFlags(QtCore.Qt.Window | QtCore.Qt.WindowTitleHint | QtCore.Qt.WindowSystemMenuHint | QtCore.Qt.WindowMinMaxButtonsHint)
        self.showFullScreen()
        self.current_user = current_user
        self.db = DatabaseManager()
        self.reminder_service = ReminderService(self.db)
        self.reminder_service.start()
        self.active_filters = {}
        self.selected_appointment_id = None



        # Setup central widget and main layout
        central = QtWidgets.QWidget()
        main_layout = QtWidgets.QVBoxLayout(central)
        
        # Set white background and style
        self.setStyleSheet(f"""
                QMainWindow, QWidget {{
                    background-color: {background_color};
                    color: {text_color};
                }}
                QPushButton {{
                    background-color: {button_color};
                    color: white;
                    border: none;
                    padding: 8px 16px;
                    border-radius: 4px;
                }}
                QPushButton:hover {{
                    background-color: {button_hover_color};
                }}
                QLineEdit {{
                    border: 1px solid #CCCCCC;
                    border-radius: 4px;
                    padding: 6px;
                    background-color: {background_color};
                    color: {text_color};
                }}
                QTableWidget {{
                    border: 1px solid #DDDDDD;
                    gridline-color: #EEEEEE;
                }}
                QHeaderView::section {{
                    background-color: #F5F5F5;
                    border: 1px solid #DDDDDD;
                    padding: 4px;
                }}
                QMenu {{
                    background-color: {background_color};
                    border: 1px solid #CCCCCC;
                }}
                QMenu::item {{
                    padding: 6px 20px;
                }}
                QMenu::item:selected {{
                    background-color: {button_color};
                    color: white;
                }}
            """)
            

        # Setup central widget and main layout
        central = QtWidgets.QWidget()
        main_layout = QtWidgets.QVBoxLayout(central)
        
        # Search layout
        search_layout = QtWidgets.QHBoxLayout()
        self.search_input = QtWidgets.QLineEdit()
        self.search_input.setPlaceholderText("Search by client name, phone, or email...")
        search_btn = QtWidgets.QPushButton("Search")
        search_btn.setIcon(QtGui.QIcon.fromTheme("edit-find"))
        search_layout.addWidget(self.search_input)
        search_layout.addWidget(search_btn)
        
        # Filter display
        self.filter_display = QtWidgets.QLabel("")
        self.filter_display.setStyleSheet("color: #666666; font-style: italic;")
        
        # Table setup
        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(11)
        self.table.setHorizontalHeaderLabels([
            "ID", "Representative", "Client First", "Client Last", "Email", "Phone",
            "Date", "Time", "Reason", "School Preferences", "Notes"
        ])
        self.table.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(False)
        self.table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        self.table.doubleClicked.connect(self.handle_row_double_click)
        
        # Button layout
        btn_layout = QtWidgets.QHBoxLayout()
        if self.current_user.role == ROLE_ADMIN:  # Only show for admins
            add_btn = QtWidgets.QPushButton("Add Appointment")
            add_btn.clicked.connect(self.add_appointment)
            btn_layout.addWidget(add_btn)
        refresh_btn = QtWidgets.QPushButton("Refresh")
        filter_btn = QtWidgets.QPushButton("Filters")
        btn_layout.addWidget(filter_btn)
        btn_layout.addWidget(refresh_btn)
        btn_layout.addStretch()
        
        # Status bar setup
        self.statusBar().showMessage(f"Logged in as: {self.current_user.username} ({self.current_user.role})")
        
        # Setup menu bar
        menubar = self.menuBar()
        account_menu = menubar.addMenu('Account')
        change_pwd_action = QtWidgets.QAction('Change Password', self)
        logout_action = QtWidgets.QAction('Logout', self)
        account_menu.addAction(change_pwd_action)
        account_menu.addAction(logout_action)
        
        # Admin menu
        if self.current_user.role == ROLE_ADMIN:
            admin_menu = menubar.addMenu('Admin')
            user_mgmt_action = QtWidgets.QAction('User Management', self)
            admin_menu.addAction(user_mgmt_action)
            user_mgmt_action.triggered.connect(self.open_user_management)
        
        # Connect signals
        search_btn.clicked.connect(self.load_appointments)
        self.search_input.returnPressed.connect(self.load_appointments)
        # add_btn.clicked.connect(self.add_appointment)
        refresh_btn.clicked.connect(self.load_appointments)
        filter_btn.clicked.connect(self.open_filter_dialog)
        change_pwd_action.triggered.connect(self.change_own_password)
        logout_action.triggered.connect(self.logout)
        
        # Layout assembly
        main_layout.addLayout(search_layout)
        main_layout.addWidget(self.filter_display)
        main_layout.addWidget(self.table)
        main_layout.addLayout(btn_layout)
        self.setCentralWidget(central)

        self.setCentralWidget(central)

        # Load appointments on start
        self.load_appointments()
        
        # Log successful login
        logging.info(f"User '{self.current_user.username}' logged in successfully")
    
    def get_selected_id(self):
        """Retrieve the ID of the currently selected appointment."""
        selected_rows = self.table.selectionModel().selectedRows()
        if selected_rows:
            row = selected_rows[0].row()
            return int(self.table.item(row, 0).text())  # Assuming the ID is in the first column
        return None


    def show_context_menu(self, position):
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            return
            
        row = selected_rows[0].row()
        self.selected_appointment_id = int(self.table.item(row, 0).text())
        
        menu = QtWidgets.QMenu()
        menu.setStyleSheet("""...""")  # Keep your existing styles
        
        view_action = menu.addAction("View Details")
        
        if self.current_user.role == ROLE_USER:
            view_action.triggered.connect(self.view_appointment_details)
        elif self.current_user.role == ROLE_ADMIN:
            delete_action = menu.addAction("Delete Appointment")
            delete_action.triggered.connect(self.delete_appointment)  # Connect to delete function
            view_action.triggered.connect(self.view_appointment_details)
        
        # Show the menu at cursor position
        menu.exec_(self.table.viewport().mapToGlobal(position))



    def handle_row_double_click(self, index):
        row = index.row()
        self.selected_appointment_id = int(self.table.item(row, 0).text())
        self.view_appointment_details()
        
    def view_appointment_details(self):
        appointment_id = self.selected_appointment_id
        if not appointment_id:
            QtWidgets.QMessageBox.warning(self, "No Selection", "Please select an appointment to view.")
            return

        appointment = next((x for x in self.db.get_appointments() if x.appointment_id == appointment_id), None)
        if not appointment:
            QtWidgets.QMessageBox.warning(self, "Error", "Could not retrieve appointment details.")
            return

        # Create a dialog for viewing appointment details
        detail_dialog = QtWidgets.QDialog(self)
        detail_dialog.setWindowTitle("Appointment Details")
        detail_dialog.setFixedWidth(500)
        detail_dialog.setStyleSheet("""
            QDialog {
                background-color: white;
                color: #333333;
            }
            QLabel {
                color: #333333;
            }
            QGroupBox {
                font-weight: bold;
            }
            QTextEdit {
                border: 1px solid #CCCCCC;
                border-radius: 4px;
                background-color: #F9F9F9;
            }
            QPushButton {
                background-color: #4A90E2;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #3A80D2;
            }
        """)  # Keep your existing styles

        layout = QtWidgets.QVBoxLayout(detail_dialog)

        # Client info
        client_group = QtWidgets.QGroupBox("Client Information")
        client_layout = QtWidgets.QFormLayout()
        client_layout.addRow("Name:", QtWidgets.QLabel(f"{appointment.client_first_name} {appointment.client_last_name}"))
        # client_layout.addRow("Email:", QtWidgets.QLabel(appointment.client_email))
        # client_layout.addRow("Phone:", QtWidgets.QLabel(appointment.client_phone))
        client_group.setLayout(client_layout)

        self.client_email_edit = QtWidgets.QLineEdit(appointment.client_email)
        self.client_phone_edit = QtWidgets.QLineEdit(appointment.client_phone)
        client_layout.addRow("Email:", self.client_email_edit)
        client_layout.addRow("Phone:", self.client_phone_edit)

        # Appointment info
        appt_group = QtWidgets.QGroupBox("Appointment Details")
        appt_layout = QtWidgets.QFormLayout()

        appt_layout.addRow("ID:", QtWidgets.QLabel(str(appointment.appointment_id)))
        appt_layout.addRow("Representative:", QtWidgets.QLabel(appointment.representative_name))

        self.date_edit = QtWidgets.QDateEdit(QtCore.QDate.fromString(appointment.appointment_date, 'yyyy-MM-dd'))
        appt_layout.addRow("Date:", self.date_edit)

        self.time_edit = QtWidgets.QTimeEdit(QtCore.QTime.fromString(appointment.appointment_time, 'HH:mm:ss'))
        if not self.time_edit.time().isValid():
            # Try alternative format if the first one fails
            self.time_edit.setTime(QtCore.QTime.fromString(appointment.appointment_time, 'HH:mm'))
        appt_layout.addRow("Time:", self.time_edit)

        self.reason_edit = QtWidgets.QTextEdit()
        self.reason_edit.setPlainText(appointment.reason)
        appt_layout.addRow("Reason:", self.reason_edit)

        self.pref_edit = QtWidgets.QTextEdit()
        self.pref_edit.setPlainText(appointment.school_preferences)
        appt_layout.addRow("School Preferences:", self.pref_edit)

        self.notes_edit = QtWidgets.QTextEdit()
        self.notes_edit.setPlainText(appointment.notes)
        appt_layout.addRow("Notes and Feedback:", self.notes_edit)

        appt_group.setLayout(appt_layout)

        # Add groups to layout
        layout.addWidget(client_group)
        layout.addWidget(appt_group)

        # Buttons
        save_btn = QtWidgets.QPushButton("Save Changes")
        save_btn.clicked.connect(lambda: self.save_appointment_changes(appointment_id, detail_dialog))
        layout.addWidget(save_btn)

        close_btn = QtWidgets.QPushButton("Close")
        close_btn.clicked.connect(detail_dialog.close)
        layout.addWidget(close_btn)

        detail_dialog.exec_()



    def save_appointment_changes(self, appointment_id, detail_dialog):
        # Logic to save changes to the appointment
        appointment = next((x for x in self.db.get_appointments() if x.appointment_id == appointment_id), None)
        logging.info("appointment accepted, processing appointment update.")
        if self.current_user.role == ROLE_USER:
            logging.info("Dialog accepted, ROLE USER")
            new_notes = self.notes_edit.toPlainText()
            if appointment:
                appointment.notes = new_notes
                self.db.update_appointment(appointment)  # Update without old_appt
                QtWidgets.QMessageBox.information(self, "Success", "Feedback updated successfully.")
                self.load_appointments()
                detail_dialog.close()
        elif self.current_user.role == ROLE_ADMIN:
            logging.info("Dialog accepted, ROLE ADMIN")
            new_date = self.date_edit.date().toString('yyyy-MM-dd')
            new_time = self.time_edit.time().toString('HH:mm')
            new_reason = self.reason_edit.toPlainText()
            new_preferences = self.pref_edit.toPlainText()
            new_notes = self.notes_edit.toPlainText()
            new_email = self.client_email_edit.text().strip()  # Get updated email
            new_phone = self.client_phone_edit.text().strip()  # Get updated phone
            logging.info("GOT ALL")
            if appointment:
                appointment.appointment_date = new_date
                appointment.appointment_time = new_time
                appointment.reason = new_reason
                appointment.school_preferences = new_preferences
                appointment.notes = new_notes
                appointment.client_email = new_email  # Update email
                appointment.client_phone = new_phone  # Update phone
                logging.info("CHANGED")
                # Pass the original appointment as old_appt
                self.db.update_appointment(appointment, old_appt=appointment)  # Pass the original appointment
                QtWidgets.QMessageBox.information(self, "Success", "Appointment updated successfully.")
                self.load_appointments()
                detail_dialog.close()



    def open_filter_dialog(self):
        filter_dialog = FilterDialog(self.db, self.current_user)
        
        if filter_dialog.exec_() == QtWidgets.QDialog.Accepted:
            self.active_filters = filter_dialog.get_filter_params()
            self.load_appointments()
            self.update_filter_display()
            
            # Log filter application
            filter_summary = ", ".join([f"{k}:{v}" for k, v in self.active_filters.items()])
            logging.info(f"User '{self.current_user.username}' applied filters: {filter_summary}")
            
    def clear_filters(self):
        self.active_filters = {}
        self.search_input.clear()
        self.filter_display.setText("")
        self.load_appointments()
        
        logging.info(f"User '{self.current_user.username}' cleared all filters")
        
    def update_filter_display(self):
        if not self.active_filters:
            self.filter_display.setText("")
            return
            
        filter_text = "Active Filters: "
        filters = []
        
        if 'start_date' in self.active_filters and self.active_filters['start_date']:
            if 'end_date' in self.active_filters and self.active_filters['end_date']:
                filters.append(f"Date Range {self.active_filters['start_date']} to {self.active_filters['end_date']}")
            else:
                filters.append(f"From {self.active_filters['start_date']}")
        elif 'end_date' in self.active_filters and self.active_filters['end_date']:
            filters.append(f"Until {self.active_filters['end_date']}")
            
        if 'representative' in self.active_filters and self.active_filters['representative']:
            filters.append(f"Rep: {self.active_filters['representative']}")
            
        if 'keyword' in self.active_filters and self.active_filters['keyword']:
            filters.append(f"Keyword: '{self.active_filters['keyword']}'")
            
        self.filter_display.setText(filter_text + ", ".join(filters))
        
    def load_appointments(self):
        text = self.search_input.text().strip()
        if not text:
            text = None
        else:
            try:
                text = sanitize_input(text)  # Sanitize the input
            except ValueError as e:
                QtWidgets.QMessageBox.warning(self, "Input Error", str(e))
                return 
        
        try:
            if self.current_user.role != ROLE_ADMIN:
                appts = self.db.get_appointments(search_filter=text, username=self.current_user.username, filter_params=self.active_filters)
            else: 
                appts = self.db.get_appointments(search_filter=text, filter_params=self.active_filters)
                
            self.table.setRowCount(0)
            
            for a in appts:
                row = self.table.rowCount()
                self.table.insertRow(row)
                
                # Format date and time for display
                date_obj = QtCore.QDate.fromString(a.appointment_date, 'yyyy-MM-dd')
                formatted_date = date_obj.toString('MM/dd/yyyy')
                
                time_obj = QtCore.QTime.fromString(a.appointment_time, 'HH:mm:ss')  # Ensure the correct format
                formatted_time = time_obj.toString('hh:mm AP')  # Format to 12-hour format
                
                # Prepare row values
                values = [
                    str(a.appointment_id), 
                    a.representative_name,
                    a.client_first_name, 
                    a.client_last_name,
                    a.client_email, 
                    a.client_phone,
                    formatted_date, 
                    formatted_time, 
                    a.reason, 
                    a.school_preferences, 
                    a.notes
                ]
                
                # Truncate long text fields for better display
                for col, val in enumerate(values):
                    item = QtWidgets.QTableWidgetItem(val[:100] + '...' if col > 7 and len(val) > 100 else val)
                    self.table.setItem(row, col, item)
                    
            logging.info(f"Loaded {self.table.rowCount()} appointments for user '{self.current_user.username}'")
            self.statusBar().showMessage(f"Loaded {self.table.rowCount()} appointments")
                
        except Exception as e:
            logging.error(f"Error loading appointments: {str(e)}")
            self.statusBar().showMessage(f"Error loading appointments: {str(e)}")
            QtWidgets.QMessageBox.critical(self, "Database Error", f"Failed to load appointments: {str(e)}")


    def change_own_password(self):
        action_allowed = ids.record_event(self.current_user.username, "password change")
        
        if not action_allowed:
            QtWidgets.QMessageBox.warning(self, "Action Restricted", 
                "This action has been blocked for security reasons. Please try again later or contact an administrator.")
            logging.warning(f"Password change attempt blocked for user '{self.current_user.username}' due to rate limiting")
            return
            
        new_pwd, ok = QtWidgets.QInputDialog.getText(
            self,
            "Change Password",
            "Enter new password:",
            QtWidgets.QLineEdit.Password
        )
        
        if ok and new_pwd:
            if not is_strong_password(new_pwd):
                QtWidgets.QMessageBox.warning(
                    self, "Weak Password",
                    "Password must be at least 8 characters long and include an uppercase letter, a lowercase letter, a number, and a special character."
                )
                logging.warning(f"Rejected weak self-password change attempt by '{self.current_user.username}'")
                return
                
            try:
                self.db.update_user_password(self.current_user.user_id, new_pwd)
                QtWidgets.QMessageBox.information(self, "Success", "Password updated successfully.")
                logging.info(f"User '{self.current_user.username}' changed their password successfully")
            except Exception as e:
                logging.error(f"Password change failed for user '{self.current_user.username}': {str(e)}")
                QtWidgets.QMessageBox.critical(self, "Error", f"Failed to update password: {str(e)}")

    def add_appointment(self):
        action_allowed = ids.record_event(self.current_user.username, "create appointment")
        
        if not action_allowed:
            QtWidgets.QMessageBox.warning(self, "Action Restricted", 
                "This action has been blocked for security reasons. Please try again later or contact an administrator.")
            logging.warning(f"Appointment creation blocked for user '{self.current_user.username}' due to rate limiting")
            return
            
        dlg = AppointmentDialog()
        
        # Set the default representative to current user if not admin
        if self.current_user.role != ROLE_ADMIN:
            idx = dlg.rep_combo.findText(self.current_user.username)
            if idx >= 0:
                dlg.rep_combo.setCurrentIndex(idx)
                dlg.rep_combo.setEnabled(False)  # Lock the field for regular users
        
        if dlg.exec_():
            try:
                appointment_id = self.db.add_appointment(dlg.appointment)
                logging.info(f"Appointment added by '{self.current_user.username}' for client '{dlg.appointment.client_first_name} {dlg.appointment.client_last_name}'")
                self.load_appointments()
                
                if dlg.send_email_checkbox.isChecked() and dlg.appointment.client_email:
                    appointment = next((x for x in self.db.get_appointments() 
                                if x.appointment_id == appointment_id), None)
                    if appointment:
                        subject, html_content = get_appointment_created_email(appointment)
                        if send_email(appointment.client_email, subject, html_content):
                            logging.info(f"Confirmation email sent to {appointment.client_email}")
                        else:
                            logging.error(f"Failed to send confirmation email to {appointment.client_email}")
                            QtWidgets.QMessageBox.warning(self, "Email Error", 
                                                    "Appointment saved but email notification failed.")
                
                self.load_appointments()
                QtWidgets.QMessageBox.information(self, "Success", "Appointment added successfully.")
                
            except Exception as e:
                logging.error(f"Error adding appointment: {str(e)}")
                QtWidgets.QMessageBox.critical(self, "Error", f"Failed to add appointment: {str(e)}")


    def delete_appointment(self):
        appt_id = self.get_selected_id()
        
        if not appt_id:
            QtWidgets.QMessageBox.warning(self, "Select Appointment", "Please select an appointment to delete.")
            return
            
        if self.current_user.role != ROLE_ADMIN:
            QtWidgets.QMessageBox.warning(self, "Access Denied", "Only administrators can delete appointments.")
            logging.warning(f"User  '{self.current_user.username}' attempted to delete appointment without permission")
            return
            
        action_allowed = ids.record_event(self.current_user.username, "delete appointment")
        
        if not action_allowed:
            QtWidgets.QMessageBox.warning(self, "Action Restricted", 
                "This action has been blocked for security reasons. Please try again later or contact an administrator.")
            logging.warning(f"Appointment deletion blocked for user '{self.current_user.username}' due to rate limiting")
            return
            
        appointment = next((x for x in self.db.get_appointments() if x.appointment_id == appt_id), None)
        
        if not appointment:
            QtWidgets.QMessageBox.warning(self, "Error", "Could not retrieve appointment details.")
            return
            
        # Create a confirmation dialog
        confirmation_dialog = QtWidgets.QDialog(self)
        confirmation_dialog.setWindowTitle("Confirm Delete")
        confirmation_dialog.setFixedWidth(400)
        confirmation_dialog.setStyleSheet("""...""")  # Keep your existing styles
        
        layout = QtWidgets.QVBoxLayout(confirmation_dialog)
        
        # Add appointment information to confirm what's being deleted
        info_text = f"Are you sure you want to delete this appointment?\n\n" \
                    f"Client: {appointment.client_first_name} {appointment.client_last_name}\n" \
                    f"Date: {appointment.appointment_date}\n" \
                    f"Time: {appointment.appointment_time}\n" \
                    f"Representative: {appointment.representative_name}"
                    
        message = QtWidgets.QLabel(info_text)
        message.setWordWrap(True)
        layout.addWidget(message)
        
        send_email_checkbox = QtWidgets.QCheckBox("Send cancellation email to client")
        send_email_checkbox.setChecked(True)  # Default to sending email
        layout.addWidget(send_email_checkbox)
        
        # Create buttons for confirmation
        buttons = QtWidgets.QDialogButtonBox(confirmation_dialog)
        cancel_button = buttons.addButton("Cancel", QtWidgets.QDialogButtonBox.RejectRole)  # Correctly add Cancel button
        delete_button = buttons.addButton("Delete", QtWidgets.QDialogButtonBox.DestructiveRole)  # Correctly add Delete button
        
        layout.addWidget(buttons)
        
        # Connect the delete button to the confirm_delete method
        delete_button.clicked.connect(lambda: self.confirm_delete(appt_id, send_email_checkbox.isChecked(), confirmation_dialog))
        
        # Connect the cancel button to close the dialog
        cancel_button.clicked.connect(confirmation_dialog.close)
        
        confirmation_dialog.exec_()

    def confirm_delete(self, appt_id, should_send_email, confirmation_dialog):
        # Get appointment details BEFORE deleting it
        appointment = next((x for x in self.db.get_appointments() if x.appointment_id == appt_id), None)
        
        # Store email information before deletion
        client_email = appointment.client_email if appointment else None
        
        # Perform the deletion
        self.db.delete_appointment(appt_id)
        
        # Send cancellation email if checked
        if should_send_email and appointment and client_email:
            subject, html_content = get_appointment_cancelled_email(appointment)
            
            # Use the imported send_email function from email_module.py
            # from email_module import send_email
            if send_email(client_email, subject, html_content):
                logging.info(f"Cancellation email sent to {client_email}")
            else:
                logging.error(f"Failed to send cancellation email to {client_email}")
                QtWidgets.QMessageBox.warning(self, "Email Error", 
                                        "Appointment deleted but email notification failed.")
        
        self.load_appointments()  # Refresh the appointment list
        confirmation_dialog.close()


    def open_user_management(self):
        dlg = UserManagementDialog(self.current_user)
        dlg.exec_()  
    def logout(self):
        app = QtWidgets.QApplication.instance()
        if hasattr(self, 'reminder_service'):
            self.reminder_service.stop()
        self.close()
        self.db = DatabaseManager() 
        login = LoginDialog()
        if login.exec_() == QtWidgets.QDialog.Accepted:
            self.current_user = login.user
            self.statusBar().showMessage(f"Logged in as: {self.current_user.username} ({self.current_user.role})")
            self.load_appointments()
            self.show()
        else:
            app.quit()
def set_modern_style(app):
    app.setStyle('Fusion')
    palette = QtGui.QPalette()
    palette.setColor(QtGui.QPalette.Window, QtGui.QColor(53,53,53))
    palette.setColor(QtGui.QPalette.WindowText, QtCore.Qt.white)
    palette.setColor(QtGui.QPalette.Base, QtGui.QColor(35,35,35))
    palette.setColor(QtGui.QPalette.AlternateBase, QtGui.QColor(53,53,53))
    palette.setColor(QtGui.QPalette.ToolTipBase, QtCore.Qt.white)
    palette.setColor(QtGui.QPalette.ToolTipText, QtCore.Qt.white)
    palette.setColor(QtGui.QPalette.Text, QtCore.Qt.white)
    palette.setColor(QtGui.QPalette.Button, QtGui.QColor(53,53,53))
    palette.setColor(QtGui.QPalette.ButtonText, QtCore.Qt.white)
    palette.setColor(QtGui.QPalette.BrightText, QtCore.Qt.red)
    palette.setColor(QtGui.QPalette.Highlight, QtGui.QColor(42,130,218))
    palette.setColor(QtGui.QPalette.HighlightedText, QtCore.Qt.black)
    app.setPalette(palette)
def initialize_email_settings():
    if not os.getenv("EMAIL_USERNAME") or not os.getenv("EMAIL_PASSWORD"):
        logging.warning("Email credentials not configured. Email notifications will be disabled.")
        QtWidgets.QMessageBox.warning(
            None, "Email Configuration", 
            "Email credentials are not configured. Email notifications will be disabled. "
            "Please set EMAIL_USERNAME and EMAIL_PASSWORD in your .env file."
        )
        return False  
    if os.getenv("EMAIL_ENABLED", "True").lower() != "true":
        logging.info("Email notifications are disabled via configuration.")
        return False
    
    if not os.getenv("SECURITY_ALERT_EMAIL"):
        logging.warning("Security alert email not configured. Security alerts will only be logged.")
        QtWidgets.QMessageBox.warning(
            None, "Security Alert Configuration", 
            "Security alert email is not configured. Security alerts will only be logged. "
            "Please set SECURITY_ALERT_EMAIL in your .env file to receive email alerts."
        )
    
    logging.info("Email configuration loaded successfully.")
    return True
def main():

    app = QtWidgets.QApplication(sys.argv)
    set_modern_style(app)

    initialize_email_settings()
    login = LoginDialog()
    if login.exec_() == QtWidgets.QDialog.Accepted:
        window = MainWindow(login.user)
        window.show()
        sys.exit(app.exec_())
if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    set_modern_style(app)
    login = LoginDialog()
    if login.exec_() == QtWidgets.QDialog.Accepted:
        window = MainWindow(login.user)
        window.show()
        sys.exit(app.exec_())