import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
from email_module import send_email

class IntrusionDetector:
    """Monitors application for suspicious activities and triggers alerts when thresholds are exceeded."""
    
    def __init__(self, rate_limit_count=5, rate_limit_window=timedelta(minutes=5), business_hours=(9, 17), alert_email=None):
        """
        Initialize the intrusion detector.
        
        Args:
            rate_limit_count: Number of actions within window to trigger rate limit alert
            rate_limit_window: Time window for rate limiting (timedelta)
            business_hours: Tuple of (start_hour, end_hour) for normal business operations
            alert_email: Email address to send security alerts to (if None, alerts only go to logs)
        """
        self.rate_limit_count = rate_limit_count
        self.rate_limit_window = rate_limit_window
        self.business_hours_start, self.business_hours_end = business_hours
        self.alert_email = alert_email
        
        # Track user actions with timestamps
        self.user_actions = defaultdict(lambda: deque(maxlen=100))
        
        # Track failed login attempts
        self.failed_logins = defaultdict(int)
        
        # Track consecutive failed login attempts
        self.consecutive_failed_logins = defaultdict(int)
        
        # Track alerts sent to avoid alert flooding
        self.alerts_sent = defaultdict(lambda: datetime.min)
        
        logging.info(f"Intrusion detector initialized with rate limit: {rate_limit_count} actions per {rate_limit_window}")
    
    def record_event(self, username, action_type):
        """
        Record a user action and check for suspicious patterns.
        
        Args:
            username: Username performing the action
            action_type: Type of action being performed
        
        Returns:
            bool: True if action is allowed, False if it should be blocked
        """
        current_time = datetime.now()
        
        # Record the action with timestamp
        self.user_actions[username].append((current_time, action_type))
        
        # Check for anomalies
        if action_type == "failed login":
            self.failed_logins[username] += 1
            self.consecutive_failed_logins[username] += 1
            if self.consecutive_failed_logins[username] >= 5:
                self._trigger_alert(username, "brute_force", f"Possible brute force attack detected for user {username}.")
        elif action_type in ["create appointment", "edit appointment", "delete appointment"]:
            if not self._check_appointment_anomaly(username):
                self._trigger_alert(username, "appointment_anomaly", f"Multiple appointment actions detected for user {username}.")

        # Reset consecutive failed logins on successful login
        if action_type == "login attempt":
            self.reset_consecutive_failed_logins(username)

        # Log the action
        logging.info(f"User  '{username}' performed action: {action_type}")
        return True
    
    def reset_consecutive_failed_logins(self, username):
        """Reset the consecutive failed login counter after successful login."""
        self.consecutive_failed_logins[username] = 0
    
    def _check_appointment_anomaly(self, username):
        """Check if user has exceeded appointment action limits."""
        current_time = datetime.now()
        cutoff_time = current_time - self.rate_limit_window
        recent_actions = [action for action in self.user_actions[username] if action[0] >= cutoff_time and action[1] in ["create appointment", "edit appointment", "delete appointment"]]
        return len(recent_actions) < self.rate_limit_count  # Return True if within limit

    def _trigger_alert(self, username, alert_type, message):
        """Trigger security alert via logs and email if configured."""
        current_time = datetime.now()
        
        # Prevent alert flooding - only send one alert per user per alert type per hour
        alert_key = f"{username}_{alert_type}"
        last_alert_time = self.alerts_sent[alert_key]
        if current_time - last_alert_time < timedelta(hours=1):
            # Already sent an alert of this type within the last hour
            logging.info(f"Suppressing duplicate alert for {alert_key}")
            return
        
        # Update last alert time
        self.alerts_sent[alert_key] = current_time
        
        # Always log the alert
        logging.warning(f"SECURITY ALERT: {message}")
        
        # Send email alert if configured
        if self.alert_email:
            self._send_security_alert_email(username, alert_type, message)
    
    def _send_security_alert_email(self, username, alert_type, message):
        """Send security alert email."""
        subject = f"Pyramid Education Security Alert: {alert_type}"
        
        html_content = f"""
        <html>
        <body>
            <h2>Security Alert: {alert_type}</h2>
            <p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>User:</strong> {username}</p>
            <p><strong>Alert Type:</strong> {alert_type}</p>
            <p><strong>Details:</strong> {message}</p>
            <p>This automated alert has been generated by the Pyramid Education intrusion detection system.</p>
        </body>
        </html>
        """
        
        try:
            send_email(self.alert_email, subject, html_content)
            logging.info(f"Security alert email sent to {self.alert_email}")
        except Exception as e:
            logging.error(f"Failed to send security alert email: {str(e)}")
