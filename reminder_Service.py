import threading
import time
import logging
import datetime
from email_module import send_email

# How often to check for upcoming appointments (in seconds)
CHECK_INTERVAL = 3600  # 1 hour for production
DEBUG_CHECK_INTERVAL = 60  # 1 minute for debugging

def get_appointment_reminder_email(appointment):
    """
    Generate email content for appointment reminder.
    """
    subject = "Reminder: Your Pyramid Education Appointment Tomorrow"
    
    html_content = f"""
    <html>
    <body>
        <h2>Reminder: Your appointment with Pyramid Education is tomorrow</h2>
        <p>Dear {appointment.client_first_name} {appointment.client_last_name},</p>
        <p>This is a friendly reminder that you have an appointment scheduled with Pyramid Education:</p>
        
        <ul>
            <li><strong>Date:</strong> {appointment.appointment_date}</li>
            <li><strong>Time:</strong> {appointment.appointment_time}</li>
            <li><strong>Representative:</strong> {appointment.representative_name}</li>
            <li><strong>Reason:</strong> {appointment.reason}</li>
        </ul>
        
        <p>If you need to reschedule or have any questions, please contact us as soon as possible.</p>
        <p>We look forward to meeting with you!</p>
        <p>Sincerely,<br>The Pyramid Education Team</p>
    </body>
    </html>
    """
    
    return subject, html_content

class ReminderService:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.running = False
        self.reminder_thread = None
        self.reminder_log = set()  # Track already sent reminders
        self.debug_mode = True  # Enable more frequent checks and additional logging

    def start(self):
        """Start the reminder service"""
        if self.running:
            logging.info("Reminder service already running")
            return
            
        self.running = True
        self.reminder_thread = threading.Thread(target=self._reminder_loop, daemon=True)
        self.reminder_thread.start()
        logging.info("Appointment reminder service started successfully")
        
        # Immediate first check for debugging
        if self.debug_mode:
            threading.Thread(target=self._check_and_send_reminders, daemon=True).start()

    def stop(self):
        """Stop the reminder service"""
        if not self.running:
            return
            
        logging.info("Stopping reminder service...")
        self.running = False
        if self.reminder_thread and self.reminder_thread.is_alive():
            try:
                self.reminder_thread.join(timeout=2.0)
                logging.info("Reminder service stopped gracefully")
            except Exception as e:
                logging.error(f"Error stopping reminder thread: {str(e)}")
        else:
            logging.info("No active reminder thread to stop")

    def _reminder_loop(self):
        """Main loop to check for and send reminders"""
        logging.info("Reminder service loop started")
        check_count = 0
        
        while self.running:
            try:
                check_count += 1
                logging.info(f"Performing reminder check #{check_count}")
                self._check_and_send_reminders()
            except Exception as e:
                logging.error(f"Error in reminder service: {str(e)}")
            
            # Sleep for the check interval
            interval = DEBUG_CHECK_INTERVAL if self.debug_mode else CHECK_INTERVAL
            logging.info(f"Reminder service sleeping for {interval} seconds")
            
            # Break the sleep into smaller chunks so we can exit quickly if needed
            sleep_chunk = 5  # 5 seconds per chunk
            for _ in range(interval // sleep_chunk):
                if not self.running:
                    break
                time.sleep(sleep_chunk)
            
            # Sleep any remaining time
            if self.running and interval % sleep_chunk:
                time.sleep(interval % sleep_chunk)

    def _check_and_send_reminders(self):
        """Check for appointments within the reminder window and send reminders"""
        logging.info("Checking for appointments requiring reminder emails...")
        
        # Get tomorrow's date in yyyy-mm-dd format
        tomorrow = (datetime.datetime.now() + datetime.timedelta(days=1)).strftime('%Y-%m-%d')
        logging.info(f"Looking for appointments on {tomorrow}")
        
        try:
            # Get all appointments
            all_appointments = self.db_manager.get_appointments()
            logging.info(f"Retrieved {len(all_appointments)} total appointments")
            
            # Filter for tomorrow's appointments
            tomorrow_appointments = [
                appt for appt in all_appointments 
                if appt.appointment_date == tomorrow
            ]
            
            logging.info(f"Found {len(tomorrow_appointments)} appointments scheduled for tomorrow")
            
            # Process each appointment for tomorrow
            for appointment in tomorrow_appointments:
                # Create a unique identifier for this appointment reminder
                reminder_id = f"{appointment.appointment_id}_{appointment.appointment_date}"
                
                # Check if reminder already sent
                if reminder_id in self.reminder_log:
                    logging.info(f"Reminder already sent for appointment {appointment.appointment_id}")
                    continue
                
                # Log the appointment we're processing
                logging.info(f"Processing reminder for appointment {appointment.appointment_id}: "
                            f"{appointment.client_first_name} {appointment.client_last_name}, "
                            f"date: {appointment.appointment_date}, time: {appointment.appointment_time}")
                
                # Send reminder email
                if appointment.client_email:
                    subject, html_content = get_appointment_reminder_email(appointment)
                    logging.info(f"Attempting to send reminder to {appointment.client_email}")
                    
                    if send_email(appointment.client_email, subject, html_content):
                        logging.info(f" Reminder email successfully sent to {appointment.client_email} "
                                    f"for appointment on {appointment.appointment_date}")
                        # Mark as sent
                        self.reminder_log.add(reminder_id)
                    else:
                        logging.error(f" Failed to send reminder email to {appointment.client_email}")
                else:
                    logging.warning(f"No email address available for client {appointment.client_first_name} "
                                  f"{appointment.client_last_name} (appointment {appointment.appointment_id})")
            
            # Clean up reminder log (remove old entries)
            self._cleanup_reminder_log()
            
        except Exception as e:
            logging.error(f"Error during reminder check: {str(e)}", exc_info=True)
    
    def _cleanup_reminder_log(self):
        """Remove entries from reminder log older than 3 days"""
        today = datetime.datetime.now()
        three_days_ago = (today - datetime.timedelta(days=3)).strftime('%Y-%m-%d')
        
        to_remove = set()
        orig_count = len(self.reminder_log)
        
        for reminder_id in self.reminder_log:
            try:
                appt_id, appt_date = reminder_id.split('_')
                if appt_date < three_days_ago:
                    to_remove.add(reminder_id)
            except Exception:
                # If we can't parse it, remove it
                to_remove.add(reminder_id)
        
        self.reminder_log -= to_remove
        
        if to_remove:
            logging.info(f"Cleaned up reminder log: removed {len(to_remove)} old entries, "
                        f"{len(self.reminder_log)} entries remaining")