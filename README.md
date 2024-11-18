# FileIntegrity
File Integrity Monitor: Real-Time Directory Surveillance with Automated Alerts and Backup/Restore Capabilities

Overview

This Python application, FileIntegrityMonitor, is designed to vigilantly monitor a specified directory for any file modifications, deletions, or unauthorized additions.
Upon detecting changes, it swiftly alerts designated managers via SMS (utilizing Twilio services) and logs all events.
For altered files, it backs up the modified version and, if a backup of the original file exists, automatically restores it.

Key Features:

Real-Time Monitoring: Continuously scans the specified directory for changes.
Automated Alerts: Sends detailed SMS alerts to managers for:
Altered Files: Includes expected and current timestamps.
Deleted Files: Lists deleted file paths.
Newly Added Files: Identifies and automatically deletes unauthorized additions.
Backup and Restore:
Altered File Backup: Saves the modified file version.
Automatic Restore: Reverts altered files to their original state if a backup exists.
Comprehensive Logging: Records all events (alterations, deletions, new files) in a specified log file, including timestamps.

Configuration Requirements:
Directory Path: The folder to be monitored.
Backup Directory Path: Location for storing file backups.
Log File Path: Destination for event logs.
Manager's Phone Number: For receiving SMS alerts.

Twilio Credentials:
Account SID
Auth Token
Twilio Phone Number (for sending SMS alerts)
Technical Details:

Hashing Algorithm: SHA-256 for file integrity checks.
Monitoring Interval: 30 seconds (configurable via time.sleep()).
Dependencies:
hashlib for hashing
os and shutil for file operations
twilio for SMS services
tkinter for initial monitoring confirmation dialog (hidden window)
datetime for timestamp formatting

Usage:
Configure the required paths and credentials at the bottom of the script.
Run the script. A hidden window will briefly appear, confirming the start of monitoring.
The application will continuously monitor the specified directory, triggering actions as outlined above upon detecting changes.
