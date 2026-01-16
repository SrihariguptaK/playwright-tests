# Manual Test Cases

## Story: As HR Specialist, I want to schedule automated attendance report generation to ensure timely distribution
**Story ID:** story-9

### Test Case: Create and save attendance report schedule
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as an authorized HR Specialist
- User has access to attendance report scheduling features
- Attendance data exists in the system
- At least one valid recipient email address is available
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance reports section from the main dashboard | Attendance reports page is displayed with scheduling options visible |
| 2 | Click on 'Schedule Report' or 'Create Schedule' button | Scheduling interface is displayed with empty form fields for schedule configuration |
| 3 | Enter a descriptive name for the scheduled report (e.g., 'Weekly Attendance Summary') | Report name is accepted and displayed in the name field |
| 4 | Select report frequency from dropdown (Daily, Weekly, or Monthly) | Selected frequency is displayed and appropriate additional fields appear (e.g., day of week for weekly, date for monthly) |
| 5 | Set the time for report generation (e.g., 08:00 AM) | Time is accepted and displayed in the time field in correct format |
| 6 | Select the start date for the schedule | Calendar picker opens, selected date is accepted and displayed |
| 7 | Enter recipient email addresses in the recipients field (e.g., hr@company.com, manager@company.com) | Email addresses are validated and displayed as tags or comma-separated list |
| 8 | Select report format (PDF, Excel, CSV) from available options | Selected format is highlighted and saved in the configuration |
| 9 | Review all entered schedule parameters on the form | All parameters are correctly displayed with no validation errors |
| 10 | Click 'Save Schedule' or 'Create Schedule' button | Success message is displayed (e.g., 'Schedule created successfully'), schedule appears in the list of scheduled reports with status 'Active' |
| 11 | Verify the schedule details in the scheduled reports list | New schedule is visible with correct name, frequency, time, recipients, and next execution date/time |

**Postconditions:**
- New attendance report schedule is saved in the system
- Schedule status is set to 'Active'
- Schedule appears in the list of scheduled reports
- System has queued the schedule for automated execution
- Audit log entry is created for schedule creation

---

### Test Case: Verify automated report delivery
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- A valid attendance report schedule has been created and saved
- Schedule is in 'Active' status
- Schedule is configured to run within the next few minutes for testing purposes
- Recipient email addresses are valid and accessible for verification
- Attendance data exists for the reporting period
- Email service is configured and operational
- User has access to recipient email inbox or email logs

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Note the scheduled execution time from the scheduled reports list | Next execution time is clearly displayed (e.g., 'Next run: 2024-01-15 08:00 AM') |
| 2 | Wait for the scheduled report generation time to arrive (monitor the system clock) | System time reaches the scheduled execution time |
| 3 | Refresh the scheduled reports page after the scheduled time has passed | Schedule status shows 'Last run' timestamp updated to the recent execution time, 'Next run' shows the next scheduled time |
| 4 | Navigate to the execution logs or report history section | Execution log entry is created showing successful report generation with timestamp and status 'Success' |
| 5 | Access the email inbox of the first configured recipient | Email inbox is accessible and displays list of received emails |
| 6 | Search for the attendance report email by subject line or sender | Attendance report email is found in the inbox with correct subject line (e.g., 'Weekly Attendance Summary - [Date]') |
| 7 | Open the attendance report email | Email opens successfully, displays professional formatting with report details in body or as attachment |
| 8 | Verify email contains the report attachment in the configured format | Report file is attached with correct format (PDF/Excel/CSV) and appropriate filename (e.g., 'Attendance_Report_2024-01-15.pdf') |
| 9 | Download and open the attached attendance report file | File downloads successfully and opens without errors in appropriate application |
| 10 | Review report content including headers, employee names, attendance dates, and status columns | Report displays complete and accurate attendance data with proper formatting, all expected columns are present |
| 11 | Verify report data matches the scheduled reporting period | Report date range matches the configured schedule (e.g., last 7 days for weekly report) |
| 12 | Cross-reference sample attendance records in the report with source data in the system | Report data matches system records exactly with no discrepancies in attendance status, dates, or employee information |
| 13 | Check email inbox of additional recipients (if multiple recipients configured) | All configured recipients have received the attendance report email with identical content |

**Postconditions:**
- Attendance report is successfully generated
- Report is delivered to all configured recipients via email
- Execution log shows successful completion with timestamp
- Schedule remains active for next execution
- Next execution time is updated in the schedule
- Report data is accurate and complete
- System audit log records the automated execution

---

