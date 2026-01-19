# Manual Test Cases

## Story: As HR Manager, I want to review attendance exception reports to identify anomalies and ensure compliance
**Story ID:** story-24

### Test Case: Validate generation of attendance exception reports
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- HR manager account exists with valid credentials
- HR manager has role-based access to reporting dashboard
- Attendance database contains records with anomalies (missing punches, duplicates, inconsistencies)
- Reporting system is operational and accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the system login page and enter valid HR manager credentials (username and password), then click Login button | Authentication successful, HR manager is redirected to the reporting dashboard with access to all authorized features |
| 2 | Locate and click on the 'Attendance Exception Reports' menu item or navigation link in the reporting dashboard | Attendance exception report interface is displayed showing filter options, report generation controls, and empty report area |
| 3 | Click the 'Generate Report' button without modifying any default filters | Report is generated within 10 seconds displaying all attendance anomalies including missing punches, duplicate entries, and inconsistent records with accurate data, employee names, dates, and exception types clearly visible |

**Postconditions:**
- HR manager remains logged into the system
- Generated report is displayed on screen
- Report generation activity is logged in audit trail
- System is ready for additional report operations

---

### Test Case: Verify report filtering by employee and date range
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- HR manager is logged into the system
- Attendance exception reports interface is accessible
- Multiple employees have attendance records with anomalies
- Attendance data exists across multiple date ranges
- PDF export functionality is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | In the attendance exception reports interface, select a specific employee from the employee dropdown filter and set a date range using the date picker (e.g., last 30 days) | Selected employee name is displayed in the filter field, date range is populated with start and end dates, filter indicators show active filters |
| 2 | Click the 'Generate Report' button to apply the selected filters | Report is generated displaying only attendance anomalies for the selected employee within the specified date range, no records from other employees or dates outside the range are shown, anomaly count matches filtered criteria |
| 3 | Click the 'Export to PDF' button to download the filtered report | PDF file is generated and downloaded to the default download location, file opens successfully showing the same filtered data with proper formatting, headers, employee information, and anomaly details |

**Postconditions:**
- Filtered report remains displayed on screen
- PDF file is saved in downloads folder
- Export activity is logged with timestamp and user details
- Filters remain applied for subsequent operations

---

### Test Case: Ensure scheduling and email distribution of reports
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- HR manager is logged into the system with scheduling permissions
- Email server configuration is properly set up
- Valid email addresses exist for recipient users
- Scheduled report functionality is enabled
- System time is synchronized correctly

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the 'Schedule Report' section in the attendance exception reports interface, select report frequency (e.g., daily, weekly), set execution time, enter recipient email addresses (comma-separated), and click 'Save Schedule' button | Schedule is saved successfully with confirmation message displayed, scheduled report appears in the list of active schedules showing frequency, time, recipients, and status as 'Active' |
| 2 | Wait for the scheduled time to arrive (or advance system time for testing purposes) | At the scheduled time, the system automatically generates the attendance exception report based on configured filters and sends email to all specified recipients, schedule status updates to show last execution time |
| 3 | Check recipient email inbox, open the received email, and verify the report attachment content | Email is received by all recipients with subject line indicating attendance exception report, email body contains report summary and generation details, attached report file (PDF or Excel) opens successfully and displays accurate attendance anomaly data matching current database state |

**Postconditions:**
- Scheduled report remains active for future executions
- Email delivery is logged in system audit trail
- Recipients have access to the report attachment
- Schedule can be modified or deactivated as needed

---

## Story: As HR Manager, I want to export attendance data to payroll systems to ensure accurate salary processing
**Story ID:** story-27

### Test Case: Validate successful attendance data export
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- HR manager account exists with export permissions
- HR manager is authenticated in the system
- Validated attendance records exist for the selected pay period
- Attendance data is complete with no missing required fields
- Export functionality is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the system login page, enter valid HR manager credentials (username and password), and click the Login button | Authentication is successful, HR manager is redirected to the main dashboard with access to the attendance export interface |
| 2 | Navigate to the attendance export interface, select a specific pay period from the date range picker (e.g., January 1-15, 2024), and choose 'CSV' as the export format from the format dropdown | Pay period is selected and displayed in the filter field, CSV format is highlighted as selected, system displays the number of records to be exported for the selected period |
| 3 | Click the 'Generate Export' button and then click the 'Download' button when the file is ready | Export file is generated within 10 seconds, CSV file is downloaded to the default download location, file opens successfully in spreadsheet application, data includes all attendance records for the selected pay period with correct employee IDs, names, dates, clock-in/out times, total hours, and complies with payroll system format requirements |

**Postconditions:**
- CSV export file is saved in downloads folder
- Export activity is logged in audit trail with user, timestamp, pay period, and format
- Attendance data remains unchanged in the database
- HR manager can perform additional exports or operations

---

### Test Case: Verify export validation blocks incomplete data
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- HR manager is logged into the system
- Attendance export interface is accessible
- Attendance database contains incomplete records (missing clock-in, clock-out, or required fields) for the selected pay period
- Data validation rules are configured and active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | In the attendance export interface, select a pay period that contains incomplete attendance data (records with missing clock-in times, missing clock-out times, or other required fields), choose an export format (CSV or XML), and click the 'Generate Export' button | System performs data validation check, detects incomplete attendance records, displays a clear validation error message indicating 'Export cannot be completed: Incomplete attendance data detected', error message lists specific issues such as 'X records with missing clock-in times' and 'Y records with missing clock-out times', export process is blocked and no file is generated |

**Postconditions:**
- No export file is generated or downloaded
- Validation error is logged in system audit trail
- HR manager is prompted to resolve data issues before retrying export
- Incomplete attendance records remain flagged for correction

---

## Story: As HR Manager, I want to audit attendance data changes to ensure compliance and accountability
**Story ID:** story-29

### Test Case: Validate audit log recording of attendance changes
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User has HR Manager role with attendance edit permissions
- User is logged into the attendance management system
- At least one employee attendance record exists in the system
- Audit log database is operational and accessible
- User has valid authentication credentials

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance management module from the main dashboard | Attendance management page loads successfully displaying list of employee attendance records |
| 2 | Select an existing attendance record for an employee | Attendance record details are displayed with editable fields (date, time in, time out, status) |
| 3 | Modify the attendance record by changing the time in from original value to a new value (e.g., 9:00 AM to 9:15 AM) | Modified value is displayed in the time in field |
| 4 | Click the 'Save' button to commit the changes | Success message is displayed confirming 'Attendance record updated successfully' and the change is saved to the database |
| 5 | Navigate to the audit log interface by clicking on 'Audit Logs' menu option | Audit log interface loads successfully displaying search filters and audit log entries table |
| 6 | Search for the recently modified attendance record using employee name or record ID | Audit log entry for the attendance change is displayed in the results |
| 7 | Review the audit log entry details including timestamp, user who made the change, field changed, old value, and new value | Audit log entry contains complete details: current user's name, accurate timestamp, field name 'Time In', old value '9:00 AM', new value '9:15 AM', and record identifier |

**Postconditions:**
- Attendance record reflects the updated time in value
- Complete audit log entry exists in the audit database
- Audit log is accessible for future compliance reviews
- No data integrity issues in attendance or audit tables

---

### Test Case: Verify audit log search and export functionality
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User has HR Manager role with audit log access permissions
- User is logged into the system
- Multiple audit log entries exist in the database with different users and dates
- At least 5 attendance changes have been recorded in the audit log
- System has export functionality enabled
- User's browser allows file downloads

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the audit log interface from the main menu | Audit log page loads successfully displaying search filters (user, date range, record type) and empty results table |
| 2 | Enter a specific user name in the 'User' filter field | User name is populated in the filter field with autocomplete suggestions if available |
| 3 | Select a date range using the date picker (e.g., last 7 days) | Start date and end date are populated in the date range filter fields |
| 4 | Click the 'Search' or 'Apply Filters' button | Audit log entries matching the search criteria are displayed in the results table within 5 seconds, showing user, timestamp, record affected, field changed, old value, and new value |
| 5 | Verify that only audit entries matching the specified user and date range are displayed | All displayed entries show the correct user name and timestamps fall within the selected date range |
| 6 | Review the search results to confirm relevant audit entries are present | Audit entries are displayed in chronological order with complete information for each change |
| 7 | Click the 'Export' or 'Download Report' button | Export options dialog appears showing available formats (PDF, Excel, CSV) |
| 8 | Select the desired export format (e.g., Excel) and confirm the export action | File download begins and a success message 'Report generated successfully' is displayed |
| 9 | Open the downloaded audit report file | Report file opens successfully containing all filtered audit log entries with columns: User, Timestamp, Record ID, Employee Name, Field Changed, Old Value, New Value, and includes report generation date and filter criteria used |

**Postconditions:**
- Audit report file is saved to the user's download folder
- Report contains accurate data matching the search criteria
- Audit log interface remains accessible for additional searches
- No changes made to the audit log data during the search and export process

---

