# Manual Test Cases

## Story: As Compliance Officer, I want to view a full audit trail of quote edits to ensure regulatory compliance
**Story ID:** story-13

### Test Case: Validate audit log creation for quote edits
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Test environment is accessible and operational
- Quote Manager user account exists with quote editing permissions
- Compliance Officer user account exists with audit trail access
- Unauthorized user account exists without audit trail access
- At least one active quote exists in the system
- Audit logs database is operational and accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system as Quote Manager user | Quote Manager successfully logs in and dashboard is displayed |
| 2 | Navigate to an existing quote and open it for editing | Quote details page opens with edit functionality available |
| 3 | Make a change to the quote (e.g., update pricing, modify terms, or change customer information) | Quote is updated successfully and confirmation message is displayed |
| 4 | Note the current timestamp and Quote Manager user ID for verification | Timestamp and user ID are recorded for later validation |
| 5 | Log out as Quote Manager and log in as Compliance Officer | Compliance Officer successfully logs in and compliance dashboard is displayed |
| 6 | Navigate to the audit trail search interface | Audit trail search page loads with filter options visible (date range, user, quote ID) |
| 7 | Enter search filters: quote ID from step 2, user ID from step 4, and date range including the timestamp from step 4 | Filters are applied successfully and search is initiated |
| 8 | Start timer and submit the search query | Search results are returned and displayed within 3 seconds |
| 9 | Verify the audit log entry contains: correct user ID, accurate timestamp, quote ID, and detailed change information | Audit log entry displays all required information accurately matching the edit made in step 3 |
| 10 | Log out as Compliance Officer and log in as unauthorized user (without audit trail access) | Unauthorized user successfully logs in to their limited dashboard |
| 11 | Attempt to navigate to the audit trail interface or access audit logs directly via URL | Access denied message is displayed and user is prevented from viewing audit trail data |

**Postconditions:**
- Audit log entry exists in the database with complete information
- No unauthorized access to audit trail occurred
- All user sessions are properly logged out
- System state remains secure and compliant

---

### Test Case: Verify audit report export functionality
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Test environment is accessible and operational
- Compliance Officer user account exists with audit trail access and export permissions
- Multiple audit log entries exist in the system for testing filters
- System has PDF and CSV export functionality enabled
- User has appropriate browser settings to allow file downloads

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system as Compliance Officer | Compliance Officer successfully logs in and compliance dashboard is displayed |
| 2 | Navigate to the audit trail search interface | Audit trail search page loads with filter options and export buttons visible |
| 3 | Apply filters to generate a specific audit report (e.g., date range: last 7 days, specific user, or quote ID) | Filters are applied successfully |
| 4 | Click the search or generate report button | Audit report is generated and displayed on screen with matching records shown in a table format |
| 5 | Review the displayed report for accuracy: verify columns include user ID, timestamp, quote ID, action type, and change details | Report displays correctly with all required columns and data matches the applied filters |
| 6 | Count the number of records displayed in the report for later verification | Record count is noted for validation against exported files |
| 7 | Click the 'Export as PDF' button | PDF file download initiates automatically |
| 8 | Open the downloaded PDF file | PDF opens successfully and displays the audit report with proper formatting |
| 9 | Verify PDF content: check that all records from the displayed report are included, data is accurate, and formatting is readable | PDF contains correct data matching the on-screen report with the same record count and all information is clearly formatted |
| 10 | Return to the audit trail interface and click the 'Export as CSV' button | CSV file download initiates automatically |
| 11 | Open the downloaded CSV file in a spreadsheet application (e.g., Excel, Google Sheets) | CSV file opens successfully with data properly separated into columns |
| 12 | Verify CSV content: check that all records are included, data matches the displayed report, and all columns are present with correct headers | CSV contains correct data matching the on-screen report with the same record count, proper column headers, and all information is accurately represented |

**Postconditions:**
- PDF and CSV files are successfully downloaded and saved
- Exported files contain accurate and complete audit data
- No data corruption or loss occurred during export
- User session remains active and secure

---

## Story: As System Administrator, I want to manage user permissions for quote editing and version access to ensure secure operations
**Story ID:** story-16

### Test Case: Verify admin can assign and revoke quote editing permissions
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Test environment is accessible and operational
- System Administrator account exists with full permission management rights
- Test user account exists without quote editing permissions
- At least one active quote exists in the system for testing access
- User roles and permissions database is operational
- Admin portal is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the admin portal as System Administrator | System Administrator successfully logs in and admin dashboard is displayed |
| 2 | Navigate to the user management section | User management interface loads displaying list of users with their current permissions |
| 3 | Search for and select the test user account | Test user profile opens showing current permissions and roles |
| 4 | Verify that quote editing permission is currently not assigned to the test user | Quote editing permission checkbox or toggle is unchecked/disabled |
| 5 | Assign quote editing permission to the test user by checking the appropriate checkbox or enabling the toggle | Quote editing permission is selected and interface shows the pending change |
| 6 | Click the 'Save' or 'Apply Changes' button | Success message is displayed confirming permission change has been saved |
| 7 | Open a new browser window or incognito session and log in as the test user | Test user successfully logs in and dashboard is displayed |
| 8 | Navigate to an existing quote and attempt to edit it | Test user can access the quote and edit functionality is available immediately without requiring logout/login or system restart |
| 9 | Make a minor change to the quote and save it | Quote is successfully updated and saved, confirming editing access is active |
| 10 | Return to the admin portal session and navigate back to the test user's permissions | User management interface displays the test user with quote editing permission enabled |
| 11 | Revoke quote editing permission by unchecking the checkbox or disabling the toggle | Quote editing permission is deselected and interface shows the pending change |
| 12 | Click the 'Save' or 'Apply Changes' button | Success message is displayed confirming permission has been revoked |
| 13 | Return to the test user session (without logging out) and refresh the page or navigate to another quote | Page refreshes successfully |
| 14 | Attempt to edit a quote as the test user | Edit functionality is no longer available or access denied message is displayed, confirming permission revocation took effect immediately |

**Postconditions:**
- Test user no longer has quote editing permissions
- Permission changes are reflected in the database
- No system restart was required for changes to take effect
- All user sessions are properly maintained

---

### Test Case: Ensure permission changes are logged
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Test environment is accessible and operational
- System Administrator account exists with full permission management rights
- Test user account exists in the system
- Audit logging system is operational and enabled
- Admin has access to audit logs or permission change logs
- User roles and permissions database is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the admin portal as System Administrator | System Administrator successfully logs in and admin dashboard is displayed |
| 2 | Note the current timestamp and System Administrator user ID for later verification | Timestamp and admin user ID are recorded |
| 3 | Navigate to the user management section | User management interface loads displaying list of users |
| 4 | Search for and select the test user account | Test user profile opens showing current permissions |
| 5 | Change one or more permissions for the test user (e.g., assign quote editing permission, grant version history access, or enable audit trail viewing) | Permission changes are selected in the interface |
| 6 | Click the 'Save' or 'Apply Changes' button | Success message is displayed confirming permission changes have been saved |
| 7 | Navigate to the audit logs or permission change logs section in the admin portal | Audit logs interface loads with search and filter options |
| 8 | Search for permission change logs using filters: admin user ID from step 2, test user ID, and timestamp range including the time from step 2 | Search executes and displays matching log entries |
| 9 | Locate the log entry corresponding to the permission change made in step 5 | Log entry is found and displayed in the results |
| 10 | Verify the log entry contains: System Administrator user ID, accurate timestamp, test user ID, permission type changed, old permission value, and new permission value | Log entry displays all required information accurately: correct admin ID matches step 2, timestamp is within expected range, test user ID is correct, and permission change details are complete and accurate |
| 11 | Make an additional permission change to the same or different user | Second permission change is saved successfully |
| 12 | Refresh or re-search the audit logs | Updated audit logs are displayed including the new entry |
| 13 | Verify that the second permission change is also logged with complete information | Second log entry exists with admin ID, timestamp, affected user, and change details, confirming 100% of permission changes are being logged |

**Postconditions:**
- All permission changes are recorded in audit logs
- Audit log entries contain complete and accurate information
- Logs are accessible to authorized administrators
- System maintains data integrity and audit trail compliance

---

## Story: As Compliance Officer, I want to receive alerts on suspicious quote edits to proactively manage risks
**Story ID:** story-18

### Test Case: Validate alert generation for suspicious quote edits
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User has valid credentials with quote editing permissions
- Compliance Officer account is active and configured to receive alerts
- Suspicious edit criteria are predefined in the system (e.g., discount > 50%, price reduction > $10,000)
- Alert dashboard is accessible and operational
- System monitoring and alerting services are running
- Test quote exists in the system with known baseline values

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system with valid user credentials who has quote editing permissions | User is successfully authenticated and redirected to the main dashboard |
| 2 | Navigate to the quote management section and select an existing test quote | Quote details page is displayed with current quote information |
| 3 | Click on the 'Edit Quote' button to modify the quote | Quote edit form is displayed with editable fields |
| 4 | Perform a quote edit that meets suspicious criteria (e.g., apply a 60% discount or reduce price by $15,000) | Quote edit is saved successfully and changes are reflected in the system |
| 5 | Wait for up to 1 minute and monitor the system for alert generation | System detects the suspicious edit and generates an alert within 1 minute |
| 6 | Verify that the Compliance Officer receives a notification (email, in-app notification, or SMS) | Compliance Officer receives alert notification within 1 minute containing quote ID, edit details, user who made the edit, and timestamp |
| 7 | Log out from the current user session and log in as a Compliance Officer | Compliance Officer is successfully authenticated and redirected to the compliance dashboard |
| 8 | Access the alert dashboard from the main navigation menu | Alert dashboard is displayed showing all recent alerts |
| 9 | Locate the alert generated in step 5 in the alert list | Alert is visible in the dashboard with relevant details including quote ID, edit type, suspicious criteria triggered, user who made the edit, timestamp, and alert severity level |
| 10 | Click on the alert to view full details | Detailed alert view is displayed showing complete information about the suspicious edit, including before/after values, edit justification (if provided), and action buttons for response |
| 11 | Verify that the alert is logged in the audit trail | Alert entry is present in the system audit logs with complete details and timestamp |

**Postconditions:**
- Alert is successfully generated and stored in the system
- Compliance Officer has been notified of the suspicious activity
- Alert is visible in the alert dashboard
- Alert is logged in the audit trail for future reference
- Quote remains in edited state pending compliance review

---

## Story: As Quote Manager, I want to export quote versions and audit trails to CSV for offline analysis and reporting
**Story ID:** story-20

### Test Case: Validate CSV export of quote versions
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User has valid Quote Manager credentials with export permissions
- Test quote exists in the system with multiple versions (at least 5 versions)
- Version history page is accessible
- Export functionality is enabled for the user role
- Browser allows file downloads
- Microsoft Excel or compatible spreadsheet application is installed for verification

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system with valid Quote Manager credentials | User is successfully authenticated and redirected to the main dashboard |
| 2 | Navigate to the quote management section and select a quote with multiple versions | Quote details page is displayed |
| 3 | Click on the 'Version History' tab or link | Version history page is displayed showing all versions of the selected quote in a list or table format |
| 4 | Apply filters to the version list (e.g., filter by date range, user, or version status) | Filtered version list is displayed showing only versions matching the filter criteria with accurate count |
| 5 | Locate and click the 'Export to CSV' button | Export process initiates and a progress indicator is displayed |
| 6 | Wait for the CSV file generation to complete | CSV file is generated within 10 seconds and automatically downloaded to the default download location with a meaningful filename (e.g., quote_versions_[quoteID]_[timestamp].csv) |
| 7 | Navigate to the download location and verify the CSV file exists | CSV file is present in the download folder with appropriate file size (not empty or corrupted) |
| 8 | Open the CSV file in Microsoft Excel or compatible spreadsheet application | File opens successfully without errors or warnings |
| 9 | Verify the CSV file structure and headers (e.g., Version Number, Created Date, Created By, Changes Made, Status) | All expected column headers are present and properly formatted |
| 10 | Verify the data completeness by comparing the number of rows in CSV with the filtered version list count | Row count matches the filtered version list count (excluding header row) |
| 11 | Verify data accuracy by spot-checking 3-5 version records against the system display | Data in CSV matches the data displayed in the version history page for all checked records |
| 12 | Verify special characters, dates, and numerical values are correctly formatted | All data types are correctly formatted and readable without encoding issues |

**Postconditions:**
- CSV file is successfully downloaded and saved
- CSV file contains accurate and complete version data
- File is compatible with Excel and other spreadsheet applications
- Export action is logged in the audit trail
- No data corruption or loss occurred during export

---

### Test Case: Validate CSV export of audit trail data
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 9 mins

**Preconditions:**
- User has valid Quote Manager credentials with audit trail access and export permissions
- Test quotes exist in the system with audit trail records (at least 10 audit entries)
- Audit trail page is accessible
- Export functionality is enabled for the user role
- Browser allows file downloads
- Microsoft Excel or compatible spreadsheet application is installed for verification

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system with valid Quote Manager credentials | User is successfully authenticated and redirected to the main dashboard |
| 2 | Navigate to the audit trail section from the main menu | Audit trail page is displayed showing all audit records |
| 3 | Apply filters to the audit trail (e.g., filter by quote ID, date range, user, or action type) | Filtered audit records are displayed showing only entries matching the filter criteria with accurate count |
| 4 | Verify the filtered results display relevant audit information (timestamp, user, action, quote ID, changes) | All filtered audit records are displayed with complete information in table format |
| 5 | Locate and click the 'Export to CSV' button | Export process initiates and a progress indicator or confirmation message is displayed |
| 6 | Wait for the CSV file generation to complete | CSV file is generated within 10 seconds and automatically downloaded to the default download location with a meaningful filename (e.g., audit_trail_[timestamp].csv) |
| 7 | Navigate to the download location and verify the CSV file exists | CSV file is present in the download folder with appropriate file size indicating data content |
| 8 | Open the CSV file in Microsoft Excel or compatible spreadsheet application | File opens successfully without errors, warnings, or formatting issues |
| 9 | Verify the CSV file structure and headers (e.g., Timestamp, User, Action Type, Quote ID, Field Changed, Old Value, New Value, IP Address) | All expected column headers are present, properly labeled, and in logical order |
| 10 | Verify the data completeness by comparing the number of rows in CSV with the filtered audit trail count | Row count in CSV matches the filtered audit trail count displayed in the system (excluding header row) |
| 11 | Verify data accuracy by spot-checking 3-5 audit records against the system display | Audit data in CSV exactly matches the data displayed in the audit trail page for all checked records including timestamps, user names, and change details |
| 12 | Verify timestamp formatting is consistent and readable | All timestamps are in a consistent format (e.g., YYYY-MM-DD HH:MM:SS) and correctly represent the audit event times |
| 13 | Verify special characters, long text fields, and multi-line values are properly escaped and formatted | All data is correctly formatted with proper CSV escaping, no broken rows, and all content is readable |
| 14 | Test data manipulation in Excel (e.g., sorting, filtering, pivot tables) | CSV data can be sorted, filtered, and analyzed using standard Excel functions without errors |

**Postconditions:**
- CSV file is successfully downloaded and saved
- CSV file contains accurate and complete audit trail data
- File is compatible with Excel and other spreadsheet applications
- Export action is logged in the system audit trail
- No sensitive data is exposed beyond user's authorization level
- Original audit trail data remains unchanged in the system

---

