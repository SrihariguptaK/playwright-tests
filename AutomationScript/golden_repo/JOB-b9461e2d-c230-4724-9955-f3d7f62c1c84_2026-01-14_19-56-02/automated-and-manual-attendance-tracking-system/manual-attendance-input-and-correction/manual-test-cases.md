# Manual Test Cases

## Story: As Attendance Manager, I want to review and approve manual attendance entries to ensure data accuracy
**Story ID:** story-2

### Test Case: Approve manual attendance entry successfully
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User has valid Attendance Manager credentials
- At least one manual attendance entry exists in pending status
- Database is accessible and operational
- User has approval permissions assigned to their role

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance management portal login page | Login page is displayed with username and password fields |
| 2 | Enter valid Attendance Manager credentials and click Login button | User is successfully authenticated and redirected to the attendance management dashboard |
| 3 | Verify access to the manual attendance approval section in the navigation menu | Manual attendance approval section is visible and accessible in the menu |
| 4 | Click on the manual attendance approval section link | System navigates to the approval section and displays the pending entries page |
| 5 | View the list of pending manual attendance entries | List displays all pending manual attendance entries with columns showing employee ID, date, time, reason, and submitter information |
| 6 | Select a specific pending entry from the list by clicking on it | Entry details page opens showing complete information including employee name, ID, date, time, reason for manual entry, and submitter details |
| 7 | Review all details of the selected entry for accuracy and completeness | All entry details are clearly displayed and readable |
| 8 | Click the Approve button for the reviewed entry | Approval confirmation dialog appears asking to confirm the action |
| 9 | Confirm the approval action in the dialog | System processes the approval within 2 seconds, entry status changes to 'Approved', success message is displayed, and timestamp with manager ID is recorded |
| 10 | Verify that the submitter receives a notification about the approval | Submitter receives notification via system notification and/or email confirming that their manual attendance entry has been approved |

**Postconditions:**
- Manual attendance entry status is updated to 'Approved' in the database
- Approval action is logged in audit trail with timestamp and manager user ID
- Entry is removed from pending list
- Submitter has received approval notification
- Attendance record is finalized in the system

---

### Test Case: Reject manual attendance entry with comments
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User has valid Attendance Manager credentials
- At least one manual attendance entry exists in pending status
- Database is accessible and operational
- User has approval permissions assigned to their role

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance management portal login page | Login page is displayed with username and password fields |
| 2 | Enter valid Attendance Manager credentials and click Login button | User is successfully authenticated and redirected to the attendance management dashboard |
| 3 | Verify access to the manual attendance approval section in the navigation menu | Manual attendance approval section is visible and accessible in the menu |
| 4 | Navigate to the manual attendance approval section | Pending manual attendance entries list is displayed |
| 5 | Select a pending manual attendance entry from the list | Entry details page opens showing all information about the selected entry |
| 6 | Review the entry details and identify issues requiring rejection | Entry details are displayed clearly for review |
| 7 | Click the Reject button for the selected entry | Rejection dialog appears with a mandatory comments field |
| 8 | Enter detailed rejection comments explaining the reason for rejection (e.g., 'Invalid time entry - conflicts with existing biometric record') | Comments are accepted in the text field without character limit errors |
| 9 | Click Confirm Rejection button | System processes the rejection within 2 seconds, entry status changes to 'Rejected', rejection comments are saved, success message is displayed |
| 10 | Verify that rejection details are recorded in the system | Entry status shows 'Rejected', comments are saved and visible, timestamp and manager ID are recorded in audit trail |
| 11 | Check that the submitter receives a rejection notification | Submitter receives notification via system notification and/or email with rejection reason and comments included |
| 12 | Verify the notification contains the rejection comments | Notification displays the exact rejection comments entered by the manager |

**Postconditions:**
- Manual attendance entry status is updated to 'Rejected' in the database
- Rejection comments are saved and associated with the entry
- Rejection action is logged in audit trail with timestamp and manager user ID
- Entry remains visible in rejected entries list
- Submitter has received rejection notification with comments
- Entry is not finalized in the attendance system

---

### Test Case: Prevent unauthorized user from accessing approval functionality
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User account exists without approval permissions
- Role-based access control is configured and active
- Manual attendance approval functionality exists in the system
- Database and authentication services are operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance management portal login page | Login page is displayed with username and password fields |
| 2 | Enter credentials of a user without approval permissions (e.g., regular employee or clerk without manager role) | User is successfully authenticated and redirected to their authorized dashboard |
| 3 | Check the navigation menu for manual attendance approval section | Manual attendance approval section is not visible in the navigation menu |
| 4 | Attempt to manually navigate to the approval section URL by typing it in the browser address bar | System displays 'Access Denied' or '403 Forbidden' error page indicating insufficient permissions |
| 5 | Verify that no approval functionality is accessible through the UI | User cannot access any approval buttons, pending entries list, or approval-related features |
| 6 | Open API testing tool (e.g., Postman) and attempt to call GET /api/manual-attendance/pending endpoint with the unauthorized user's authentication token | API returns 401 Unauthorized or 403 Forbidden status code with error message indicating insufficient permissions |
| 7 | Attempt to call POST /api/manual-attendance/approve endpoint with a valid entry ID using the unauthorized user's token | API returns 401 Unauthorized or 403 Forbidden status code with error message 'User does not have approval permissions' |
| 8 | Verify that no data is returned or modified by the unauthorized API calls | No pending entries data is exposed and no approval actions are processed |
| 9 | Check audit logs for the unauthorized access attempts | Audit logs record the unauthorized access attempts with user ID, timestamp, and denied action |

**Postconditions:**
- Unauthorized user remains unable to access approval functionality
- No manual attendance entries are modified
- Security logs contain records of unauthorized access attempts
- System security integrity is maintained
- No sensitive data is exposed to unauthorized user

---

## Story: As Attendance Clerk, I want to input manual attendance entries to handle exceptions and corrections
**Story ID:** story-4

### Test Case: Add manual attendance entry successfully
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User has valid Attendance Clerk credentials
- User has manual attendance input permissions
- At least one valid employee exists in the system
- Database is accessible and operational
- Manual attendance input section is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance system login page | Login page is displayed with username and password fields |
| 2 | Enter valid Attendance Clerk credentials and click Login button | User is successfully authenticated and redirected to the attendance clerk dashboard |
| 3 | Verify access to the manual attendance input section in the navigation menu | Manual attendance input section is visible and accessible in the menu |
| 4 | Click on the manual attendance input section link | System navigates to the manual attendance input page displaying the input form |
| 5 | Click on 'Add New Manual Attendance Entry' button | New entry form is displayed with fields for Employee ID, Date, Time, and Reason |
| 6 | Enter a valid employee ID in the Employee ID field (e.g., 'EMP12345') | Employee ID is accepted and system validates that the employee exists, displaying employee name if validation is successful |
| 7 | Select a valid date from the date picker (current or past date) | Date is accepted and displayed in the correct format (e.g., DD/MM/YYYY) |
| 8 | Enter a valid time in the time field (e.g., '09:00 AM') | Time is accepted and displayed in the correct format without validation errors |
| 9 | Enter a reason for the manual entry in the Reason field (e.g., 'Biometric device malfunction') | Reason text is accepted in the field |
| 10 | Verify that all required fields are filled and no validation errors are displayed | All fields show valid data with green checkmarks or no error indicators |
| 11 | Click the Submit or Save button to save the manual attendance entry | System processes the entry within 2 seconds and displays a success confirmation message (e.g., 'Manual attendance entry saved successfully') |
| 12 | Verify that the new entry appears in the list of manual attendance entries | Newly created entry is visible in the manual attendance entries list with status 'Pending' and all entered details displayed correctly |
| 13 | Check that the audit log records the manual entry action | Audit log contains a record of the manual entry creation with clerk user ID, timestamp, and entry details |

**Postconditions:**
- Manual attendance entry is saved in the database with status 'Pending'
- Entry is visible in the manual attendance entries list
- Audit trail contains record of the entry creation
- Confirmation message is displayed to the clerk
- Entry is ready for manager approval

---

### Test Case: Edit and delete manual attendance entry
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as Attendance Clerk with appropriate permissions
- At least one manual attendance entry exists in the system
- Entry is in editable status (not yet approved)
- Database is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the manual attendance input section from the dashboard | Manual attendance input page is displayed showing list of existing manual entries |
| 2 | Locate an existing manual attendance entry from the list | List displays existing manual attendance entries with columns for Employee ID, Date, Time, Reason, and Status |
| 3 | Click on the Edit icon or button for the selected entry | Entry details are displayed in edit mode with all fields populated with current values and editable |
| 4 | Verify that all current entry details are correctly displayed in the form | Employee ID, Date, Time, and Reason fields show the existing values accurately |
| 5 | Modify the Time field to a different valid time (e.g., change from '09:00 AM' to '10:30 AM') | New time value is accepted without validation errors |
| 6 | Modify the Reason field to update the explanation (e.g., 'Biometric device malfunction - corrected time') | Updated reason text is accepted in the field |
| 7 | Click the Save Changes button | System processes the update within 2 seconds and displays success confirmation message (e.g., 'Manual attendance entry updated successfully') |
| 8 | Verify that the updated entry shows the modified values in the list | Entry in the list displays the updated time and reason, with modification timestamp updated |
| 9 | Check that the edit action is logged in the audit trail | Audit log contains a record of the modification with clerk user ID, timestamp, and changed fields |
| 10 | Select the same or another manual attendance entry for deletion | Entry is selected and Delete button or icon is visible and enabled |
| 11 | Click the Delete button for the selected entry | Deletion confirmation dialog appears asking 'Are you sure you want to delete this entry?' |
| 12 | Click Confirm or Yes in the deletion confirmation dialog | System processes the deletion within 2 seconds and displays success confirmation message (e.g., 'Manual attendance entry deleted successfully') |
| 13 | Verify that the deleted entry is removed from the list | Entry no longer appears in the manual attendance entries list |
| 14 | Check that the deletion action is logged in the audit trail | Audit log contains a record of the deletion with clerk user ID, timestamp, and deleted entry details |

**Postconditions:**
- Modified entry is updated in the database with new values
- Deleted entry is removed from the database or marked as deleted
- Both edit and delete actions are recorded in audit trail
- Confirmation messages are displayed for both operations
- Manual attendance entries list reflects the changes

---

### Test Case: Prevent unauthorized access to manual attendance input
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User account exists without manual attendance input permissions
- Role-based access control is configured and active
- Manual attendance input functionality exists in the system
- Database and authentication services are operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance system login page | Login page is displayed with username and password fields |
| 2 | Enter credentials of a user without manual attendance input permissions (e.g., regular employee or viewer role) | User is successfully authenticated and redirected to their authorized dashboard |
| 3 | Check the navigation menu for manual attendance input section | Manual attendance input section is not visible or accessible in the navigation menu |
| 4 | Attempt to manually navigate to the manual attendance input URL by typing it in the browser address bar | System displays 'Access Denied' or '403 Forbidden' error page with message indicating insufficient permissions |
| 5 | Verify that no manual attendance input functionality is accessible through the UI | User cannot access any input forms, entry lists, or manual attendance-related features |
| 6 | Open API testing tool (e.g., Postman) and attempt to call POST /api/manual-attendance endpoint with the unauthorized user's authentication token | API returns 401 Unauthorized or 403 Forbidden status code with error message 'User does not have manual attendance input permissions' |
| 7 | Prepare a valid manual attendance entry payload with Employee ID, Date, Time, and Reason | Payload is prepared in correct JSON format |
| 8 | Send the POST request to create a manual attendance entry using the unauthorized user's token | API returns authorization error and no entry is created in the database |
| 9 | Attempt to call PUT /api/manual-attendance/{id} endpoint to edit an existing entry using the unauthorized user's token | API returns 401 Unauthorized or 403 Forbidden status code with appropriate error message |
| 10 | Attempt to call DELETE /api/manual-attendance/{id} endpoint to delete an entry using the unauthorized user's token | API returns 401 Unauthorized or 403 Forbidden status code with appropriate error message |
| 11 | Verify that no manual attendance entries are created, modified, or deleted | Database remains unchanged and no unauthorized operations are executed |
| 12 | Check security audit logs for the unauthorized access attempts | Audit logs record all unauthorized access attempts with user ID, timestamp, attempted action, and denied status |

**Postconditions:**
- Unauthorized user remains unable to access manual attendance input functionality
- No manual attendance entries are created, modified, or deleted
- Security logs contain records of all unauthorized access attempts
- System security integrity is maintained
- Database remains unchanged from unauthorized attempts

---

## Story: As Attendance Clerk, I want to view attendance history for employees to verify and reconcile records
**Story ID:** story-8

### Test Case: Search and view attendance history
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Attendance Clerk user account exists with valid credentials
- Attendance Clerk has role-based access to attendance history section
- Attendance database contains historical biometric and manual attendance records
- Test employee ID exists in the system with attendance data
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance system login page | Login page is displayed with username and password fields |
| 2 | Enter valid Attendance Clerk credentials (username and password) | Credentials are accepted and entered in the respective fields |
| 3 | Click the Login button | User is successfully authenticated and redirected to the attendance system dashboard |
| 4 | Verify access to attendance history section in the navigation menu | Attendance history section is visible and accessible based on role-based access control |
| 5 | Click on the Attendance History menu option | Attendance history page loads displaying search interface with employee ID and date range fields |
| 6 | Enter a valid employee ID in the employee search field | Employee ID is accepted and displayed in the input field without errors |
| 7 | Select a valid start date from the date picker | Start date is selected and displayed in the date range field |
| 8 | Select a valid end date from the date picker (after start date) | End date is selected and displayed in the date range field without validation errors |
| 9 | Click the Search button to submit the query | Search query is processed and loading indicator appears |
| 10 | Wait for search results to load | Attendance records are displayed within 5 seconds showing combined biometric and manual attendance data in a tabular format |
| 11 | Verify the displayed attendance records contain date, time, entry type (biometric/manual), and status columns | All attendance records show complete information with both biometric and manual entries clearly identified |
| 12 | Review the records for data accuracy and completeness | Attendance data matches the selected employee and date range with accurate timestamps and entry types |

**Postconditions:**
- User remains logged in to the attendance system
- Attendance history search results are displayed on screen
- Search parameters remain in the input fields for reference
- System logs the search query for audit purposes

---

### Test Case: Export attendance history data
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Attendance Clerk is logged into the attendance system
- User has navigated to the attendance history section
- Valid employee ID and date range have been entered
- Attendance history search has been performed successfully
- Search results are displayed on screen with attendance records
- Browser allows file downloads

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Verify that attendance history search results are displayed on the screen | Attendance records are visible in tabular format with multiple entries |
| 2 | Locate the Export button on the attendance history results page | Export button is visible and enabled on the interface |
| 3 | Click the Export button | Export process initiates and browser download dialog appears or file automatically downloads |
| 4 | Wait for the CSV file download to complete | CSV file is successfully downloaded to the default downloads folder |
| 5 | Navigate to the downloads folder and locate the exported CSV file | CSV file is present with a meaningful filename containing employee ID and date range information |
| 6 | Open the downloaded CSV file using a spreadsheet application | CSV file opens successfully displaying attendance data in structured columns |
| 7 | Verify CSV file contains all expected columns (Employee ID, Date, Time, Entry Type, Status) | All required columns are present with proper headers |
| 8 | Verify the CSV data matches the attendance records displayed on screen | All attendance entries from the search results are accurately reflected in the CSV file with correct data |
| 9 | Check that both biometric and manual attendance entries are included in the export | CSV file contains combined biometric and manual attendance data as displayed in the search results |

**Postconditions:**
- CSV file is successfully downloaded and saved locally
- Exported data is available for reconciliation purposes
- User remains on the attendance history page with search results still displayed
- Export action is logged in the system audit trail

---

### Test Case: Validate search input errors
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Attendance Clerk is logged into the attendance system
- User has navigated to the attendance history section
- Attendance history search interface is displayed
- Date range fields and employee ID field are accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the attendance history search page | Search interface is displayed with empty employee ID and date range fields |
| 2 | Enter a valid employee ID in the employee search field | Employee ID is accepted and displayed in the input field |
| 3 | Select an end date from the date picker | End date is selected and displayed in the date range field |
| 4 | Select a start date that is after the previously selected end date (invalid date range) | Start date is entered in the field |
| 5 | Observe the validation behavior on the date fields | Validation error message is displayed indicating that end date cannot be before start date |
| 6 | Attempt to click the Search button with invalid date range | Search button is either disabled or clicking it triggers a validation error message preventing the search |
| 7 | Verify the error message clearly states the validation issue | Error message displays: 'End date must be after start date' or similar clear validation message |
| 8 | Verify that no search query is executed with invalid inputs | Search is blocked and no API call is made to the backend; no results are displayed |
| 9 | Correct the date range by selecting a valid start date that is before the end date | Valid start date is selected and validation error message disappears |
| 10 | Verify the Search button becomes enabled after correcting the inputs | Search button is now enabled and clickable without validation errors |
| 11 | Click the Search button with corrected valid inputs | Search query executes successfully and attendance records are displayed |

**Postconditions:**
- Invalid search attempts are blocked by validation
- User is informed of input errors through clear error messages
- System prevents invalid data from being submitted to the backend
- After correction, search functionality works as expected
- Validation errors are logged for system monitoring

---

