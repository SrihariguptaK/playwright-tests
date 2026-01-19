# Manual Test Cases

## Story: As Employee, I want to receive notifications about my schedule change request status to stay informed
**Story ID:** story-4

### Test Case: Verify notification sent upon approval
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee has submitted a schedule change request
- Request is in pending status
- Approver has valid credentials and approval permissions
- Email service is operational
- Employee email address is valid and configured in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login as an approver with valid credentials | Approver successfully logs into the system and dashboard is displayed |
| 2 | Navigate to pending schedule change requests | List of pending requests is displayed with the submitted request visible |
| 3 | Select the employee's schedule change request | Request details are displayed including employee information, requested changes, and approval options |
| 4 | Click approve button and submit the approval | System displays confirmation message that request has been approved and notification is being sent |
| 5 | Verify system triggers notification by checking notification queue or logs | Notification entry is created in the system with status 'Triggered' or 'Pending' |
| 6 | Wait up to 5 minutes and check employee email inbox | Notification email is received within 5 minutes containing approval status, request details, and approval comments if any |
| 7 | Access NotificationLogs table or notification history interface | Log entry shows successful delivery with timestamp, recipient email, delivery status as 'Delivered', and no errors |
| 8 | Verify email content includes all required information | Email contains request ID, approval status, approver name, approval date/time, and any approval comments |

**Postconditions:**
- Schedule change request status is updated to 'Approved'
- Notification is logged in NotificationLogs table with successful delivery status
- Employee has received email notification
- Notification delivery timestamp is within 5 minutes of approval action

---

### Test Case: Verify notification sent upon rejection with comments
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee has submitted a schedule change request
- Request is in pending status
- Approver has valid credentials and rejection permissions
- Email service is operational
- Employee email address is valid and configured in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login as an approver with valid credentials | Approver successfully logs into the system and dashboard is displayed |
| 2 | Navigate to pending schedule change requests | List of pending requests is displayed with the submitted request visible |
| 3 | Select the employee's schedule change request | Request details are displayed including employee information, requested changes, and rejection options |
| 4 | Click reject button and enter rejection comments (e.g., 'Insufficient staffing coverage during requested period') | Rejection comment field accepts the input and displays the entered text |
| 5 | Submit the rejection with comments | System displays confirmation message that request has been rejected and notification is being sent |
| 6 | Verify system triggers notification by checking notification queue or logs | Notification entry is created in the system with status 'Triggered' or 'Pending' and includes rejection comments |
| 7 | Wait up to 5 minutes and check employee email inbox | Notification email is received within 5 minutes containing rejection status and the specific rejection comments entered by approver |
| 8 | Verify email content includes rejection comments | Email clearly displays rejection comments: 'Insufficient staffing coverage during requested period' along with request details |
| 9 | Access NotificationLogs table or notification history interface | Log entry shows successful delivery with timestamp, recipient email, delivery status as 'Delivered', rejection comments included, and no errors |

**Postconditions:**
- Schedule change request status is updated to 'Rejected'
- Rejection comments are stored with the request
- Notification is logged in NotificationLogs table with successful delivery status
- Employee has received email notification with rejection comments
- Notification delivery timestamp is within 5 minutes of rejection action

---

### Test Case: Ensure notifications are sent only to request owners
- **ID:** tc-003
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Multiple employees exist in the system with valid email addresses
- Employee A has submitted a schedule change request
- Employee B exists in the system but did not submit this request
- Request is in pending status
- Approver has valid credentials
- Email service is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Identify and record Employee A (request owner) email address | Employee A email address is documented (e.g., employeeA@company.com) |
| 2 | Identify and record Employee B (non-owner) email address | Employee B email address is documented (e.g., employeeB@company.com) |
| 3 | Login as approver and navigate to the schedule change request submitted by Employee A | Request details show Employee A as the requester |
| 4 | Approve or reject the schedule change request to trigger notification | System confirms the status change and triggers notification process |
| 5 | Check NotificationLogs table for notification entries related to this request | Notification log shows only one entry with Employee A's email address as the recipient |
| 6 | Verify Employee A's email inbox within 5 minutes | Employee A receives the notification email with status update |
| 7 | Verify Employee B's email inbox within 5 minutes | Employee B does NOT receive any notification email for this request |
| 8 | Check system notification queue or delivery logs for Employee B | No notification entries exist for Employee B related to this request |
| 9 | Verify notification contains correct employee identification | Email sent to Employee A contains their name and request details specific to their submission |

**Postconditions:**
- Only Employee A (request owner) received the notification
- Employee B did not receive any notification
- NotificationLogs table contains entry only for Employee A
- No unauthorized notification deliveries occurred
- Employee contact information remains protected

---

## Story: As System Administrator, I want to configure approval workflow roles to ensure correct approvers are assigned
**Story ID:** story-5

### Test Case: Create and assign approval roles successfully
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Administrator has valid credentials with role management permissions
- System has at least 2-3 users available for role assignment
- ApprovalRoles and UserRoles tables are accessible
- Role management interface is operational
- Administrator is logged into the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the system as an administrator with valid credentials | Administrator successfully logs in and admin dashboard is displayed |
| 2 | Navigate to the role management page from admin menu or configuration panel | Role management page loads successfully displaying existing roles in a list or table format with columns for role name, description, and assigned users |
| 3 | Verify existing roles are displayed correctly | All existing approval roles are listed with their current user assignments visible |
| 4 | Click 'Create New Role' or 'Add Role' button | Role creation form is displayed with fields for role name, description, and user assignment options |
| 5 | Enter role name (e.g., 'Department Manager Approver') in the role name field | Role name is accepted and displayed in the input field |
| 6 | Enter role description (e.g., 'Approves schedule changes for department employees') | Description is accepted and displayed in the description field |
| 7 | Select multiple users from available users list to assign to this role (e.g., select 2-3 users) | Selected users are highlighted or moved to 'Assigned Users' section |
| 8 | Click 'Save' or 'Create Role' button | System displays success message confirming role and user assignments have been saved successfully |
| 9 | Verify the new role appears in the roles list | New role 'Department Manager Approver' is displayed in the roles list with correct name and description |
| 10 | Click on the newly created role to view details | Role details page shows the role with all assigned users listed correctly (2-3 users as assigned) |
| 11 | Verify data persistence by checking ApprovalRoles table | New role entry exists in ApprovalRoles table with correct role name and description |
| 12 | Verify user assignments in UserRoles table | UserRoles table contains entries linking the assigned users to the new role ID |

**Postconditions:**
- New approval role is created and saved in the system
- Multiple users are successfully assigned to the new role
- Role appears in the roles list with correct information
- Changes are persisted in ApprovalRoles and UserRoles tables
- Role is immediately available for use in approval workflows

---

### Test Case: Validate role configuration errors
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Administrator has valid credentials with role management permissions
- Administrator is logged into the system
- Role management interface is operational
- System has validation rules configured for role creation

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the system as an administrator | Administrator successfully logs in and admin dashboard is displayed |
| 2 | Navigate to role management page | Role management page loads successfully |
| 3 | Click 'Create New Role' or 'Add Role' button | Role creation form is displayed with empty fields |
| 4 | Leave the role name field empty and enter only description | Description field accepts input while role name remains empty |
| 5 | Attempt to save the role without entering required role name | System prevents save operation and displays validation error message such as 'Role name is required' near the role name field |
| 6 | Verify the role was not saved by checking the roles list | Incomplete role does not appear in the roles list |
| 7 | Enter a valid role name (e.g., 'Senior Approver') in the role name field | Role name is accepted and validation error for role name is cleared |
| 8 | Leave other required fields empty if applicable (e.g., description or user assignment if mandatory) | Fields remain empty |
| 9 | Attempt to save again with remaining missing required fields | System displays appropriate validation errors for each missing required field and prevents save operation |
| 10 | Correct all validation errors by filling in all required fields with valid data | All fields are populated with valid information and validation errors are cleared |
| 11 | Click 'Save' button after correcting all errors | System successfully saves the role and displays success confirmation message |
| 12 | Verify the role now appears in the roles list | New role 'Senior Approver' is displayed in the roles list with all correct information |

**Postconditions:**
- Invalid role configurations are rejected by the system
- Appropriate validation error messages are displayed to the administrator
- No incomplete or invalid roles are saved to the database
- After correction, valid role is successfully saved
- Data integrity is maintained in ApprovalRoles table

---

### Test Case: Ensure only authorized admins can access role management
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- System has role-based access control implemented
- Non-admin user account exists with valid credentials but without admin privileges
- Admin user account exists with proper role management permissions
- Role management URL or navigation path is known

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the system using non-admin user credentials | Non-admin user successfully logs in and regular user dashboard is displayed |
| 2 | Verify admin menu or configuration panel is not visible in navigation | Admin-specific menu items and role management options are not displayed in the user interface |
| 3 | Attempt to access role management page directly via URL or navigation path | System denies access and displays appropriate error message such as 'Access Denied', 'Unauthorized Access', or '403 Forbidden' |
| 4 | Verify user is redirected to appropriate page (dashboard or error page) | User is redirected away from role management page to either their dashboard or a dedicated access denied page |
| 5 | Check system logs for unauthorized access attempt | Security log records the unauthorized access attempt with user ID, timestamp, and attempted resource |
| 6 | Logout from non-admin user account | User is successfully logged out and returned to login page |
| 7 | Login using administrator credentials with role management permissions | Administrator successfully logs in and admin dashboard is displayed |
| 8 | Navigate to role management page using admin menu | Role management page loads successfully with full access to all role configuration features |
| 9 | Verify all role management functions are accessible (create, edit, delete, assign) | All role management buttons and features are visible and functional for the authorized administrator |

**Postconditions:**
- Non-admin users cannot access role management functionality
- Appropriate error messages are displayed for unauthorized access attempts
- Security logs contain records of unauthorized access attempts
- Authorized administrators have full access to role management
- System security and authorization controls are functioning correctly

---

## Story: As Auditor, I want to view audit trails of schedule change approvals to ensure compliance and traceability
**Story ID:** story-6

### Test Case: View and filter audit logs successfully
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Auditor account exists with valid credentials and read-only audit access permissions
- Audit portal is accessible and operational
- ApprovalLogs table contains audit trail data with various dates, users, and request IDs
- Schedule change approval activities have been logged in the system
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the audit portal login page | Audit portal login page is displayed with username and password fields |
| 2 | Enter valid auditor credentials (username and password) | Credentials are accepted and input fields display masked password |
| 3 | Click the 'Login' button | Auditor is successfully authenticated and redirected to the audit portal dashboard |
| 4 | Navigate to the 'Schedule Change Audit Trail' section from the main menu | Audit trail page loads within 5 seconds displaying a list of audit log entries with columns for timestamp, user info, action type, request ID, and status |
| 5 | Locate the filter panel and select a date range filter (e.g., last 30 days) | Date range picker is displayed and selected date range is highlighted |
| 6 | Select a specific user from the user filter dropdown | User filter is applied and dropdown shows the selected user name |
| 7 | Click 'Apply Filters' button | Audit logs are refreshed and display only entries matching the selected date range and user within 5 seconds. Record count updates to reflect filtered results |
| 8 | Verify that displayed audit logs match the applied filter criteria by checking dates and user names | All displayed audit log entries fall within the selected date range and are associated with the selected user |
| 9 | Click on a specific audit entry row to view detailed information | Detailed audit information panel or modal opens displaying complete details including timestamp, user ID, user name, action performed, request ID, approval status, IP address, and any additional metadata |
| 10 | Review the detailed audit information for completeness | All relevant audit details are displayed accurately and are readable |

**Postconditions:**
- Auditor remains logged into the audit portal
- Filtered audit logs remain displayed on screen
- No data has been modified in the ApprovalLogs table
- Audit trail of auditor's viewing activity is logged in the system

---

### Test Case: Export audit logs to CSV and PDF
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Auditor is logged into the audit portal with valid credentials
- Auditor has read-only access permissions to audit logs
- Audit trail page is loaded and displaying audit log entries
- ApprovalLogs table contains exportable audit data
- Browser allows file downloads
- Sufficient disk space available for downloads

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the audit trail page if not already there | Audit trail page is displayed with audit log entries and filter options |
| 2 | Apply desired filters (e.g., select date range of last 7 days and specific request ID) | Filter criteria are applied and audit logs are filtered accordingly |
| 3 | Click 'Apply Filters' button to confirm filter selection | Filtered audit logs are displayed showing only entries matching the filter criteria. Record count reflects filtered results |
| 4 | Verify the filtered logs displayed on screen match the expected criteria | All displayed entries match the applied filters (date range and request ID) |
| 5 | Locate and click the 'Export to CSV' button | CSV file download is initiated. Browser shows download progress |
| 6 | Wait for CSV download to complete and open the downloaded CSV file | CSV file is successfully downloaded with filename containing timestamp (e.g., audit_logs_YYYYMMDD_HHMMSS.csv). File opens in spreadsheet application showing all filtered audit log data with proper column headers (Timestamp, User ID, User Name, Action, Request ID, Status, IP Address) |
| 7 | Verify CSV file contains correct data matching the filtered results displayed on screen | CSV file contains all filtered audit entries with accurate data. Number of rows matches the filtered record count. Data is properly formatted and readable |
| 8 | Return to the audit trail page and click the 'Export to PDF' button | PDF file download is initiated. Browser shows download progress |
| 9 | Wait for PDF download to complete and open the downloaded PDF file | PDF file is successfully downloaded with filename containing timestamp (e.g., audit_logs_YYYYMMDD_HHMMSS.pdf). File opens in PDF reader showing formatted audit log report with header, filter criteria applied, and tabular data |
| 10 | Verify PDF file contains correct data matching the filtered results with proper formatting | PDF file contains all filtered audit entries with accurate data in a well-formatted table. Report includes header with export date/time, applied filters, and page numbers. Data matches the filtered record count and is clearly readable |

**Postconditions:**
- Two files are downloaded: one CSV and one PDF containing the same filtered audit data
- Original audit logs in the database remain unchanged
- Auditor remains logged into the audit portal
- Export actions are logged in the audit trail
- Downloaded files are stored in the browser's default download location

---

### Test Case: Ensure audit logs are immutable
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Auditor is logged into the audit portal with read-only access permissions
- Audit trail page is loaded and displaying audit log entries
- ApprovalLogs table contains existing audit entries
- System has proper security controls to prevent unauthorized modifications
- Audit logging for security events is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the audit trail page and select a specific audit log entry | Audit log entry is selected and detailed view is displayed |
| 2 | Look for any edit, modify, or update buttons or options in the user interface | No edit, modify, or update buttons are visible or available in the interface. Only read-only view options are present |
| 3 | Right-click on an audit log entry to check for context menu options | Context menu either does not appear or shows only read-only options (e.g., View Details, Export). No edit or delete options are available |
| 4 | Attempt to double-click on an audit log field to edit it inline | Field does not become editable. No inline editing capability is available. Field remains in read-only state |
| 5 | Look for any delete, remove, or archive buttons in the audit log interface | No delete, remove, or archive buttons are visible or accessible in the interface |
| 6 | Attempt to use browser developer tools or inspect element to modify audit log data in the UI | While UI elements may be temporarily modified in browser, any attempt to save or submit changes results in an error. System rejects the modification attempt |
| 7 | If API access is available, attempt to send a PUT or DELETE request to the audit logs endpoint (e.g., PUT /api/audit-logs/{id}) | API returns HTTP 403 Forbidden or 405 Method Not Allowed error. Error message indicates that modification or deletion of audit logs is not permitted |
| 8 | Check the system security logs or audit trail for the unauthorized attempt | System logs the unauthorized modification/deletion attempt with details including timestamp, user ID, attempted action, and denial reason |
| 9 | Verify that the original audit log entry remains unchanged in the database | Original audit log entry is intact with all original data unchanged. Timestamp and all fields remain exactly as they were before the attempt |
| 10 | Review the audit trail to confirm the unauthorized attempt was logged | A new audit entry exists documenting the unauthorized modification/deletion attempt, including auditor's user ID, timestamp, and action attempted |

**Postconditions:**
- All audit log entries remain unchanged and intact
- Unauthorized modification/deletion attempt is logged in the security audit trail
- Auditor's session remains active without being terminated
- System integrity is maintained
- No data corruption or loss has occurred in the ApprovalLogs table

---

