# Manual Test Cases

## Story: As Schedule Coordinator, I want to track the status of my schedule change requests to achieve transparency and timely updates
**Story ID:** story-5

### Test Case: Validate display of user's schedule change requests
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User has valid Schedule Coordinator credentials
- Schedule Coordinator has previously submitted at least 5 schedule change requests with varying statuses (Pending, Approved, Rejected)
- Database contains schedule change requests with approval history and comments
- Application is accessible and running
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page and enter valid Schedule Coordinator credentials (username and password), then click the Login button | User is successfully authenticated and redirected to the dashboard. Dashboard displays a list of all schedule change requests submitted by the logged-in Schedule Coordinator with columns showing request ID, date submitted, request type, current status, and action buttons |
| 2 | Locate the status filter dropdown on the dashboard and select 'Pending' from the available status options, then click Apply or wait for auto-refresh | The request list automatically updates and displays only schedule change requests with 'Pending' status. All other statuses (Approved, Rejected, etc.) are filtered out. The count of displayed requests matches the number of pending requests |
| 3 | Click on one of the pending requests from the filtered list to open the detailed view | A detailed view modal or page opens displaying comprehensive information including: request details, submission date and time, complete approval history with timestamps, all comments from approvers and stakeholders, current status with status change timeline, and requester information. All data displayed is accurate and matches the selected request |

**Postconditions:**
- User remains logged in as Schedule Coordinator
- Dashboard maintains the applied filter state
- Detailed view can be closed to return to the filtered list
- No data has been modified during the test

---

### Test Case: Verify notifications on status changes
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User has valid Schedule Coordinator credentials
- User has valid Approver credentials for testing approval workflow
- Notification system is enabled and configured
- User has notification preferences enabled
- Email or in-app notification delivery system is functional
- Database is accessible and can record status changes

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as Schedule Coordinator, navigate to the schedule change request submission form, fill in all required fields (date, time, reason, affected resources), and click Submit button | Schedule change request is successfully created and saved to the database. Request appears in the Schedule Coordinator's dashboard with initial status 'Pending' or 'Submitted'. A confirmation message is displayed with the request ID |
| 2 | Log out from Schedule Coordinator account. Log in as an Approver with appropriate permissions, navigate to pending approvals queue, locate the newly submitted request, review the details, and change the status to 'Approved' by clicking the Approve button and adding optional comments | Request status is updated to 'Approved' in the system. The status change is recorded with timestamp and approver information. Schedule Coordinator receives a notification (email and/or in-app notification) indicating that their schedule change request has been approved, including request ID, approval timestamp, and any comments from the approver |
| 3 | Log out from Approver account. Log back in as the original Schedule Coordinator, navigate to 'My Schedule Changes' dashboard, and locate the previously submitted request in the list | The dashboard displays the request with updated status showing 'Approved'. The status change is reflected accurately with the approval timestamp. The notification indicator (if applicable) shows that a new notification was received. Opening the request details shows the complete approval history including the approver's name, approval time, and any comments added |

**Postconditions:**
- Schedule change request status is permanently updated to 'Approved' in the database
- Notification record is stored in the system
- Approval history is complete and auditable
- Schedule Coordinator can view the approved request in their dashboard
- System is ready for subsequent workflow actions

---

### Test Case: Ensure dashboard loads within performance requirements
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User has valid Schedule Coordinator credentials
- Database contains at least 50 schedule change requests for the test user to simulate realistic load
- System is under normal load conditions (not peak hours)
- Network latency is within acceptable range (<100ms)
- Browser performance monitoring tools are available (browser developer tools or stopwatch)
- Server resources are at normal operating levels

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open browser developer tools and navigate to the Network tab to monitor load times. Navigate to the application login page, enter valid Schedule Coordinator credentials, start timing, and click the Login button | User is successfully authenticated and the dashboard page loads completely. The dashboard displays the list of submitted schedule change requests with all UI elements rendered. Page load time from login submission to full dashboard display is 3 seconds or less as measured by browser tools or stopwatch |
| 2 | On the loaded dashboard, clear any existing filters, start timing, and trigger the loading of the complete list of submitted requests by clicking 'Refresh' or 'Load All' if available, or by clearing filters to show all requests | The complete list of schedule change requests loads and displays all records with proper formatting. All columns (request ID, date, status, type) are populated correctly. The list load time from action initiation to complete display is 3 seconds or less. Pagination controls (if applicable) are functional |
| 3 | Start timing, apply multiple filters simultaneously (select status 'Approved' and date range for the last 30 days), and click Apply or wait for auto-refresh | The filtered list updates to show only requests matching the selected criteria (Approved status within last 30 days). The filtered results display accurately with correct data. The response time from applying filters to displaying filtered results is 3 seconds or less. Filter indicators show active filters clearly |

**Postconditions:**
- Dashboard remains functional and responsive
- All performance metrics are logged for analysis
- User session remains active
- Filters can be cleared or modified for additional testing
- System performance remains stable

---

## Story: As System Administrator, I want to configure notification templates for schedule change workflows to achieve consistent communication
**Story ID:** story-6

### Test Case: Validate creation and editing of notification templates
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User has valid System Administrator credentials with full template management permissions
- Notification templates management module is deployed and accessible
- Database has NotificationTemplates table with proper schema
- At least one existing notification template is present in the system for editing
- Application is running and accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page, enter valid System Administrator credentials (username and password), click Login, and then navigate to the Notification Templates management page from the admin menu or settings | User is successfully authenticated with administrator privileges. The Notification Templates management page loads and displays a list of existing templates with columns showing template name, type, last modified date, and action buttons (Edit, Delete, Preview). A 'Create New Template' button is visible and accessible |
| 2 | Click the 'Create New Template' button, enter template details in the form including: Template Name (e.g., 'Schedule Change Approved'), Template Type (e.g., 'Email'), Subject line with placeholders (e.g., 'Your schedule change request {{requestId}} has been approved'), Body content with multiple placeholders (e.g., 'Dear {{userName}}, Your request for {{scheduleDate}} has been approved by {{approverName}} on {{approvalDate}}'), and click the Save button | The new notification template is successfully created and saved to the database. A success confirmation message is displayed (e.g., 'Template created successfully'). The template appears in the templates list with all entered details. The template ID is generated automatically. All placeholders are preserved in the correct format |
| 3 | Locate the newly created template in the list, click the Edit button or template name to open it in edit mode, modify the template by changing the subject line to 'Schedule Change Request {{requestId}} - Approved' and adding additional text to the body 'Please review the updated schedule in your dashboard', then click the Save button | The template opens in edit mode with all existing content populated in the form fields. Changes are successfully saved to the database. A success confirmation message is displayed (e.g., 'Template updated successfully'). The template list refreshes and shows the updated 'Last Modified' timestamp. Opening the template again shows all the modified content accurately reflecting the changes made |

**Postconditions:**
- New notification template exists in the database and is available for use
- Template modifications are permanently saved
- Template can be assigned to workflow events
- Audit log records template creation and modification actions
- Administrator remains logged in for further template management

---

### Test Case: Verify template preview functionality
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 4 mins

**Preconditions:**
- User has valid System Administrator credentials
- At least one notification template exists with multiple placeholders (e.g., {{userName}}, {{requestId}}, {{scheduleDate}}, {{approverName}})
- Sample data is configured in the system for preview functionality
- Template rendering engine is functional
- Application is accessible and running

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as System Administrator, navigate to the Notification Templates management page, locate an existing template with placeholders in the list, and click the Edit button or template name to open it in edit mode | The template editor opens displaying the complete template content including: template name, type, subject line with placeholders in raw format (e.g., {{userName}}, {{requestId}}), body content with all placeholders visible, and a 'Preview' button or link is clearly visible and accessible in the editor interface |
| 2 | Click the 'Preview' or 'Preview with Sample Data' button to generate a preview of the template | A preview modal or panel opens displaying the rendered template with all placeholders replaced by realistic sample data. For example: {{userName}} is replaced with 'John Smith', {{requestId}} is replaced with 'REQ-12345', {{scheduleDate}} is replaced with '2024-02-15', {{approverName}} is replaced with 'Jane Doe'. The preview shows both the subject line and body content fully rendered. The formatting and layout are preserved correctly. The preview renders within 1 second as per performance requirements |

**Postconditions:**
- Template remains in edit mode for further modifications if needed
- Preview can be closed to return to edit mode
- No changes are made to the actual template during preview
- Administrator can preview multiple times without issues
- System performance remains stable

---

### Test Case: Ensure unauthorized users cannot manage templates
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User has valid non-administrator credentials (e.g., Schedule Coordinator or Approver role)
- Role-based access control (RBAC) is properly configured
- Notification template management requires administrator role
- API endpoints for template management have proper authentication and authorization
- Application security middleware is active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page, enter valid credentials for a non-administrator user (e.g., Schedule Coordinator), click Login, and then attempt to navigate to the Notification Templates management page by manually entering the URL (e.g., /admin/notification-templates) or looking for it in the navigation menu | User is successfully authenticated with non-administrator role. The Notification Templates management page is not accessible. Either the menu option is not visible in the navigation, or if the URL is accessed directly, the user is redirected to an error page or their default dashboard. An appropriate error message is displayed such as 'Access Denied', 'Insufficient Permissions', or 'This page requires administrator privileges'. HTTP status code 403 (Forbidden) is returned |
| 2 | Using an API testing tool (e.g., Postman, curl) or browser developer console, attempt to directly access the template management API endpoints while authenticated as the non-administrator user. Try the following requests: GET /api/notification-templates (list templates), POST /api/notification-templates (create template) with sample payload, PUT /api/notification-templates/{id} (update template), DELETE /api/notification-templates/{id} (delete template) | All API requests are denied with appropriate authorization errors. Each request returns HTTP status code 403 (Forbidden) or 401 (Unauthorized). Response body contains error messages such as 'Access denied: Administrator role required' or 'Insufficient permissions to perform this action'. No template data is returned, created, modified, or deleted. Security logs record the unauthorized access attempts with user details and timestamp |

**Postconditions:**
- No unauthorized access to template management functionality occurred
- No templates were created, modified, or deleted by non-administrator user
- Security audit logs contain records of access denial
- User session remains active with their original role permissions
- System security integrity is maintained

---

## Story: As System Administrator, I want to generate audit reports for schedule change approvals to achieve compliance and transparency
**Story ID:** story-9

### Test Case: Validate generation of audit reports with filters
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User has System Administrator role assigned
- AuditLogs table contains test data with various dates, users, and approval statuses
- System is accessible and user has valid credentials
- At least 100 audit log entries exist in the database for testing

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page and enter valid System Administrator credentials, then click Login button | User is successfully authenticated and redirected to the admin dashboard. Audit reports page link is visible in the navigation menu |
| 2 | Click on the Audit Reports menu option in the navigation | Audit reports page loads successfully displaying filter options including date range picker, user dropdown, and approval status dropdown |
| 3 | Select a date range by choosing start date and end date from the date picker (e.g., last 30 days) | Selected date range is displayed in the date range field and highlighted |
| 4 | Select a specific user from the user filter dropdown | Selected user is displayed in the user filter field |
| 5 | Select an approval status from the status filter dropdown (e.g., Approved, Pending, Rejected) | Selected status is displayed in the status filter field |
| 6 | Click the Generate Report button and start timer | System processes the request, displays a loading indicator, and generates the report within 10 seconds. Report is displayed on screen showing filtered audit log entries with columns for date, user, action, status, and details |
| 7 | Verify the report content matches the applied filters | All displayed audit entries fall within the selected date range, match the selected user, and have the selected approval status. Record count is displayed at the top of the report |

**Postconditions:**
- Audit report is successfully generated and displayed
- Report generation time is logged and within 10 seconds
- User remains logged in as System Administrator
- Filters remain applied for subsequent operations

---

### Test Case: Verify export of audit reports in CSV and PDF
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as System Administrator
- User is on the Audit Reports page
- At least one audit report has been generated and is displayed on screen
- Browser download settings allow automatic file downloads
- User has write permissions to the default download directory

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Apply filters (date range, user, status) and click Generate Report button | Audit report is generated and displayed on screen with data rows showing audit log entries. Export options (CSV and PDF buttons) are visible and enabled |
| 2 | Note the number of records and key data points displayed in the report for verification | Record count and sample data values are documented for comparison |
| 3 | Click the Export as CSV button | CSV file download initiates immediately. File is saved to the downloads folder with naming convention 'AuditReport_YYYYMMDD_HHMMSS.csv' |
| 4 | Open the downloaded CSV file in a spreadsheet application (Excel, Google Sheets) | CSV file opens successfully. All columns are present (Date, User, Action, Status, Details). Data matches the on-screen report exactly. Number of rows matches the record count. No data truncation or formatting issues. Special characters and commas are properly escaped |
| 5 | Return to the audit report page and click the Export as PDF button | PDF file download initiates immediately. File is saved to the downloads folder with naming convention 'AuditReport_YYYYMMDD_HHMMSS.pdf' |
| 6 | Open the downloaded PDF file in a PDF reader application | PDF file opens successfully with professional formatting. Report includes header with title 'Audit Report', generation date, and applied filters. All data columns are properly aligned and readable. Table formatting is consistent with proper borders and spacing. Page numbers are present if report spans multiple pages. Data matches the on-screen report and CSV export exactly |
| 7 | Compare data between the on-screen report, CSV export, and PDF export | All three formats contain identical data with same record count and values. No data loss or corruption in any format |

**Postconditions:**
- Two files are downloaded: one CSV and one PDF
- Both files contain accurate and complete audit report data
- Files are saved in the user's download directory
- User remains on the audit reports page
- Original report remains displayed on screen

---

### Test Case: Ensure scheduling of recurring audit reports
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in as System Administrator
- User is on the Audit Reports page
- System has email/notification service configured and operational
- User has valid email address in their profile
- Scheduled job service is running and accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | On the Audit Reports page, click the Schedule Report button or tab | Schedule Report configuration panel opens displaying options for report scheduling including filters, frequency, format, and delivery method |
| 2 | Enter a descriptive name for the scheduled report (e.g., 'Weekly Approval Audit') | Report name is entered and displayed in the name field |
| 3 | Configure report filters: select date range as 'Last 7 days', select specific user or 'All Users', and select approval status as 'All Statuses' | All filter selections are applied and displayed in the schedule configuration form |
| 4 | Select recurrence frequency from dropdown (e.g., Daily, Weekly, Monthly) - choose 'Weekly' | Weekly frequency is selected and additional options appear for day of week selection |
| 5 | Select the day of the week for report generation (e.g., Monday) and time (e.g., 09:00 AM) | Day and time selections are displayed. Summary shows 'Report will be generated every Monday at 09:00 AM' |
| 6 | Select report format(s) by checking CSV and/or PDF checkboxes | Selected format(s) are checked and highlighted |
| 7 | Enter delivery email address or select from user list for report recipients | Email address(es) are added to the recipients list |
| 8 | Click Save Schedule button | System validates the configuration, displays success message 'Scheduled report created successfully', and returns to the scheduled reports list showing the newly created schedule with status 'Active' |
| 9 | Navigate to the Scheduled Reports list/tab to view all scheduled reports | Scheduled reports list displays showing the newly created schedule with columns: Name, Filters, Frequency, Format, Next Run Date, Status, and Actions |
| 10 | Wait for the scheduled time or trigger a manual test run if available (or verify next scheduled run date is correct) | If test run triggered: Report generation job executes successfully. If verifying schedule: Next run date/time is correctly calculated and displayed |
| 11 | After scheduled time passes (or test run completes), check the report delivery location (email inbox or reports archive) | Report is generated automatically at the scheduled time. Email is received with report attached in selected format(s). Report contains data matching the configured filters. Report archive shows the generated report with timestamp. Report generation is logged in the system |
| 12 | Verify the generated scheduled report content and format | Report contains accurate data for the specified date range (Last 7 days from generation time). Applied filters are correctly reflected in the report. Format matches the selected option (CSV/PDF). Data is complete and properly formatted |

**Postconditions:**
- Scheduled report is saved and active in the system
- Report appears in the list of scheduled reports
- Scheduled job is registered in the job scheduler
- Report is generated and delivered according to schedule
- Audit log contains entry for schedule creation
- User can view, edit, or delete the scheduled report

---

## Story: As System Administrator, I want to manage user roles and permissions for schedule change workflows to achieve secure access control
**Story ID:** story-11

### Test Case: Validate creation and assignment of user roles
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- User has System Administrator role with full permissions
- User is logged into the system with valid credentials
- User roles management module is accessible
- At least 2-3 test users exist in the system for role assignment
- Database tables UserRoles and Permissions are accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page and enter System Administrator credentials, then click Login | User is successfully authenticated and redirected to the admin dashboard. User roles management link/menu is visible in the administration section |
| 2 | Click on User Roles Management menu option in the navigation or administration panel | User Roles Management page loads successfully displaying existing roles in a table/list format with columns: Role Name, Description, Permissions Count, Users Count, and Actions. Create New Role button is visible and enabled |
| 3 | Click the Create New Role button | Create Role form/modal opens displaying fields for Role Name, Description, and Permissions selection area. All available permissions are listed with checkboxes |
| 4 | Enter a unique role name in the Role Name field (e.g., 'Schedule Approver') | Role name is entered and displayed in the field without validation errors |
| 5 | Enter a description for the role in the Description field (e.g., 'Can approve schedule change requests') | Description is entered and displayed in the field |
| 6 | Select relevant permissions by checking checkboxes (e.g., 'View Schedule Changes', 'Approve Schedule Changes', 'Reject Schedule Changes') | Selected permissions are checked and highlighted. Permission count updates to show number of selected permissions |
| 7 | Click Save or Create Role button | System validates the input, creates the role successfully, displays success message 'Role created successfully', and returns to the roles list. New role appears in the roles table with correct name, description, and permission count |
| 8 | Locate the newly created role in the roles list and click on Assign Users or Manage Users action button | User assignment interface opens showing two panels: Available Users (left) and Assigned Users (right). Search and filter options are available |
| 9 | Search for or select test users from the Available Users list by checking their checkboxes | Selected users are highlighted with checkboxes checked |
| 10 | Click Add or Assign button to move selected users to the role | Selected users move from Available Users to Assigned Users panel. User count for the role updates to reflect the number of assigned users |
| 11 | Click Save or Confirm button to finalize user assignments | System saves the assignments, displays success message 'Users assigned successfully', and updates the role's user count in the main roles list |
| 12 | Log out as System Administrator and log in as one of the newly assigned users | User logs in successfully. User interface reflects the permissions assigned to the new role. Features corresponding to assigned permissions (View, Approve, Reject schedule changes) are visible and accessible. Features not included in the role permissions are hidden or disabled |
| 13 | Verify that the user can access schedule change approval features | User can navigate to schedule changes section, view pending schedule change requests, and has access to Approve and Reject action buttons as per the assigned permissions |

**Postconditions:**
- New role is created and saved in UserRoles table
- Role has assigned permissions stored in database
- Users are successfully assigned to the new role
- Role-based access control is enforced for assigned users
- Changes are reflected immediately in user sessions
- Audit log contains entries for role creation and user assignments

---

### Test Case: Verify enforcement of role-based access control
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Two test user accounts exist: User A without approval permissions and User B with approval permissions
- Roles are properly configured with different permission sets
- User A is assigned to a role without 'Approve Schedule Changes' permission (e.g., 'Schedule Viewer' role)
- User B is assigned to a role with 'Approve Schedule Changes' permission (e.g., 'Schedule Approver' role)
- At least one pending schedule change request exists in the system for testing
- System's role-based access control mechanism is active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page and enter credentials for User A (user without approval permissions) | User A is successfully authenticated and logged into the system, redirected to their dashboard |
| 2 | Navigate to the Schedule Changes section from the main menu | Schedule Changes page loads successfully. User A can view the list of schedule change requests with details |
| 3 | Click on a pending schedule change request to view details | Schedule change request details page opens showing all information (requester, date, reason, status). Approve and Reject buttons are NOT visible or are disabled/grayed out. User sees only View or Read-only access. Message may display 'You do not have permission to approve schedule changes' |
| 4 | Attempt to access approval features through direct URL manipulation (if applicable, enter /schedule-changes/approve/[id] in browser) | System denies access and displays error message 'Access Denied' or 'Insufficient Permissions'. User is redirected to unauthorized access page or back to the schedule changes list |
| 5 | Check the main navigation menu and user interface for approval-related options | Approval-related menu items, buttons, and features are hidden or not accessible. User interface reflects limited permissions |
| 6 | Log out as User A | User A is successfully logged out and redirected to login page |
| 7 | Log in with credentials for User B (user with approval permissions) | User B is successfully authenticated and logged into the system, redirected to their dashboard |
| 8 | Navigate to the Schedule Changes section from the main menu | Schedule Changes page loads successfully. User B can view the list of schedule change requests. Additional columns or indicators show approval actions are available |
| 9 | Click on the same pending schedule change request to view details | Schedule change request details page opens showing all information. Approve and Reject buttons ARE visible and enabled. User has full access to approval functionality |
| 10 | Click the Approve button to test approval functionality | Approval confirmation dialog appears asking for confirmation. User can add comments if required |
| 11 | Confirm the approval action | System processes the approval successfully. Success message displays 'Schedule change approved successfully'. Request status updates to 'Approved'. Approval is recorded with User B's name and timestamp |
| 12 | Verify that approval features are consistently accessible throughout the application for User B | All approval-related features, menu items, and buttons are visible and functional for User B across different pages and sections |

**Postconditions:**
- User A confirmed to have restricted access without approval permissions
- User B confirmed to have full access with approval permissions
- Role-based access control is properly enforced
- No unauthorized access occurred
- Test schedule change request status is updated to Approved
- System maintains security and access control integrity

---

### Test Case: Ensure audit logging of role changes
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as System Administrator
- User Roles Management page is accessible
- Audit logging system is enabled and operational
- Database has AuditLogs table with proper schema
- At least one existing role is available for modification
- System clock is synchronized and accurate

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to User Roles Management page as System Administrator | User Roles Management page loads displaying list of existing roles with Create, Edit, and Delete action options |
| 2 | Click Create New Role button and enter role details: Name 'Test Audit Role', Description 'Role for audit testing', and select 2-3 permissions | Create Role form is filled with test data |
| 3 | Click Save button to create the role and note the exact timestamp | Role is created successfully with success message displayed. New role appears in the roles list |
| 4 | Navigate to Audit Logs or Audit Trail section (may be under Reports or Administration menu) | Audit Logs page loads showing a searchable/filterable list of audit entries |
| 5 | Filter or search audit logs by action type 'Role Created' or by recent timestamp, and locate the entry for the newly created role | Audit log entry is found with following details: Action: 'Role Created', Role Name: 'Test Audit Role', User: [Administrator username], Timestamp: [creation time within seconds of action], Details: Permissions assigned, Status: Success |
| 6 | Return to User Roles Management page and click Edit action for the 'Test Audit Role' | Edit Role form opens with current role details populated |
| 7 | Modify the role by changing description to 'Updated role for audit testing' and add or remove one permission, then click Save | Role is updated successfully with success message. Changes are reflected in the roles list |
| 8 | Return to Audit Logs and search for the role modification entry | New audit log entry is found with following details: Action: 'Role Modified' or 'Role Updated', Role Name: 'Test Audit Role', User: [Administrator username], Timestamp: [modification time], Details: Shows what was changed (description updated, permissions added/removed), Previous Values and New Values are logged, Status: Success |
| 9 | Return to User Roles Management page and click Delete action for the 'Test Audit Role' | Delete confirmation dialog appears asking 'Are you sure you want to delete this role?' |
| 10 | Confirm the deletion by clicking Yes or Confirm button | Role is deleted successfully with success message. Role is removed from the roles list |
| 11 | Return to Audit Logs and search for the role deletion entry | New audit log entry is found with following details: Action: 'Role Deleted', Role Name: 'Test Audit Role', User: [Administrator username], Timestamp: [deletion time], Details: Role details before deletion including permissions, Status: Success |
| 12 | Verify completeness of audit trail by reviewing all three entries (Create, Modify, Delete) in sequence | Complete audit trail exists showing full lifecycle of the role. All entries contain: accurate timestamps in chronological order, correct administrator username, detailed action descriptions, before and after values for modifications, no missing or incomplete data. Audit entries are immutable and cannot be edited or deleted |

**Postconditions:**
- All role changes are logged in the audit trail
- Audit logs contain complete information including user, timestamp, and change details
- Test role is deleted from the system
- Audit log entries are permanent and immutable
- Audit trail provides complete compliance record
- System maintains data integrity for audit purposes

---

