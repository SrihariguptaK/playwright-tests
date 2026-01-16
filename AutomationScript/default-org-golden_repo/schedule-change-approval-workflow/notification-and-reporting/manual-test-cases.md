# Manual Test Cases

## Story: As Employee, I want to receive notifications about schedule change request status to stay informed
**Story ID:** story-14

### Test Case: Validate notification delivery on request submission
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has a verified email address on file
- Notification service is operational and configured
- Employee has default notification preferences enabled (email and in-app)
- Employee has permission to submit schedule change requests

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule change request submission page | Schedule change request form is displayed with all required fields |
| 2 | Fill in all required fields for the schedule change request (date, time, reason, etc.) | All fields accept valid input and display no validation errors |
| 3 | Click the 'Submit' button to submit the schedule change request | System displays success message confirming request submission and generates a unique request ID |
| 4 | Check the employee's registered email inbox within 1 minute of submission | Email notification is received confirming submission with request ID, submission timestamp, and request details |
| 5 | Navigate to the in-app notification center or bell icon in the application | In-app notification is displayed confirming submission with request ID, submission timestamp, and request details |
| 6 | Navigate to the employee profile and access the notification history section | Notification history page displays successfully with list of all notifications |
| 7 | Locate the submission notification in the notification history list | Submission notification is listed with correct request ID, timestamp, status, and complete request details matching the submitted information |

**Postconditions:**
- Schedule change request is saved in the system with 'Submitted' status
- Both email and in-app notifications are logged in notification history
- Notification delivery timestamp is recorded in the system
- Request is queued for manager review

---

### Test Case: Verify notification on approval and rejection
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Employee has submitted a schedule change request that is in 'Pending' status
- Manager is logged into the system with valid credentials and approval permissions
- Employee has default notification preferences enabled (email and in-app)
- Notification service is operational
- Employee's email address is verified and active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager navigates to the pending schedule change requests queue | List of pending requests is displayed including the employee's submitted request |
| 2 | Manager selects the employee's schedule change request to review | Request details are displayed with options to Approve, Reject, or Request More Information |
| 3 | Manager clicks 'Approve' button and adds optional approval comments | System displays confirmation dialog for approval action |
| 4 | Manager confirms the approval action | System displays success message, request status changes to 'Approved', and timestamp is recorded |
| 5 | Within 1 minute, check the employee's email inbox | Email notification is received indicating approval with request ID, approval timestamp, manager name, and any comments |
| 6 | Employee logs into the system and checks the in-app notification center | In-app notification is displayed indicating approval with request ID, approval timestamp, manager name, and any comments |
| 7 | Manager navigates to another pending schedule change request from a different employee | Request details are displayed with action options |
| 8 | Manager clicks 'Reject' button and enters mandatory rejection reason | System displays confirmation dialog for rejection action |
| 9 | Manager confirms the rejection action | System displays success message, request status changes to 'Rejected', and timestamp is recorded |
| 10 | Within 1 minute, check the affected employee's email inbox | Email notification is received indicating rejection with request ID, rejection timestamp, manager name, and rejection reason |
| 11 | Affected employee logs into the system and checks the in-app notification center | In-app notification is displayed indicating rejection with request ID, rejection timestamp, manager name, and rejection reason |

**Postconditions:**
- Approved request status is updated to 'Approved' in the database
- Rejected request status is updated to 'Rejected' in the database
- All notifications are logged in notification history for respective employees
- Notification delivery timestamps are recorded
- Approved schedule changes are reflected in the employee's schedule
- Rejected requests remain accessible for employee reference

---

### Test Case: Ensure notification preferences are respected
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has default notification preferences enabled (both email and in-app)
- Employee has access to notification preferences settings
- Notification service is operational
- Employee has at least one pending or active schedule change request

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the employee profile or settings page | Profile/settings page is displayed with navigation options |
| 2 | Click on 'Notification Preferences' or 'Notification Settings' option | Notification preferences page is displayed showing current settings with toggles for email and in-app notifications |
| 3 | Verify current notification preferences show both email and in-app notifications are enabled | Both email and in-app notification toggles are in 'ON' or 'Enabled' state |
| 4 | Toggle the email notification preference to 'OFF' or 'Disabled' | Email notification toggle changes to disabled state while in-app notification remains enabled |
| 5 | Click 'Save' or 'Update Preferences' button | System displays success message confirming preferences have been updated |
| 6 | Trigger a notification event by submitting a new schedule change request or having a manager update an existing request status | Request is processed successfully and notification event is triggered |
| 7 | Within 1 minute, check the employee's email inbox | No email notification is received for the triggered event |
| 8 | Navigate to the in-app notification center in the application | In-app notification is displayed for the triggered event with all relevant details (request ID, status, timestamp) |
| 9 | Navigate back to notification preferences and verify email notifications remain disabled | Email notification toggle remains in 'OFF' state and in-app notification toggle remains in 'ON' state |
| 10 | Check notification history in employee profile | Notification history shows the in-app notification was delivered but no email notification was sent for the recent event |

**Postconditions:**
- Employee notification preferences are updated in the database with email disabled
- System continues to send only in-app notifications for future events
- Preference change is logged in the audit trail
- No email notifications are queued or sent for this employee until preferences are changed again

---

## Story: As Administrator, I want to configure approval workflows for schedule changes to align with organizational policies
**Story ID:** story-15

### Test Case: Verify administrator can create and save valid workflow configurations
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Administrator is logged into the system with valid admin credentials
- Administrator has 'Administrator' role with workflow configuration permissions
- Workflow configuration UI is accessible and operational
- At least one existing workflow configuration exists in the system
- Valid approver users and roles are defined in the system
- Database connection is active and ApprovalWorkflowConfig table is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the administration portal or admin dashboard | Admin dashboard is displayed with administrative menu options |
| 2 | Click on 'Approval Workflow Settings' or 'Workflow Configuration' menu option | Workflow configuration UI is displayed showing list of current workflow configurations with details (name, approvers, rules, status) |
| 3 | Verify the UI displays options to create new workflow, edit existing workflows, and view workflow details | UI shows 'Create New Workflow' button and action buttons (Edit, View, Delete) for each existing workflow |
| 4 | Click 'Create New Workflow' button | Workflow creation form is displayed with fields for workflow name, description, approval levels, approvers, and conditional rules |
| 5 | Enter a unique workflow name (e.g., 'Department Manager Approval Workflow') | Workflow name field accepts input without validation errors |
| 6 | Enter workflow description (e.g., 'Two-level approval for schedule changes requiring department manager and HR approval') | Description field accepts input without validation errors |
| 7 | Add first approval level by clicking 'Add Approval Level' and select 'Department Manager' role as approver | First approval level is added with Department Manager role displayed, showing level order as 1 |
| 8 | Add second approval level and select 'HR Manager' role as approver | Second approval level is added with HR Manager role displayed, showing level order as 2 |
| 9 | Add conditional routing rule: 'If request duration > 5 days, require additional VP approval' | Conditional rule is added and displayed in the rules section with condition and action clearly shown |
| 10 | Click 'Validate Configuration' button | System validates the workflow configuration and displays success message: 'Workflow configuration is valid' |
| 11 | Click 'Save' button to save the new workflow configuration | System displays success message confirming workflow has been saved, and new workflow appears in the workflow list with 'Active' status |
| 12 | Wait for 5 minutes to allow configuration propagation | Time elapses without system errors |
| 13 | As an employee user, submit a new schedule change request that matches the workflow criteria | Schedule change request is submitted successfully with confirmation message |
| 14 | As administrator, navigate to the submitted request details and verify approval workflow assignment | Request shows the newly created workflow is assigned with approval routing to Department Manager as first approver |
| 15 | Verify the approval chain displays both Department Manager and HR Manager in correct sequence | Approval chain shows Level 1: Department Manager (Pending), Level 2: HR Manager (Awaiting Level 1) |

**Postconditions:**
- New workflow configuration is saved in ApprovalWorkflowConfig table
- Workflow is marked as 'Active' and available for assignment
- Configuration change is logged in audit trail with administrator username and timestamp
- New schedule change requests automatically use the updated workflow
- Existing pending requests continue using their originally assigned workflows

---

### Test Case: Ensure invalid workflow configurations are rejected
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Administrator is logged into the system with valid admin credentials
- Administrator has 'Administrator' role with workflow configuration permissions
- Workflow configuration UI is accessible and operational
- System validation rules are active and configured
- Database connection is active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the workflow configuration UI via admin dashboard | Workflow configuration page is displayed with list of existing workflows |
| 2 | Click 'Create New Workflow' button | Workflow creation form is displayed with all required fields |
| 3 | Enter workflow name 'Test Invalid Workflow - Missing Approvers' and description | Name and description fields accept input |
| 4 | Leave the approvers section empty without adding any approval levels | Form displays with no approval levels configured |
| 5 | Click 'Save' button to attempt saving the workflow without approvers | System prevents save operation and displays error message: 'Workflow must have at least one approval level with a valid approver' |
| 6 | Verify the workflow was not saved by checking the workflow list | New workflow does not appear in the workflow configuration list |
| 7 | Click 'Create New Workflow' button again to test circular rule scenario | New workflow creation form is displayed |
| 8 | Enter workflow name 'Test Circular Rule Workflow' and add Department Manager as Level 1 approver | Workflow name is entered and Level 1 approver is configured |
| 9 | Add conditional rule: 'If Department Manager rejects, route back to Department Manager for re-approval' | Conditional rule is entered in the rules section |
| 10 | Click 'Validate Configuration' button | System detects circular routing logic and displays error message: 'Circular approval routing detected. Approver cannot route back to themselves.' |
| 11 | Click 'Save' button to attempt saving the workflow with circular rule | System prevents save operation and displays error message: 'Cannot save workflow with validation errors. Please fix circular routing rule.' |
| 12 | Verify the workflow was not saved by checking the workflow list | Circular rule workflow does not appear in the workflow configuration list |
| 13 | Attempt to create workflow with duplicate name of an existing workflow | System displays error message: 'Workflow name already exists. Please use a unique name.' |
| 14 | Attempt to create workflow with special characters or SQL injection patterns in the name field | System displays error message: 'Invalid characters detected. Workflow name can only contain alphanumeric characters, spaces, and hyphens.' |

**Postconditions:**
- No invalid workflow configurations are saved in the database
- System maintains data integrity by rejecting malformed configurations
- Error messages are logged for audit purposes
- Existing valid workflows remain unaffected
- Administrator remains on the configuration page to correct errors

---

### Test Case: Verify access control for workflow configuration features
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Non-administrator user account exists with 'Employee' or 'Manager' role (not Administrator role)
- Non-administrator user has valid login credentials
- Workflow configuration feature is protected by role-based access control
- Administrator role is properly configured in the system
- Authentication and authorization services are operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system using non-administrator user credentials (Employee or Manager role) | User successfully logs in and is redirected to their role-appropriate dashboard |
| 2 | Verify the main navigation menu or dashboard for presence of admin options | Administration menu, admin dashboard link, or workflow configuration options are not visible in the navigation |
| 3 | Attempt to manually navigate to workflow configuration URL by entering '/admin/workflow-configuration' or similar path in browser address bar | System denies access and displays error message: 'Access Denied. You do not have permission to access this resource.' or redirects to unauthorized page (403 Forbidden) |
| 4 | Verify the user remains on an error page or is redirected to their appropriate dashboard | User is not able to access workflow configuration UI and sees appropriate error message or is redirected |
| 5 | Attempt to access workflow configuration API endpoint directly using browser developer tools or API client (GET /api/workflows) | API returns 403 Forbidden status code with error message: 'Insufficient permissions. Administrator role required.' |
| 6 | Attempt to create a workflow using API endpoint (POST /api/workflows) with non-admin credentials | API returns 403 Forbidden status code with error message: 'Insufficient permissions. Administrator role required.' |
| 7 | Log out the non-administrator user | User is successfully logged out and redirected to login page |
| 8 | Log in using administrator credentials | Administrator successfully logs in and is redirected to admin dashboard |
| 9 | Verify administration menu and workflow configuration options are visible | Admin navigation menu displays with 'Workflow Configuration' or 'Approval Workflow Settings' option visible |
| 10 | Navigate to workflow configuration UI | Workflow configuration page loads successfully with full access to view, create, edit, and delete workflows |
| 11 | Verify access is logged by checking audit trail or access logs | System logs show denied access attempts by non-administrator user with timestamp and user ID |

**Postconditions:**
- Non-administrator users cannot access workflow configuration features
- Administrator users retain full access to workflow configuration
- All unauthorized access attempts are logged in audit trail
- System security and role-based access control remain intact
- No unauthorized changes are made to workflow configurations

---

## Story: As Manager, I want to generate reports on schedule change approvals to monitor workflow efficiency
**Story ID:** story-16

### Test Case: Validate report generation with filters
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Manager user is logged into the system with valid credentials
- Manager has role-based access to the reporting module
- Approval workflow data exists in the system (ApprovalActions and ScheduleChangeRequests tables)
- At least one department with approval data is available
- Date range contains approval records for testing

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the reporting module from the main dashboard | Reporting module page loads successfully and displays available report types |
| 2 | Select 'Approval Workflow Report' from the report type dropdown | Filter options for date range and department are displayed |
| 3 | Select a start date and end date for the report (e.g., last 30 days) | Date range is accepted and displayed in the filter section |
| 4 | Select one or more departments from the department filter dropdown | Selected departments are displayed in the filter section |
| 5 | Click the 'Generate Report' button | Report generation begins and a loading indicator is displayed |
| 6 | Wait for report generation to complete | Report is generated within 5 seconds and displays filtered data including approval times, volumes, and outcomes for the selected date range and departments |
| 7 | Review the report data table for accuracy | Report displays correct data matching the applied filters with columns for request ID, department, submission date, approval time, status, and outcome |
| 8 | Scroll down to view visualizations section | Visualizations section is visible with charts for approval times and volumes |
| 9 | Examine the approval times visualization (e.g., bar chart or line graph) | Visualization accurately reflects the approval time data from the report, showing time metrics by department or date |
| 10 | Examine the approval volumes visualization (e.g., pie chart or bar chart) | Visualization accurately reflects the approval volume data from the report, showing counts by status or department |
| 11 | Verify that visualization data matches the tabular report data | All numbers and metrics in visualizations correspond exactly to the data shown in the report table |

**Postconditions:**
- Report remains displayed on screen for further actions
- Filter selections are retained for potential report modifications
- Report data is cached for export functionality
- System logs the report generation activity

---

### Test Case: Verify report export functionality
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Manager user is logged into the system with valid credentials
- Manager has successfully generated an approval workflow report
- Report is currently displayed on screen with data
- Browser allows file downloads
- System has export functionality enabled for CSV and PDF formats

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate the export options section on the generated report page | Export section is visible with options for CSV and PDF formats |
| 2 | Click the 'Export as CSV' button | CSV file download begins immediately and browser shows download progress |
| 3 | Wait for CSV download to complete and locate the downloaded file | CSV file is successfully downloaded to the default downloads folder with a descriptive filename (e.g., 'Approval_Workflow_Report_YYYY-MM-DD.csv') |
| 4 | Open the downloaded CSV file in a spreadsheet application (e.g., Excel, Google Sheets) | CSV file opens successfully and displays all report data in proper columns |
| 5 | Verify CSV content includes all data fields: request ID, department, dates, approval times, status, and outcomes | All data fields are present and values match the report displayed on screen |
| 6 | Verify CSV formatting is correct with proper delimiters and no data corruption | Data is properly formatted with comma delimiters, headers in first row, and all special characters are correctly encoded |
| 7 | Return to the report page in the browser | Report page is still displayed with the same data |
| 8 | Click the 'Export as PDF' button | PDF file download begins immediately and browser shows download progress |
| 9 | Wait for PDF download to complete and locate the downloaded file | PDF file is successfully downloaded to the default downloads folder with a descriptive filename (e.g., 'Approval_Workflow_Report_YYYY-MM-DD.pdf') |
| 10 | Open the downloaded PDF file in a PDF reader application | PDF file opens successfully and displays the report with proper formatting |
| 11 | Verify PDF content includes report title, filter parameters, data table, and visualizations | PDF contains all report elements including header with filters applied, complete data table, and chart visualizations |
| 12 | Verify PDF data accuracy by comparing values to the on-screen report | All data values in the PDF match exactly with the report displayed on screen |
| 13 | Check PDF formatting for readability including page breaks, headers, and footers | PDF is professionally formatted with proper page breaks, page numbers, report generation timestamp, and company branding if applicable |

**Postconditions:**
- Two files (CSV and PDF) are saved in the downloads folder
- Both exported files contain accurate and complete report data
- Original report remains displayed on screen
- System logs the export activities
- Files are ready for sharing or archival purposes

---

### Test Case: Ensure scheduled report delivery
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Manager user is logged into the system with valid credentials
- Manager has access to the reporting module with scheduling capabilities
- Manager has a valid email address configured in their user profile
- Email delivery service is configured and operational
- SMTP settings are properly configured in the system
- At least one report configuration exists or can be created

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the reporting module and generate or select an approval workflow report | Report is displayed with scheduling options available |
| 2 | Locate and click the 'Schedule Report' button or link | Schedule report configuration dialog or page opens |
| 3 | Select 'Daily' from the frequency dropdown menu | Daily frequency is selected and additional daily scheduling options appear |
| 4 | Select the time for daily delivery (e.g., 8:00 AM) | Selected time is displayed in the schedule configuration |
| 5 | Verify the email address field is pre-populated with the manager's email | Manager's email address from user profile is displayed in the recipient field |
| 6 | Optionally add additional recipient email addresses if the feature allows | Additional email addresses can be added and are displayed in the recipient list |
| 7 | Select the report format for email delivery (CSV, PDF, or both) | Selected format(s) are indicated in the schedule configuration |
| 8 | Review the schedule summary showing frequency, time, recipients, and format | Schedule summary displays all configured parameters correctly |
| 9 | Click the 'Save Schedule' or 'Activate Schedule' button | Schedule is saved successfully and a confirmation message is displayed |
| 10 | Navigate to the scheduled reports list or dashboard | Newly created schedule appears in the list with status 'Active' and shows next scheduled run time |
| 11 | Wait for the scheduled time or trigger a test delivery if available | System processes the scheduled report at the designated time |
| 12 | Check the manager's email inbox at or shortly after the scheduled delivery time | Email is received with the subject line containing the report name and date |
| 13 | Open the received email and verify the email body contains report summary or description | Email body includes report details, date range, and any relevant summary information |
| 14 | Verify the email contains the report attachment(s) in the specified format(s) | Report file(s) are attached in the selected format (CSV and/or PDF) with appropriate filenames |
| 15 | Download and open the attached report file(s) | Attached files open successfully and contain accurate, up-to-date approval workflow data |
| 16 | Return to the system and check the scheduled report execution log | Execution log shows successful delivery with timestamp and recipient information |

**Postconditions:**
- Scheduled report is active and will continue to run daily at the specified time
- Email delivery is logged in the system
- Manager receives automated reports without manual intervention
- Schedule can be modified or deactivated by the manager as needed
- System maintains schedule configuration for future executions

---

