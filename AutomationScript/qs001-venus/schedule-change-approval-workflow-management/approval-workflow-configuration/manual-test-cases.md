# Manual Test Cases

## Story: As Administrator, I want to define multi-level approval workflows to achieve flexible schedule change approvals
**Story ID:** story-1

### Test Case: Validate successful creation of multi-level approval workflow
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Administrator is logged into the system with valid credentials
- Administrator has role-based access permissions to configure workflows
- Workflow configuration database is accessible and operational
- At least two potential approvers exist in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Administrator navigates to workflow configuration page by clicking on 'Workflow Management' menu option | Workflow configuration UI is displayed with options to create new workflow, view existing workflows, and workflow management tools are visible |
| 2 | Administrator clicks 'Create New Workflow' button | New workflow creation form is displayed with fields for workflow name, description, and approval levels |
| 3 | Administrator enters workflow name 'Schedule Change Approval - Level 2' and description 'Two-level approval for schedule modifications' | Workflow name and description are accepted and displayed in the form fields |
| 4 | Administrator clicks 'Add Approval Level' button to create first approval level | First approval level section is displayed with fields for level name and approver assignment |
| 5 | Administrator enters level name 'Manager Approval' and assigns approver 'John Smith' from the approver dropdown list | Level 1 is configured with name 'Manager Approval' and approver 'John Smith' is displayed as assigned |
| 6 | Administrator clicks 'Add Approval Level' button to create second approval level | Second approval level section is displayed below the first level with fields for level name and approver assignment |
| 7 | Administrator enters level name 'Director Approval' and assigns approver 'Jane Doe' from the approver dropdown list | Level 2 is configured with name 'Director Approval' and approver 'Jane Doe' is displayed as assigned. Both workflow levels and approvers are displayed correctly in hierarchical order |
| 8 | Administrator reviews the complete workflow configuration and clicks 'Save Workflow' button | System validates the workflow configuration, processes the save request, and displays confirmation message 'Workflow created successfully' with workflow ID |

**Postconditions:**
- New workflow is saved in the workflow configuration database
- Workflow appears in the list of available workflows
- Workflow is available for assignment to schedule change requests
- Audit log records workflow creation with administrator details and timestamp

---

### Test Case: Prevent saving workflow with circular dependencies
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Administrator is logged into the system with valid credentials
- Administrator has role-based access permissions to configure workflows
- Workflow configuration page is accessible
- System has circular dependency validation logic enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Administrator navigates to workflow configuration page and clicks 'Create New Workflow' button | New workflow creation form is displayed with empty fields ready for input |
| 2 | Administrator enters workflow name 'Circular Test Workflow' and adds three approval levels | Three approval level sections are displayed and ready for configuration |
| 3 | Administrator configures Level 1 with approver 'User A' and sets conditional routing to Level 2 | Level 1 is configured with User A and routing to Level 2 is displayed |
| 4 | Administrator configures Level 2 with approver 'User B' and sets conditional routing to Level 3 | Level 2 is configured with User B and routing to Level 3 is displayed |
| 5 | Administrator configures Level 3 with approver 'User C' and attempts to set conditional routing back to Level 1, creating a circular dependency | Level 3 configuration shows routing back to Level 1 |
| 6 | Administrator clicks 'Save Workflow' button | System detects circular dependency in the approval routing (Level 1 → Level 2 → Level 3 → Level 1) and displays error message 'Cannot save workflow: Circular dependency detected in approval routing. Please review and correct the workflow configuration.' |
| 7 | Administrator reviews the error message and removes the circular routing by changing Level 3 routing to 'End Workflow' instead of Level 1 | Level 3 configuration is updated to end the workflow without circular routing |
| 8 | Administrator clicks 'Save Workflow' button again | System validates the corrected workflow configuration, detects no circular dependencies, and displays confirmation message 'Workflow created successfully'. The corrected workflow is saved to the database |

**Postconditions:**
- Workflow with corrected configuration is saved in the database
- No circular dependencies exist in the saved workflow
- Workflow is available for use in schedule change approvals
- Error and correction actions are logged in the audit trail

---

### Test Case: Validate mandatory approver per level before saving
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Administrator is logged into the system with valid credentials
- Administrator has permissions to create and configure workflows
- Workflow configuration page is accessible
- System has mandatory field validation enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Administrator navigates to workflow configuration page and clicks 'Create New Workflow' button | New workflow creation form is displayed with all required fields empty |
| 2 | Administrator enters workflow name 'Incomplete Workflow Test' and description 'Testing mandatory approver validation' | Workflow name and description are accepted and displayed in the form |
| 3 | Administrator clicks 'Add Approval Level' button to create first approval level | First approval level section is displayed with fields for level name and approver assignment |
| 4 | Administrator enters level name 'Manager Review' but leaves the approver field empty without selecting any approver | Level name 'Manager Review' is displayed but approver field remains empty with no selection |
| 5 | Administrator clicks 'Save Workflow' button without assigning an approver to the level | System performs validation and displays error message 'Cannot save workflow: Each approval level must have at least one approver assigned. Please assign an approver to Level 1.' The workflow is not saved and the form remains in edit mode |
| 6 | Administrator reviews the validation error and clicks on the approver dropdown for Level 1 | Approver dropdown list is displayed showing available approvers in the system |
| 7 | Administrator selects 'Sarah Johnson' as the approver for Level 1 | Approver 'Sarah Johnson' is assigned to Level 1 and displayed in the approver field |
| 8 | Administrator clicks 'Save Workflow' button again | System validates the workflow configuration, confirms all mandatory fields are completed, and displays success message 'Workflow saved successfully' with the workflow ID |

**Postconditions:**
- Workflow is successfully saved with all required approvers assigned
- Workflow appears in the active workflows list
- All approval levels have at least one approver assigned
- Validation error and successful save are recorded in the system audit log

---

## Story: As Administrator, I want to configure notification settings to achieve timely communication for schedule change approvals
**Story ID:** story-4

### Test Case: Create and save notification template successfully
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Administrator is logged into the system with valid administrator credentials
- Administrator has admin-only access to notification configuration
- Notification configuration database is accessible and operational
- Notification settings page is available in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Administrator clicks on 'Settings' menu and selects 'Notification Configuration' option | Notification configuration UI is displayed showing list of notification events (submission, approval, rejection, escalation) and existing templates |
| 2 | Administrator clicks 'Create New Template' button | Template creation form is displayed with fields for template name, event type, subject line, message body, and recipient configuration |
| 3 | Administrator selects 'Approval' from the event type dropdown | Event type is set to 'Approval' and relevant template variables for approval events are displayed |
| 4 | Administrator enters template name 'Schedule Change Approved Notification' | Template name is accepted and displayed in the template name field |
| 5 | Administrator enters subject line 'Your Schedule Change Request Has Been Approved' | Subject line is accepted and displayed in the subject field |
| 6 | Administrator enters message body in the template editor: 'Dear {{requester_name}}, Your schedule change request #{{request_id}} has been approved by {{approver_name}} on {{approval_date}}. The changes will be effective from {{effective_date}}.' | Template editor accepts the input with template variables properly formatted and syntax highlighting is displayed for variables |
| 7 | Administrator configures recipients by selecting 'Requester' and 'Manager' roles from the recipient list | Selected recipient roles are displayed in the recipients section |
| 8 | Administrator selects notification delivery method as 'Email' from the delivery options | Email delivery method is selected and displayed as the active delivery channel |
| 9 | Administrator clicks 'Save Template' button | System validates the template configuration, saves the template to the notification configuration database, and displays confirmation message 'Notification template saved successfully' with template ID |

**Postconditions:**
- New notification template is saved in the notification configuration database
- Template appears in the list of available notification templates
- Template is available for selection in workflow notification settings
- Template creation is logged in the audit trail with administrator details and timestamp

---

### Test Case: Prevent saving notification template with invalid syntax
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Administrator is logged into the system with administrator privileges
- Notification settings page is accessible
- Template syntax validation is enabled in the system
- Notification configuration database is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Administrator navigates to notification settings page and clicks 'Create New Template' button | Template creation form is displayed with empty fields ready for input |
| 2 | Administrator enters template name 'Invalid Syntax Test Template' and selects event type 'Rejection' | Template name and event type are set and displayed in the form |
| 3 | Administrator enters subject line 'Schedule Change Request Rejected' | Subject line is accepted and displayed |
| 4 | Administrator enters message body with invalid template syntax: 'Dear {{requester_name, Your request {{request_id} has been rejected by {{approver_name on {{rejection_date}}.' (missing closing braces and commas in wrong places) | Message body with invalid syntax is entered in the template editor |
| 5 | Administrator configures recipients as 'Requester' and selects 'Email' as delivery method | Recipients and delivery method are configured and displayed |
| 6 | Administrator clicks 'Save Template' button | System performs syntax validation and displays validation error message 'Cannot save template: Invalid template syntax detected. Error at line 1: Missing closing brace for variable {{requester_name. Error at line 1: Missing closing brace for variable {{request_id. Error at line 1: Missing closing brace for variable {{approver_name.' The template is not saved and remains in edit mode |
| 7 | Administrator reviews the validation errors and corrects the message body to: 'Dear {{requester_name}}, Your request {{request_id}} has been rejected by {{approver_name}} on {{rejection_date}}.' | Corrected message body with proper syntax is displayed in the template editor with all variables properly closed |
| 8 | Administrator clicks 'Save Template' button again | System validates the corrected template syntax, confirms no syntax errors, saves the template successfully, and displays confirmation message 'Template saved successfully' with template ID |

**Postconditions:**
- Template with corrected syntax is saved in the notification configuration database
- Template is available for use in notification workflows
- All template variables are properly formatted and validated
- Validation error and successful save are recorded in the system audit log

---

### Test Case: Test notification delivery
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 4 mins

**Preconditions:**
- Administrator is logged into the system with valid credentials
- At least one notification template is configured and saved in the system
- Test notification functionality is enabled
- Administrator has a valid email address configured in their profile
- Email notification service is operational and accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Administrator navigates to notification settings page | Notification settings page is displayed with list of configured notification templates |
| 2 | Administrator selects an existing notification template 'Schedule Change Approved Notification' from the template list | Selected template details are displayed including template name, event type, subject, message body, and recipient configuration |
| 3 | Administrator clicks 'Test Notification' button | Test notification dialog is displayed with options to enter test recipient email address and preview the notification content |
| 4 | Administrator enters test recipient email address 'admin.test@company.com' in the recipient field | Test recipient email address is accepted and displayed in the recipient field |
| 5 | Administrator reviews the notification preview showing sample data populated in template variables | Notification preview displays the template with sample values: 'Dear John Doe, Your schedule change request #12345 has been approved by Jane Smith on 2024-01-15. The changes will be effective from 2024-01-20.' |
| 6 | Administrator clicks 'Send Test Notification' button | System processes the test notification request, sends the notification to the configured recipient email address, and displays progress indicator 'Sending notification...' |
| 7 | System completes notification delivery and administrator observes the result | Notification is sent to configured recipient 'admin.test@company.com' successfully |
| 8 | Administrator views the delivery confirmation on screen | System displays success message 'Test notification sent successfully to admin.test@company.com. Delivery confirmed at 2024-01-15 10:30:45 AM' with timestamp and delivery status |
| 9 | Administrator checks the test recipient email inbox | Test notification email is received in the inbox with correct subject line, message body with populated variables, and proper formatting |

**Postconditions:**
- Test notification is successfully delivered to the specified recipient
- Delivery confirmation is recorded in the notification logs
- Template functionality is verified as working correctly
- Test notification activity is logged in the audit trail with delivery status and timestamp

---

## Story: As Administrator, I want to manage user roles and permissions for approval workflows to achieve secure access control
**Story ID:** story-8

### Test Case: Create and assign user roles successfully
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Administrator is logged into the system with admin privileges
- User management module is accessible
- At least 2 test users exist in the system for role assignment
- Database connection is active and stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the user management module from the admin dashboard | User management module loads successfully displaying existing roles and users |
| 2 | Click on 'Create New Role' button | Role creation form is displayed with fields for role name, description, and permissions |
| 3 | Enter role name as 'Workflow Manager' and description as 'Manages approval workflows' | Role name and description are accepted and displayed in the form fields |
| 4 | Select specific permissions: 'Configure Workflows', 'View Submissions', 'Manage Approvers' | Selected permissions are highlighted and marked as active for this role |
| 5 | Click 'Save Role' button | Success message is displayed, and the new role 'Workflow Manager' appears in the role list with assigned permissions |
| 6 | Select the newly created 'Workflow Manager' role from the role list | Role details page opens showing role name, description, permissions, and user assignment section |
| 7 | Click 'Assign Users' button and select 2 test users from the available user list | Selected users are displayed in the assignment preview section |
| 8 | Click 'Confirm Assignment' button | Success message is displayed, and the 2 users are now listed under the 'Workflow Manager' role with assigned permissions applied |
| 9 | Log out as Administrator and log in as one of the assigned users | User successfully logs in and can access workflow configuration features as per assigned permissions |

**Postconditions:**
- New role 'Workflow Manager' exists in the system with defined permissions
- 2 users are assigned to the 'Workflow Manager' role
- Assigned users have active permissions for workflow configuration
- Role creation and assignment are logged in audit trail

---

### Test Case: Enforce permissions across approval modules
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Multiple user roles exist with different permission levels
- Test user 'User A' exists without 'Approve Requests' permission
- Test user 'User B' exists with 'Approver' role having 'Approve Requests' permission
- At least one approval request is pending in the system
- Both users have valid login credentials

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system as 'User A' who does not have 'Approve Requests' permission | User A successfully logs in and is directed to the dashboard |
| 2 | Navigate to the approval workflow module | Approval workflow module loads showing limited view based on user permissions |
| 3 | Attempt to access the pending approval request and click 'Approve' button | Access is denied with error message: 'You do not have permission to approve requests. Please contact your administrator.' |
| 4 | Verify that the approval action was not executed by checking the request status | Request status remains 'Pending' and no approval action is recorded |
| 5 | Log out as 'User A' and log in as 'User B' with 'Approver' role | User B successfully logs in with approver privileges |
| 6 | Navigate to the approval workflow module and access the same pending approval request | Approval request details are displayed with active 'Approve' and 'Reject' buttons |
| 7 | Click 'Approve' button and add approval comments | Approval action succeeds, success message is displayed, and request status changes to 'Approved' |
| 8 | Verify the approval is recorded with User B's name and timestamp | Approval history shows User B as approver with correct timestamp and comments |

**Postconditions:**
- User A's unauthorized access attempt is blocked and logged
- User B's approval action is successfully completed
- Request status is updated to 'Approved'
- Permission enforcement is validated across the approval module
- All actions are recorded in system audit logs

---

### Test Case: Audit logging of role and user assignment changes
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Administrator is logged into the system
- Existing role 'Manager' is available in the system
- Test user 'John Doe' exists and is assigned to 'Manager' role
- Audit logging functionality is enabled
- Administrator has access to audit log viewer

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to user management module and select the 'Manager' role | Manager role details are displayed with current permissions and assigned users |
| 2 | Click 'Edit Permissions' and add new permission 'Delete Workflows' | Permission is added to the role's permission list |
| 3 | Click 'Save Changes' button | Success message is displayed confirming permission update for 'Manager' role |
| 4 | Navigate to user assignment section and remove user 'John Doe' from 'Manager' role | Confirmation dialog appears asking to confirm user removal |
| 5 | Confirm the removal action | Success message is displayed and 'John Doe' is no longer listed under 'Manager' role |
| 6 | Navigate to the audit log viewer from the admin menu | Audit log interface loads displaying recent system activities |
| 7 | Filter audit logs by 'Role Management' category and today's date | Filtered audit logs display only role and permission related changes |
| 8 | Locate the log entry for 'Manager' role permission change | Log entry shows: Action='Permission Added', Role='Manager', Permission='Delete Workflows', Changed By='Administrator', Timestamp=current date/time |
| 9 | Locate the log entry for user assignment change | Log entry shows: Action='User Removed from Role', User='John Doe', Role='Manager', Changed By='Administrator', Timestamp=current date/time |
| 10 | Export audit logs to CSV format and verify data integrity | CSV file is downloaded containing all logged changes with complete and accurate information |

**Postconditions:**
- Manager role has updated permissions including 'Delete Workflows'
- User 'John Doe' is removed from 'Manager' role
- All changes are logged in audit trail with administrator details and timestamps
- Audit logs are accessible and exportable for compliance review
- System maintains complete audit history for security compliance

---

## Story: As Administrator, I want to validate approval workflow configurations to achieve error-free setups
**Story ID:** story-10

### Test Case: Detect circular dependencies in workflow
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Administrator is logged into the system with workflow configuration privileges
- Workflow configuration module is accessible
- System validation engine is active and functional
- No existing workflows with circular dependencies exist

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the workflow configuration module from the admin dashboard | Workflow configuration interface loads displaying options to create or edit workflows |
| 2 | Click 'Create New Workflow' button | Workflow creation form is displayed with fields for workflow name, description, and approval routing |
| 3 | Enter workflow name as 'Purchase Approval' and description as 'Multi-level purchase approval process' | Workflow name and description are accepted and displayed in the form |
| 4 | Add approval level 'Level 1' with approver 'Manager A' and set routing to 'Level 2' | Level 1 is created with Manager A assigned and routing configured to Level 2 |
| 5 | Add approval level 'Level 2' with approver 'Manager B' and set routing to 'Level 3' | Level 2 is created with Manager B assigned and routing configured to Level 3 |
| 6 | Add approval level 'Level 3' with approver 'Director C' and set routing back to 'Level 1' creating a circular loop | Level 3 is created with Director C assigned and routing configured back to Level 1 |
| 7 | Click 'Save Workflow' button | System displays validation error message: 'Circular dependency detected: Level 1 → Level 2 → Level 3 → Level 1. Please correct the approval routing to prevent infinite loops.' |
| 8 | Verify that the workflow is not saved by checking the workflow list | Workflow 'Purchase Approval' does not appear in the saved workflows list |
| 9 | Edit Level 3 routing and change it from 'Level 1' to 'End Workflow' | Level 3 routing is updated to terminate the workflow instead of looping back |
| 10 | Click 'Save Workflow' button again | Success message is displayed: 'Workflow saved successfully', and 'Purchase Approval' workflow appears in the workflow list with valid routing |

**Postconditions:**
- Circular dependency validation is confirmed to be working correctly
- Invalid workflow with circular routing is prevented from being saved
- Corrected workflow without circular dependencies is successfully saved
- Workflow 'Purchase Approval' exists with valid linear approval routing
- Validation error and successful save are logged in system logs

---

### Test Case: Prevent saving workflow with missing approvers
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 9 mins

**Preconditions:**
- Administrator is logged into the system
- Workflow configuration module is accessible
- At least one user with approver role exists in the system
- Validation rules for mandatory approvers are configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to workflow configuration module and click 'Create New Workflow' | Workflow creation form is displayed with empty approval level configuration |
| 2 | Enter workflow name as 'Expense Approval' and description as 'Employee expense approval workflow' | Workflow name and description are entered successfully |
| 3 | Add approval level 'Level 1 - Team Lead' and assign approver 'Sarah Johnson' | Level 1 is created with Sarah Johnson assigned as approver |
| 4 | Add approval level 'Level 2 - Department Manager' but leave the approver field empty | Level 2 is created but approver field remains empty with no selection |
| 5 | Add approval level 'Level 3 - Finance Director' and assign approver 'Michael Chen' | Level 3 is created with Michael Chen assigned as approver |
| 6 | Click 'Save Workflow' button | System displays validation error message: 'Approval level 'Level 2 - Department Manager' requires at least one approver. Please assign an approver before saving.' Save action is blocked. |
| 7 | Verify the error indicator is displayed on Level 2 approval section | Red error indicator or highlight appears on Level 2 section showing missing approver |
| 8 | Attempt to navigate away from the workflow configuration page | Warning message appears: 'You have unsaved changes. Are you sure you want to leave?' |
| 9 | Cancel navigation and return to Level 2 configuration, then assign approver 'David Martinez' | David Martinez is successfully assigned to Level 2, and error indicator is removed |
| 10 | Click 'Save Workflow' button | Success message is displayed: 'Workflow saved successfully', and 'Expense Approval' workflow appears in the workflow list with all approvers assigned |

**Postconditions:**
- Workflow with missing approvers is prevented from being saved
- Validation error clearly identifies the approval level with missing approver
- Corrected workflow with all approvers assigned is successfully saved
- Workflow 'Expense Approval' exists with complete approver assignments at all levels
- Validation enforcement is logged for audit purposes

---

### Test Case: Validate conditional routing logic
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Administrator is logged into the system
- Workflow configuration module supports conditional routing
- Conditional logic syntax rules are documented and available
- Test approvers exist in the system for assignment

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to workflow configuration module and click 'Create New Workflow' | Workflow creation form is displayed with conditional routing options |
| 2 | Enter workflow name as 'Invoice Approval' and description as 'Conditional invoice approval based on amount' | Workflow name and description are entered successfully |
| 3 | Add approval level 'Level 1 - Supervisor' with approver 'Alice Brown' | Level 1 is created with Alice Brown assigned |
| 4 | Enable conditional routing for Level 1 and enter invalid condition: 'IF amount > $5000 THEN goto Level 2 ELSE goto' | Conditional routing field accepts the input and displays it in the configuration |
| 5 | Add approval level 'Level 2 - Finance Manager' with approver 'Robert Lee' | Level 2 is created with Robert Lee assigned |
| 6 | Click 'Save Workflow' button | System displays validation error: 'Invalid conditional routing logic at Level 1: ELSE clause is incomplete. Please specify a valid routing destination or action.' |
| 7 | Verify that the error message highlights the specific syntax issue in the conditional logic | Error message includes details about the incomplete ELSE clause and suggests correction |
| 8 | Click 'View Syntax Help' link in the error message | Help panel opens displaying conditional routing syntax examples and valid operators |
| 9 | Correct the conditional routing logic to: 'IF amount > $5000 THEN goto Level 2 ELSE end workflow' | Corrected conditional logic is entered and displayed in the routing configuration |
| 10 | Click 'Validate Logic' button to test the condition syntax | System displays validation success message: 'Conditional routing logic is valid' |
| 11 | Click 'Save Workflow' button | Success message is displayed: 'Workflow saved successfully', and 'Invoice Approval' workflow appears in the workflow list with valid conditional routing |

**Postconditions:**
- Invalid conditional routing logic is detected and prevented from being saved
- Clear validation error messages guide administrator to correct syntax issues
- Corrected workflow with valid conditional routing is successfully saved
- Workflow 'Invoice Approval' exists with properly configured conditional logic
- Validation results are logged for troubleshooting and audit purposes

---

## Story: As Manager, I want to receive notifications on schedule change request status updates to achieve timely awareness
**Story ID:** story-11

### Test Case: Receive notification upon request submission
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Manager is logged into the system
- Manager has valid notification preferences configured
- Manager has at least one notification channel (email/SMS) enabled
- Email/SMS gateway services are operational
- Manager has permission to submit schedule change requests

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager navigates to the schedule change request form | Schedule change request form is displayed with all required fields |
| 2 | Manager fills in all required fields (date, time, reason, etc.) for the schedule change request | All fields are populated correctly and validation passes |
| 3 | Manager clicks the 'Submit' button to submit the schedule change request | System displays success message confirming request submission and generates a unique request ID |
| 4 | System processes the submission and triggers notification service | System sends submission confirmation notification to manager's preferred channel within 1 minute |
| 5 | Manager checks their preferred notification channel (email or SMS) | Manager receives notification via preferred channel |
| 6 | Manager reviews the notification content | Notification contains correct request details including request ID, date, time, reason, submission timestamp, and current status as 'Submitted' |
| 7 | Verify notification delivery is logged in the system | System logs show successful notification delivery with timestamp and delivery status |

**Postconditions:**
- Schedule change request is saved in the system with 'Submitted' status
- Notification is successfully delivered to manager
- Notification delivery is logged in the system
- Request is visible in manager's request history

---

### Test Case: Receive notification on approval and rejection
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Manager has submitted a schedule change request
- Request is in 'Pending Approval' status
- Approver is logged into the system
- Approver has permission to approve/reject requests
- Manager has valid notification preferences configured
- Email/SMS gateway services are operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Approver navigates to the pending requests queue | List of pending schedule change requests is displayed including the manager's request |
| 2 | Approver selects the manager's schedule change request to review | Request details are displayed with all submitted information |
| 3 | Approver adds comments in the comments field (e.g., 'Approved due to valid business reason') | Comments are entered successfully in the comments field |
| 4 | Approver clicks 'Approve' button to approve the request | System updates request status to 'Approved' and displays confirmation message |
| 5 | System triggers notification service for status update | System sends status update notification to manager within 1 minute |
| 6 | Manager receives notification via preferred channel | Manager receives notification containing request ID, updated status 'Approved', approver comments, and approval timestamp |
| 7 | Verify notification is accurate and timely | Notification contains accurate information and is received within 1 minute of approval action |
| 8 | Repeat steps 1-7 for rejection scenario: Approver selects another pending request and clicks 'Reject' with rejection reason | System updates status to 'Rejected', sends notification to manager with rejection status and comments within 1 minute |
| 9 | Manager receives rejection notification and reviews content | Notification contains request ID, status 'Rejected', rejection reason, and timestamp |
| 10 | Verify both approval and rejection notifications are logged | System logs show successful delivery of both notifications with timestamps and delivery status |

**Postconditions:**
- Request status is updated to 'Approved' or 'Rejected' in the system
- Manager receives accurate status update notification
- Notification includes approver comments
- Notification delivery is logged with success status
- Request history reflects the status change with timestamp

---

### Test Case: Manage notification preferences
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 7 mins

**Preconditions:**
- Manager is logged into the system
- Manager has access to notification preferences settings
- Manager has at least one notification channel configured (email or SMS)
- System supports multiple notification channels (email and SMS)
- Manager has valid email address and/or phone number in profile

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Manager navigates to user profile or settings section | User profile/settings page is displayed with navigation menu |
| 2 | Manager clicks on 'Notification Preferences' or 'Notification Settings' option | Notification preferences page is displayed showing current settings |
| 3 | Manager reviews current notification channel preferences (email, SMS, or both) | Current preferences are displayed correctly showing enabled/disabled channels |
| 4 | Manager updates notification channel preferences by selecting/deselecting email and SMS options | Checkboxes or toggles respond to manager's selections |
| 5 | Manager selects specific notification types to receive (submission confirmation, approval, rejection, escalation) | Notification type preferences are updated according to selections |
| 6 | Manager clicks 'Save' or 'Update Preferences' button | System displays success message confirming preferences are saved successfully |
| 7 | Manager verifies updated preferences are displayed correctly on the preferences page | Updated preferences are reflected accurately on the screen |
| 8 | Manager submits a new schedule change request to test updated preferences | Request is submitted successfully |
| 9 | System sends notification according to updated preferences | Notification is sent only to the newly selected channels (email, SMS, or both) |
| 10 | Manager checks the selected notification channels | Notifications are received only via the channels specified in updated preferences |
| 11 | Manager verifies no notifications are received on disabled channels | No notifications are sent to channels that were disabled in preferences |
| 12 | Verify preference changes are logged in the system | System audit log shows preference update with timestamp and changed values |

**Postconditions:**
- Notification preferences are updated and saved in the system
- Future notifications are sent according to new preferences
- Manager receives notifications only via selected channels
- Preference changes are logged in system audit trail
- No notifications are sent to disabled channels

---

