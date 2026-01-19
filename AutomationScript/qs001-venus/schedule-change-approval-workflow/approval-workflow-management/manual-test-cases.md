# Manual Test Cases

## Story: As Approver, I want to review schedule change requests to achieve informed approval decisions
**Story ID:** story-12

### Test Case: Approve schedule change request successfully
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Approver account exists with valid credentials and approval permissions
- At least one pending schedule change request is assigned to the approver
- Request contains complete details and attachments
- System is accessible and approval dashboard is functional
- Database contains ScheduleChangeRequests and ApprovalActions tables with test data

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the system login page and enter valid approver credentials (username and password), then click Login button | Approver is successfully authenticated and redirected to the home page or approval dashboard |
| 2 | Navigate to the approval dashboard by clicking on 'Approvals' or 'Pending Requests' menu option | Dashboard displays within 3 seconds showing a list of all pending schedule change requests assigned to the approver with columns for request ID, employee name, request date, and current status |
| 3 | Select a specific pending schedule change request from the list by clicking on it | Request details page opens displaying complete information including employee details, requested schedule changes, reason for change, submission date, and any attached supporting documents |
| 4 | Review all request details and click on any attachments to view supporting documents | Attachments open correctly in appropriate viewer (PDF, image, document) and display the complete content without errors |
| 5 | Click the 'Approve' button to approve the schedule change request | A confirmation dialog or comment box appears allowing the approver to add optional comments |
| 6 | Enter optional approval comments in the comment field (e.g., 'Approved as requested. Schedule updated.') and click 'Submit' or 'Confirm Approval' button | System processes the approval action and displays a success message confirming the request has been approved |
| 7 | Verify the request status has been updated by returning to the approval dashboard or refreshing the request details page | Request status is updated to 'Approved', the request is removed from pending list or marked as approved, and approval timestamp with approver name is recorded |
| 8 | Verify that the requester receives a notification (check notification log or system notification panel) | System sends notification to the requester indicating the schedule change request has been approved, including approver comments if provided |

**Postconditions:**
- Request status is permanently updated to 'Approved' in ScheduleChangeRequests table
- Approval action is logged in ApprovalActions table with timestamp, approver ID, and comments
- Requester has received notification of approval
- Request no longer appears in pending requests list for the approver
- Audit trail is complete with all approval details
- Schedule change is ready for implementation

---

### Test Case: Reject schedule change request with comments
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Approver is logged into the system with valid approval permissions
- At least one pending schedule change request exists in the system
- Approver has access to the approval dashboard
- System notification mechanism is configured and functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | From the approval dashboard, locate and click on a pending schedule change request to review | Request details page opens displaying complete information including employee name, requested changes, submission date, reason, and any attachments |
| 2 | Review the request details and determine that the request should be rejected | All request information is clearly visible and the 'Reject' button or option is available and enabled |
| 3 | Click the 'Reject' button to initiate the rejection process | A rejection dialog or form appears with a mandatory or optional comment field for entering the rejection reason |
| 4 | Enter a detailed rejection reason in the comment field (e.g., 'Request conflicts with operational requirements. Insufficient staffing coverage during requested period.') and click 'Submit' or 'Confirm Rejection' button | System processes the rejection and displays a success message confirming the request has been rejected |
| 5 | Verify the request status has been updated by checking the request details or returning to the dashboard | Request status is updated to 'Rejected', rejection comments are saved and visible in the approval history, and timestamp with approver details is recorded |
| 6 | Verify that the requester receives a rejection notification by checking the notification log or system records | System sends notification to the requester containing the rejection status and the complete rejection reason provided by the approver |
| 7 | As the requester (or verify in requester's view), check the notification received | Notification clearly states the request was rejected and displays the rejection reason: 'Request conflicts with operational requirements. Insufficient staffing coverage during requested period.' |

**Postconditions:**
- Request status is updated to 'Rejected' in the database
- Rejection comments are permanently saved in ApprovalActions table
- Requester has received notification with rejection reason
- Request is removed from pending list and moved to rejected requests
- Complete audit trail exists with rejection details and timestamp
- Requester can view rejection reason in their request history

---

### Test Case: Request additional information for schedule change request
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Approver is logged into the system with valid credentials
- Pending schedule change request exists that requires additional information
- System supports 'Request More Information' workflow status
- Requester account is active and can receive notifications
- Request resubmission functionality is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the approval dashboard and select a pending schedule change request to review | Request details page opens showing all available information about the schedule change request |
| 2 | Review the request details and determine that additional information is needed to make an informed decision | Request details are displayed but lack sufficient information for approval or rejection decision |
| 3 | Locate and click the 'Request More Information' or 'Request Additional Info' button | A form or dialog box appears with a comment field to specify what additional information is required |
| 4 | Enter detailed comments specifying the required information (e.g., 'Please provide: 1) Coverage plan for your current shift, 2) Manager approval from your department, 3) Justification for urgency of this change') in the comment field | Comment field accepts the text input and displays the entered information clearly |
| 5 | Click 'Submit' or 'Send Request' button to submit the information request | System processes the action and displays a success message confirming that the information request has been sent to the requester |
| 6 | Verify the request status has been updated by checking the request details or dashboard | Request status is updated to 'Information Requested' or 'Pending Additional Info', and the request remains in the approver's queue with updated status indicator |
| 7 | Verify that the requester receives a notification by checking notification logs or system records | System sends notification to the requester indicating that additional information is required, including the complete list of requested details from the approver's comments |
| 8 | As the requester (or simulate requester action), log into the system and navigate to 'My Requests' to view the request | Request displays with status 'Information Requested' and shows the approver's comments detailing what additional information is needed |
| 9 | As the requester, add the requested additional information by editing the request or adding attachments, then click 'Resubmit' or 'Update Request' button | System accepts the updated information, changes request status back to 'Pending Review', and notifies the approver that additional information has been provided |
| 10 | As the approver, verify that the updated request appears back in the pending requests queue with the new information | Request reappears in approver's dashboard with updated status and timestamp, and the additional information provided by the requester is visible in the request details |

**Postconditions:**
- Request status is updated to reflect information was requested and subsequently provided
- All comments and information requests are logged in ApprovalActions table with timestamps
- Requester has successfully resubmitted the request with additional information
- Request is back in approver's pending queue for final decision
- Complete audit trail exists showing the information request cycle
- Both approver and requester notifications have been sent and logged

---

## Story: As Employee, I want to track the status of my schedule change requests to achieve transparency and timely updates
**Story ID:** story-13

### Test Case: View schedule change request status successfully
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee account exists with valid login credentials
- Employee has previously submitted at least one schedule change request
- Schedule change requests exist in various statuses (pending, approved, rejected)
- System is accessible and 'My Requests' page is functional
- Database contains employee's request history with approval actions and timestamps

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduling portal login page and enter valid employee credentials (username and password), then click Login button | Employee is successfully authenticated and redirected to the scheduling portal home page or dashboard |
| 2 | Locate and click on the 'My Requests' menu option or navigation link | System loads the 'My Requests' page within 2 seconds displaying a list of all schedule change requests submitted by the logged-in employee |
| 3 | Review the list of schedule change requests displayed on the page | List displays all employee's requests with columns showing request ID, submission date, requested change details, and current status (pending, approved, rejected, or info requested) with clear visual indicators for each status type |
| 4 | Verify that status indicators are visually distinct (e.g., different colors or icons for pending, approved, rejected) | Each status type has a clear visual indicator: pending (yellow/orange), approved (green), rejected (red), info requested (blue), making it easy to identify request status at a glance |
| 5 | Select a specific schedule change request from the list by clicking on it | Request details page opens displaying complete information including requested schedule changes, submission date, current status, and reason for request |
| 6 | Scroll down or navigate to the approval history section of the request details | Detailed approval history is displayed showing all approval actions taken on the request, including action type (submitted, reviewed, approved/rejected), approver name, timestamp for each action, and any comments provided by approvers |
| 7 | Verify the timestamps are displayed in a readable format and are chronologically ordered | All timestamps are displayed in clear date-time format (e.g., 'MM/DD/YYYY HH:MM AM/PM'), listed in chronological order from oldest to newest action |
| 8 | Check if any approver comments are present in the approval history | If approver added comments (approval notes, rejection reasons, or information requests), they are displayed clearly alongside the corresponding approval action with full text visible |
| 9 | Return to 'My Requests' list and verify that the status shown in the list matches the detailed status viewed | Status displayed in the list view is consistent with the detailed status shown in the request details page, confirming real-time accuracy |

**Postconditions:**
- Employee has successfully viewed all their schedule change requests
- Employee has accessed detailed approval history for at least one request
- No unauthorized access to other employees' requests occurred
- System performance met the 2-second response time requirement
- All status information displayed accurately reflects current database state
- Employee session remains active and secure

---

### Test Case: Prevent employee from viewing others' requests
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee is logged into the scheduling portal with valid credentials
- Multiple employees exist in the system with their own schedule change requests
- Another employee's request ID is known or can be obtained
- System has role-based access control implemented
- Security validation is active on API endpoints

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | As the logged-in employee, navigate to 'My Requests' page and note the URL structure and request IDs visible | Employee can view their own requests normally, and URL structure is visible (e.g., '/my-requests' or '/requests?employeeId=123') |
| 2 | Identify or obtain a request ID that belongs to another employee (e.g., request ID 9999 that is not in the employee's list) | Another employee's request ID is identified for testing purposes |
| 3 | Attempt to access another employee's request by manually modifying the URL in the browser address bar (e.g., change '/request/1234' to '/request/9999' or modify employeeId parameter) | System detects unauthorized access attempt and denies access to the request |
| 4 | Observe the system response after attempting unauthorized access | System displays an error message such as 'Access Denied', 'Unauthorized Access', or 'You do not have permission to view this request', and does not display any details of the other employee's request |
| 5 | Verify that the employee is redirected back to their 'My Requests' page or an error page, and no sensitive information about the other employee's request is exposed | Employee is redirected to a safe page (their own requests list or error page), and no data about the unauthorized request is visible in the response, page source, or network traffic |
| 6 | Attempt to access another employee's request using API endpoint directly (e.g., using browser developer tools or API testing tool to call GET /api/my-schedule-change-requests with another employee's request ID) | API returns 403 Forbidden or 401 Unauthorized status code with appropriate error message, and does not return any request data |
| 7 | Return to 'My Requests' page using normal navigation (clicking menu link) | Employee can access their own 'My Requests' page normally without any issues |
| 8 | Select and view one of the employee's own requests from the list | Access is granted immediately, and full request details including approval history, timestamps, and comments are displayed without any errors or access restrictions |
| 9 | Verify that the security event was logged by checking system logs (if accessible) or confirming with system administrator | Unauthorized access attempt is logged in security audit logs with timestamp, employee ID, and attempted request ID for security monitoring purposes |

**Postconditions:**
- Employee was successfully prevented from accessing another employee's request
- No unauthorized data was exposed or accessible
- Employee can still access their own requests without restriction
- Security controls are confirmed to be functioning correctly
- Unauthorized access attempt is logged in audit trail
- System maintains data privacy and security compliance

---

## Story: As System Administrator, I want to configure approval workflow rules to achieve flexible and compliant schedule change approvals
**Story ID:** story-14

### Test Case: Create and activate a new approval workflow
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Administrator account with valid credentials exists
- Administrator has proper role permissions for workflow configuration
- Admin portal is accessible and operational
- At least one role, department, and individual user exists in the system for approver assignment
- ApprovalWorkflows and ApproverAssignments tables are accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the admin portal login page and enter valid administrator credentials | Administrator is successfully authenticated and redirected to the admin portal dashboard |
| 2 | Locate and click on the workflow configuration section in the navigation menu | Workflow configuration page is displayed showing existing workflows and option to create new workflow |
| 3 | Click on 'Create New Workflow' button | New workflow creation form is displayed with fields for workflow name, description, and approval stages |
| 4 | Enter workflow name as 'Multi-Level Schedule Approval' and description as 'Three-stage approval process for schedule changes' | Workflow name and description are accepted and displayed in the form fields |
| 5 | Add first approval stage named 'Manager Review' and assign approver by role 'Department Manager' | First approval stage is created with role-based approver assignment successfully configured |
| 6 | Add second approval stage named 'HR Review' and assign approver by department 'Human Resources' | Second approval stage is created with department-based approver assignment successfully configured |
| 7 | Add third approval stage named 'Executive Approval' and assign specific individual approver 'John Smith - VP Operations' | Third approval stage is created with individual approver assignment successfully configured |
| 8 | Click 'Save Workflow' button | System validates the workflow configuration, displays success message 'Workflow saved successfully', and workflow appears in the list with 'Inactive' status |
| 9 | Locate the newly created workflow in the list and click 'Activate' button | Confirmation dialog appears asking 'Are you sure you want to activate this workflow?' |
| 10 | Click 'Confirm' on the activation dialog | Workflow status changes to 'Active', success message displays 'Workflow activated successfully', and workflow becomes available for new schedule change requests |
| 11 | Submit a new schedule change request that should trigger this workflow | The newly activated workflow is applied to the schedule change request and first stage approver receives assignment |

**Postconditions:**
- New approval workflow is created and saved in ApprovalWorkflows table
- Workflow status is set to 'Active'
- All three approval stages are configured with assigned approvers in ApproverAssignments table
- Workflow is available for routing new schedule change requests
- Changes are applied within 1 minute as per performance requirements
- Administrator remains logged into the admin portal

---

### Test Case: Prevent invalid workflow configurations
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Administrator is logged into the admin portal
- Administrator has proper role permissions for workflow configuration
- Workflow configuration page is accessible
- System validation rules are active and enforced

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to workflow configuration page and click 'Create New Workflow' button | New workflow creation form is displayed |
| 2 | Enter workflow name as 'Incomplete Workflow Test' and description | Workflow name and description are accepted in the form |
| 3 | Add first approval stage named 'Initial Review' but leave the approver assignment field empty | Approval stage is added with no approver assigned |
| 4 | Add second approval stage named 'Final Review' but leave the approver assignment field empty | Second approval stage is added with no approver assigned |
| 5 | Click 'Save Workflow' button without assigning any approvers | System performs validation and displays error messages: 'Approval stage 1 requires at least one approver' and 'Approval stage 2 requires at least one approver'. Workflow is not saved |
| 6 | Verify that the workflow does not appear in the workflow list | Workflow list does not contain the invalid workflow, confirming save was prevented |
| 7 | Return to the workflow form and assign approver by role 'Team Lead' to the first approval stage | First approval stage now has valid approver assignment, error for stage 1 is cleared |
| 8 | Assign approver by department 'Finance' to the second approval stage | Second approval stage now has valid approver assignment, error for stage 2 is cleared |
| 9 | Click 'Save Workflow' button with all required approvers assigned | System validates successfully, displays success message 'Workflow saved successfully', and workflow appears in the list with all validation errors resolved |

**Postconditions:**
- Invalid workflow configuration was prevented from being saved
- Validation errors were displayed to guide administrator
- Corrected workflow is successfully saved in ApprovalWorkflows table
- Data integrity is maintained with no incomplete workflows in the system
- Administrator remains on workflow configuration page

---

### Test Case: Restrict workflow configuration access to administrators
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Non-admin user account exists with valid credentials and standard user role
- Administrator account exists with valid credentials and admin role
- Workflow configuration page requires admin role for access
- Role-based access control is properly configured
- Both users are not currently logged in

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page using non-admin user credentials | Login page is displayed |
| 2 | Enter valid non-admin user credentials and click 'Login' | Non-admin user is successfully authenticated and redirected to standard user dashboard |
| 3 | Attempt to navigate directly to the workflow configuration page URL | Access is denied with error message 'Access Denied: You do not have permission to access this page. Administrator privileges required.' User is redirected to unauthorized access page or remains on current page |
| 4 | Verify that workflow configuration menu option is not visible in the navigation menu | Workflow configuration option is not displayed in the navigation menu for non-admin user |
| 5 | Log out from the non-admin user account | User is successfully logged out and redirected to login page |
| 6 | Enter valid administrator credentials and click 'Login' | Administrator is successfully authenticated and redirected to admin portal dashboard |
| 7 | Locate workflow configuration option in the navigation menu | Workflow configuration menu option is visible and accessible to administrator |
| 8 | Click on workflow configuration menu option | Access is granted and workflow configuration page is displayed with full functionality including create, edit, delete, and activate options |
| 9 | Verify all workflow management features are available: create new workflow, edit existing workflow, delete workflow, and activate/deactivate workflow | All workflow management features are accessible and functional for administrator user |

**Postconditions:**
- Non-admin user access to workflow configuration was successfully blocked
- Appropriate error message was displayed to non-admin user
- Administrator successfully accessed workflow configuration with full permissions
- Role-based access control is confirmed to be working correctly
- Security requirements are met with admin-only access enforced
- Administrator remains logged into the admin portal

---

## Story: As Approver, I want to receive notifications for pending schedule change requests to achieve timely processing
**Story ID:** story-15

### Test Case: Verify notification sent upon request assignment
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Approver account exists with valid email address and active status
- Approver has default notification preferences enabled for both email and in-app notifications
- Active approval workflow is configured with the approver assigned
- Notification service is operational and integrated
- Employee account exists to submit schedule change request
- ScheduleChangeRequests and ApprovalWorkflows tables are accessible
- Notification delivery logging is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as employee user and navigate to schedule change request submission page | Schedule change request form is displayed with all required fields |
| 2 | Fill in schedule change request details: select date, enter reason 'Medical appointment', and specify requested time change from 9:00 AM to 11:00 AM | All request details are entered successfully in the form |
| 3 | Click 'Submit Request' button | Request is submitted successfully, confirmation message displays 'Your schedule change request has been submitted', and request is saved in ScheduleChangeRequests table |
| 4 | System automatically determines approver based on configured workflow and assigns the request | Request is assigned to the designated approver within the workflow, assignment is recorded in the system |
| 5 | Wait up to 1 minute and verify notification is triggered and sent to the assigned approver | Notification is sent to approver via both email and in-app notification within 1 minute of assignment as per SLA |
| 6 | Log in as the assigned approver and check email inbox | Email notification is received with subject line 'New Schedule Change Request Requires Your Approval' containing request ID, employee name, requested date, reason, and direct link to approval interface |
| 7 | Verify in-app notification by checking notification center in the application | In-app notification is displayed showing 'New schedule change request from [Employee Name] requires your review' with request summary and timestamp |
| 8 | Review notification content for accuracy: verify request ID, employee name, date, time change details, and reason match the submitted request | All notification content is accurate and matches the original schedule change request details |
| 9 | Click on the direct link provided in the email notification | Browser opens and approver is directed to the approval interface with the specific schedule change request displayed for review |
| 10 | Verify the correct request is displayed with all details: employee name, current schedule, requested schedule, reason, and submission date | Approval interface displays the correct request with complete and accurate information, approve and deny buttons are available |
| 11 | Check notification delivery logs in the admin system | Notification delivery status is logged showing successful delivery timestamp, recipient, notification type (email and in-app), and delivery confirmation |

**Postconditions:**
- Schedule change request is successfully submitted and assigned to approver
- Notification is sent to approver within 1 minute SLA
- Both email and in-app notifications are delivered successfully
- Notification content is accurate and actionable
- Direct link navigates approver to correct request
- Notification delivery is logged for audit purposes
- Request remains in pending status awaiting approval
- Approver has access to review and act on the request

---

### Test Case: Test notification preference settings
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 7 mins

**Preconditions:**
- Approver account exists and is active
- Approver is currently receiving both email and in-app notifications (default settings)
- Approver profile page with notification preferences is accessible
- Active approval workflow is configured with the approver assigned
- Employee account exists to submit schedule change request
- Notification service is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as approver and navigate to user profile settings page | Profile settings page is displayed with personal information and notification preferences section |
| 2 | Locate notification preferences section and view current settings | Notification preferences section shows current settings with checkboxes for 'Email Notifications' (checked) and 'In-App Notifications' (checked) |
| 3 | Uncheck the 'Email Notifications' checkbox to disable email alerts while keeping 'In-App Notifications' enabled | Email Notifications checkbox is unchecked, In-App Notifications remains checked |
| 4 | Click 'Save Preferences' button | Success message displays 'Notification preferences updated successfully', and changes are saved to approver profile in the database |
| 5 | Verify updated preferences are displayed correctly after save | Notification preferences show Email Notifications disabled (unchecked) and In-App Notifications enabled (checked) |
| 6 | Log out from approver account | Approver is successfully logged out |
| 7 | Log in as employee user and navigate to schedule change request submission page | Schedule change request form is displayed |
| 8 | Submit a new schedule change request with details: date tomorrow, reason 'Personal appointment', time change from 1:00 PM to 3:00 PM | Request is submitted successfully and assigned to the approver based on workflow |
| 9 | Wait up to 1 minute for notification processing | System processes the request assignment and triggers notification based on approver preferences |
| 10 | Check approver's email inbox for notification | No email notification is received, confirming email alerts are disabled as per updated preferences |
| 11 | Log in as approver and check in-app notification center | In-app notification is displayed showing the new schedule change request, confirming in-app notifications are still active |
| 12 | Verify notification delivery logs show only in-app notification was sent | Logs confirm in-app notification was delivered successfully and no email notification was sent, respecting approver preferences |

**Postconditions:**
- Approver notification preferences are successfully updated and saved
- Email notifications are disabled for the approver
- In-app notifications remain enabled and functional
- New schedule change request triggers only in-app notification
- No email notification is sent to approver
- Notification preferences are respected by the system
- Notification delivery logs accurately reflect preference-based delivery
- Request remains pending and accessible to approver for review

---

## Story: As Approver, I want to delegate approval tasks to another approver to achieve continuity during absence
**Story ID:** story-18

### Test Case: Assign and revoke delegation successfully
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User with approver role is logged into the system
- At least one other approver exists in the system to be assigned as delegate
- Approver has active approval tasks in their queue
- DelegationAssignments table is accessible
- API endpoints POST /api/delegations and GET /api/delegations are operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to delegation settings page from the main dashboard | Delegation settings page loads successfully displaying delegation management interface |
| 2 | Click on 'Assign Delegate' or 'Create Delegation' button | Delegation assignment form is displayed with fields for delegate selection, start date, and end date |
| 3 | Select a valid approver from the delegate dropdown list | Selected approver name is populated in the delegate field |
| 4 | Set start date to current date and end date to 7 days from current date | Both dates are accepted and displayed in the form with proper date format |
| 5 | Click 'Save' or 'Assign Delegation' button | Delegation is saved successfully, confirmation message is displayed, and delegation appears in the delegation list with status 'Active' |
| 6 | Verify delegate receives notification about the delegation assignment | Delegate receives notification indicating they have been assigned approval tasks with delegation period details |
| 7 | Log out from the original approver account and log in as the delegate | Delegate successfully logs into the system |
| 8 | Navigate to approval requests queue or delegated tasks section | Delegate can see the delegated approval requests from the original approver in their queue |
| 9 | Select one of the delegated approval requests and click 'Approve' | Delegate can successfully approve the request, approval is processed, and request status changes to 'Approved' |
| 10 | Log out from delegate account and log back in as the original approver | Original approver successfully logs back into the system |
| 11 | Navigate to delegation settings and locate the active delegation assignment | Active delegation is displayed in the delegation list with current status and delegate information |
| 12 | Click 'Revoke' or 'Cancel Delegation' button for the active delegation | Confirmation dialog appears asking to confirm revocation of delegation |
| 13 | Confirm the revocation action | Delegation is removed successfully, confirmation message is displayed, and delegation status changes to 'Revoked' in the audit log |
| 14 | Log out and log back in as the delegate, then navigate to approval requests | Delegate no longer has access to the previously delegated approval tasks, and delegated requests are removed from their queue |

**Postconditions:**
- Delegation assignment is revoked and recorded in audit logs
- Delegate no longer has access to original approver's tasks
- Original approver retains full control of their approval tasks
- Delegation history is maintained in DelegationAssignments table with revocation timestamp
- All approval actions taken by delegate during delegation period remain valid and recorded

---

### Test Case: Prevent unauthorized delegation assignment
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User without approver role is logged into the system
- User has standard or non-approver permissions
- Delegation functionality is enabled in the system
- Security controls are properly configured to restrict delegation assignment to approvers only

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Attempt to navigate to delegation settings page by entering the URL directly or through navigation menu | System denies access and displays error message 'Access Denied: You do not have permission to access delegation settings' or redirects to unauthorized access page |
| 2 | Attempt to send a POST request to /api/delegations endpoint with delegation assignment data using API testing tool or browser console | API returns HTTP 403 Forbidden status code with error message 'Unauthorized: Only approvers can assign delegations' |
| 3 | Verify that no delegation assignment is created in the DelegationAssignments table | No new delegation record is created, and database remains unchanged |
| 4 | Check system audit logs for the unauthorized access attempt | Audit log records the unauthorized delegation assignment attempt with user details, timestamp, and action denied status |

**Postconditions:**
- No delegation assignment is created in the system
- Non-approver user remains restricted from delegation functionality
- Security violation is logged in audit trail
- System security controls remain intact and functional

---

