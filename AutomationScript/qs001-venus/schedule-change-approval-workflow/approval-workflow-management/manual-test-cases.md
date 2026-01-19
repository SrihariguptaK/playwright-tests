# Manual Test Cases

## Story: As Approver, I want to review schedule change requests to achieve informed decision-making
**Story ID:** story-2

### Test Case: Display pending schedule change requests to approver
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User has valid approver credentials
- At least one pending schedule change request exists in the system
- User has appropriate role-based access permissions
- Network connectivity is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Approver logs into the system using valid credentials | Dashboard loads successfully within 3 seconds and displays the main navigation menu |
| 2 | Navigate to approval dashboard by clicking on the approval dashboard menu option | List of pending schedule change requests is displayed showing request ID, requester name, submission date, and current status |
| 3 | Select a request from the list to view details by clicking on the request row | Detailed information is displayed including requester details, requested changes, attachments, comments, and request history |

**Postconditions:**
- Approver remains logged in
- Request details page is displayed
- No changes are made to request status

---

### Test Case: Approve a schedule change request
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as an approver
- At least one pending schedule change request exists
- User has authorization to approve requests
- Approver is on the approval dashboard

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Select a pending schedule change request from the list by clicking on it | Request details are displayed showing all relevant information including requester name, requested changes, attachments, and current status as 'Pending' |
| 2 | Click the 'Approve' button and add optional comments in the comments text field | Approve action is accepted, comments field is populated, and the submit button becomes enabled |
| 3 | Click the 'Submit' button to confirm the approval decision | Request status is updated to 'Approved', decision is logged with timestamp and approver details, confirmation message is displayed, and notification is sent to the requester |

**Postconditions:**
- Request status is changed to 'Approved' in the database
- Approval action is logged in ApprovalActions table with timestamp
- Requester receives notification of approval
- Request is removed from pending list on dashboard

---

### Test Case: Reject a schedule change request with comments
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as an approver
- At least one pending schedule change request exists
- User has authorization to reject requests
- Approver is on the approval dashboard

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Select a pending schedule change request from the list by clicking on it | Request details are displayed showing all relevant information including requester name, requested changes, attachments, and current status as 'Pending' |
| 2 | Click the 'Reject' button and enter a rejection reason in the mandatory comments field | Reject action is accepted, rejection reason is entered in the comments field, and the submit button becomes enabled |
| 3 | Click the 'Submit' button to confirm the rejection decision | Request status is updated to 'Rejected', decision is logged with timestamp and approver details, rejection reason is saved, confirmation message is displayed, and notification is sent to the requester |

**Postconditions:**
- Request status is changed to 'Rejected' in the database
- Rejection action is logged in ApprovalActions table with timestamp and comments
- Requester receives notification of rejection with reason
- Request is removed from pending list on dashboard

---

## Story: As Scheduler, I want to view the status of my schedule change requests to achieve transparency and timely updates
**Story ID:** story-3

### Test Case: Display schedule change requests and statuses for scheduler
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User has valid scheduler credentials
- Scheduler has submitted at least one schedule change request
- User has appropriate role-based access permissions
- Network connectivity is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Scheduler logs into the system using valid credentials | 'My Schedule Changes' page loads successfully within 3 seconds and displays the navigation menu |
| 2 | View the list of submitted schedule change requests on the 'My Schedule Changes' page | All requests submitted by the logged-in scheduler are displayed with columns showing request ID, submission date, type, current status (Pending, Approved, Rejected, or Escalated), and last updated timestamp |
| 3 | Select a specific request from the list by clicking on it to view detailed approval history | Detailed view is displayed showing complete approval history including all approval actions, approver names, decision timestamps, and any comments provided by approvers |

**Postconditions:**
- Scheduler remains logged in
- Request details page is displayed
- No changes are made to any request status
- Only scheduler's own requests are visible

---

### Test Case: Filter and sort schedule change requests
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as a scheduler
- Scheduler is on the 'My Schedule Changes' page
- Multiple schedule change requests exist with different statuses and dates
- At least one request has 'Pending' status

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | On 'My Schedule Changes' page, locate the status filter dropdown and select 'Pending' from the available options | Only requests with 'Pending' status are displayed in the list, all other status requests are filtered out, and the count of displayed requests updates accordingly |
| 2 | Click on the 'Submission Date' column header to sort requests by submission date in descending order | Requests are sorted correctly with the most recent submission date appearing first, and a descending sort indicator is displayed on the column header |
| 3 | Click the 'Clear Filters' or 'Reset' button to remove all applied filters and sorting | All schedule change requests submitted by the scheduler are displayed again in the default order (typically by submission date descending), and filter selections are reset to default values |

**Postconditions:**
- All filters and sorting are cleared
- Full list of scheduler's requests is visible
- Page displays default view
- No data is modified

---

## Story: As Approver, I want to escalate schedule change requests to higher authority to achieve timely resolution
**Story ID:** story-4

### Test Case: Escalate a schedule change request successfully
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Approver role
- At least one schedule change request exists in pending status
- User has permission to escalate requests
- Higher-level approvers are configured in the system
- Notification service is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the approval dashboard | Approval dashboard loads successfully displaying list of pending schedule change requests |
| 2 | Select a schedule change request from the list | Request details are displayed including requester information, schedule details, and current status |
| 3 | Click the 'Escalate' button | Escalation dialog box opens with a comments text field and submit/cancel buttons |
| 4 | Enter escalation comments in the text field (e.g., 'Requires senior management approval due to budget implications') | Escalation comments are accepted and displayed in the text field without validation errors |
| 5 | Click the 'Submit' button to submit the escalation | System processes the escalation within 2 seconds, request status updates to 'Escalated', success message is displayed |
| 6 | Verify the request status on the dashboard | Request status shows 'Escalated' with timestamp and escalation indicator |
| 7 | Check that notification was sent to higher-level approvers | Notification is sent to next-level approvers within 1 minute containing request details and escalation comments |
| 8 | Review audit logs for the escalation action | Escalation action is logged in audit logs with timestamp, approver user details, and escalation comments |

**Postconditions:**
- Schedule change request status is 'Escalated'
- Higher-level approvers have been notified
- Escalation action is recorded in audit logs with complete details
- Original approver can view escalation history on the request

---

### Test Case: Reject escalation with missing comments
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in with Approver role
- At least one schedule change request exists in pending status
- User has permission to escalate requests
- Escalation comments are configured as mandatory field

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the approval dashboard | Approval dashboard loads successfully displaying list of pending schedule change requests |
| 2 | Select a schedule change request from the list | Request details are displayed with available actions including 'Escalate' button |
| 3 | Click the 'Escalate' button | Escalation dialog box opens with an empty comments text field |
| 4 | Leave the comments field empty and click the 'Submit' button | Validation error message is displayed: 'Escalation comments are required' or similar, submission is blocked |
| 5 | Attempt to submit escalation again without entering comments | Submission remains blocked, validation error persists, escalation dialog stays open |
| 6 | Verify that the request status has not changed | Request status remains in original state (not 'Escalated'), no escalation action recorded |
| 7 | Enter valid comments in the text field (e.g., 'Escalating for policy review') | Validation error clears, comments are accepted |
| 8 | Click 'Submit' button with valid comments | Escalation is successfully submitted, request status updates to 'Escalated' |

**Postconditions:**
- System enforces mandatory comments validation for escalations
- No incomplete escalation records are created in the system
- Request status only changes after valid escalation submission

---

## Story: As System Administrator, I want to configure approval workflow rules to achieve flexible and compliant schedule change processing
**Story ID:** story-5

### Test Case: Create and save new approval workflow configuration
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with System Administrator role
- User has access to workflow configuration module
- WorkflowConfig database tables are accessible
- No pending workflow configuration changes exist
- System is in stable state with no ongoing deployments

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system with administrator credentials | Administrator successfully logs in and lands on admin dashboard |
| 2 | Navigate to the workflow configuration page from the admin menu | Workflow configuration UI loads successfully displaying current workflow settings and configuration options |
| 3 | Click 'Add New Approval Level' button | New approval level form appears with fields for level name, sequence order, and role assignment |
| 4 | Enter approval level details: Level Name = 'Senior Management Approval', Sequence = '3', Role = 'Senior Manager' | Input fields accept the values without validation errors, data is displayed correctly in the form |
| 5 | Click 'Add Role' to assign additional roles to the approval level | Role selection dropdown appears with available system roles |
| 6 | Select 'Director' role from the dropdown and add it to the approval level | Director role is added to the approval level, both Senior Manager and Director roles are displayed |
| 7 | Define escalation path by selecting 'Escalates to: Executive Level' from the escalation dropdown | Escalation path is configured and displayed in the workflow diagram |
| 8 | Review the complete workflow configuration in the preview panel | Preview shows all approval levels, assigned roles, and escalation paths in logical sequence |
| 9 | Click 'Save Configuration' button | System validates the configuration for consistency, validation passes with no errors |
| 10 | Confirm the save action in the confirmation dialog | Configuration is saved successfully, success message displays: 'Workflow configuration saved and will be applied within 5 minutes' |
| 11 | Wait for 5 minutes and refresh the workflow configuration page | New configuration is active and displayed as current workflow, changes are applied without system downtime |
| 12 | Navigate to audit logs and search for workflow configuration changes | Configuration change is logged with administrator username, timestamp, and details of changes made |

**Postconditions:**
- New approval workflow configuration is saved in WorkflowConfig tables
- Configuration is applied and active in the system within 5 minutes
- All configuration changes are logged in audit logs
- System remains operational with no downtime
- New approval level is available for schedule change requests

---

### Test Case: Reject invalid workflow configuration
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with System Administrator role
- User has access to workflow configuration module
- Existing valid workflow configuration is in place
- Validation rules are configured for workflow consistency

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system with administrator credentials | Administrator successfully logs in and accesses admin dashboard |
| 2 | Navigate to the workflow configuration page | Workflow configuration UI loads with current workflow settings displayed |
| 3 | Click 'Add New Approval Level' to create a new level | New approval level form appears ready for input |
| 4 | Enter approval level: Level Name = 'Department Head', Sequence = '2', Role = 'Department Manager' | Approval level details are entered and displayed in the form |
| 5 | Configure escalation path to point to a non-existent approval level: 'Escalates to: Non-Existent Level' | Escalation path input accepts the entry temporarily |
| 6 | Create another approval level with the same sequence number '2' as an existing level | Duplicate sequence number is entered in the form |
| 7 | Click 'Save Configuration' button | System performs validation and displays validation errors: 'Escalation path references non-existent approval level' and 'Duplicate sequence numbers detected' |
| 8 | Review the validation error messages displayed on the screen | Clear, specific error messages are shown for each validation failure with guidance on how to resolve |
| 9 | Attempt to save the configuration again without making corrections | Save operation is blocked, validation errors persist, configuration is not saved to database |
| 10 | Verify that the original workflow configuration remains unchanged | Current active workflow configuration is unchanged, no partial updates applied |
| 11 | Correct the errors: Change escalation path to valid existing level and update sequence number to '4' | Corrections are accepted, validation errors clear from the screen |
| 12 | Click 'Save Configuration' button with corrected data | Validation passes, configuration is saved successfully, success message is displayed |

**Postconditions:**
- Invalid configuration is rejected and not saved to the system
- Original workflow configuration remains intact and operational
- No partial or inconsistent configuration data exists in the database
- Administrator is informed of specific validation errors
- System maintains data integrity throughout the validation process

---

## Story: As Scheduler, I want to receive notifications about schedule change approval decisions to achieve timely awareness
**Story ID:** story-7

### Test Case: Receive notification on approval decision
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Scheduler is logged into the system
- Scheduler has submitted a schedule change request with valid details
- Schedule change request is in 'Pending' status
- Approver has appropriate permissions to approve requests
- Notification service is operational
- Scheduler's email address is configured in user profile
- In-app notification feature is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Approver logs into the system and navigates to the approval dashboard | Approver successfully accesses the approval dashboard and sees the pending schedule change request |
| 2 | Approver selects the schedule change request submitted by the scheduler | Request details are displayed with all relevant information including requester name, date, and change details |
| 3 | Approver adds comments 'Approved as requested - no conflicts identified' and clicks the 'Approve' button | System displays confirmation message that the decision has been recorded and request status changes to 'Approved' |
| 4 | System automatically triggers notification service within 1 minute of approval | Notification service processes the approval decision and queues email and in-app notifications for the scheduler |
| 5 | Scheduler checks email inbox within 1 minute of approval | Scheduler receives email notification with subject line indicating approval, including decision details and approver comments |
| 6 | Scheduler logs into the system and checks in-app notifications | In-app notification badge shows unread notification count, notification appears in notification center |
| 7 | Scheduler clicks on the in-app notification to view details | Notification displays complete decision information including: approval status, approver name, timestamp, comments 'Approved as requested - no conflicts identified', and link to view full request details |

**Postconditions:**
- Schedule change request status is 'Approved'
- Scheduler has received both email and in-app notifications
- Notification delivery timestamp is within 1 minute of approval decision
- Notification is marked as delivered in the system
- Audit log records notification sent event

---

### Test Case: Receive notification on rejection decision
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Scheduler is logged into the system
- Scheduler has submitted a schedule change request with valid details
- Schedule change request is in 'Pending' status
- Approver has appropriate permissions to reject requests
- Notification service is operational
- Scheduler's email address is configured in user profile
- In-app notification feature is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Approver logs into the system and navigates to the approval dashboard | Approver successfully accesses the approval dashboard and sees the pending schedule change request |
| 2 | Approver selects the schedule change request submitted by the scheduler | Request details are displayed with all relevant information including requester name, date, and change details |
| 3 | Approver adds comments 'Rejected due to insufficient staffing coverage during requested period' and clicks the 'Reject' button | System displays confirmation message that the decision has been recorded and request status changes to 'Rejected' |
| 4 | System automatically triggers notification service within 1 minute of rejection | Notification service processes the rejection decision and queues email and in-app notifications for the scheduler |
| 5 | Scheduler checks email inbox within 1 minute of rejection | Scheduler receives email notification with subject line indicating rejection, including decision details and approver comments |
| 6 | Scheduler logs into the system and checks in-app notifications | In-app notification badge shows unread notification count, notification appears in notification center with rejection indicator |
| 7 | Scheduler clicks on the in-app notification to view details | Notification displays complete decision information including: rejection status, approver name, timestamp, comments 'Rejected due to insufficient staffing coverage during requested period', and link to view full request details |

**Postconditions:**
- Schedule change request status is 'Rejected'
- Scheduler has received both email and in-app notifications
- Notification delivery timestamp is within 1 minute of rejection decision
- Notification is marked as delivered in the system
- Audit log records notification sent event
- Original schedule remains unchanged

---

## Story: As Approver, I want to filter and search schedule change requests to achieve efficient workload management
**Story ID:** story-8

### Test Case: Filter schedule change requests by status and date
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Approver is logged into the system with valid credentials
- Approver has appropriate permissions to view schedule change requests
- Multiple schedule change requests exist in the system with varying statuses (Pending, Approved, Rejected)
- Schedule change requests exist with different submission dates spanning more than 7 days
- At least 3 requests with 'Pending' status exist within the last 7 days
- Approval dashboard is accessible and fully loaded

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Approver navigates to the approval dashboard | Dashboard loads successfully displaying all schedule change requests in default view with filter options visible |
| 2 | Approver locates the status filter dropdown and selects 'Pending' from the available options | Status filter is applied and dropdown shows 'Pending' as selected value |
| 3 | Approver locates the date range filter and selects 'Last 7 days' option | Date range filter is applied showing date range from current date minus 7 days to current date |
| 4 | Approver clicks 'Apply Filters' button | System processes the filter request and displays filtered results within 2 seconds showing only requests with 'Pending' status submitted within the last 7 days |
| 5 | Approver verifies the filtered list by checking status and date columns of displayed requests | All displayed requests show 'Pending' status and submission dates within the last 7 days, no requests outside filter criteria are shown |
| 6 | Approver notes the response time from clicking 'Apply Filters' to results display | Results are returned and displayed within 2 seconds as per performance requirement |
| 7 | Approver clicks 'Clear Filters' button | All filters are removed, filter dropdowns reset to default values, and full unfiltered list of all schedule change requests is displayed |

**Postconditions:**
- Filters are cleared and system returns to default view
- All schedule change requests are visible without any filtering applied
- Filter controls are reset to default state
- System performance remains within acceptable limits

---

### Test Case: Search schedule change requests by keyword
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Approver is logged into the system with valid credentials
- Approver has appropriate permissions to view schedule change requests
- Multiple schedule change requests exist in the system
- At least 3 requests contain the keyword 'maintenance' in their details, comments, or description fields
- Search functionality is enabled on the approval dashboard
- Approval dashboard is accessible and fully loaded

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Approver navigates to the approval dashboard | Dashboard loads successfully displaying all schedule change requests with search box visible at the top of the request list |
| 2 | Approver locates the search box and clicks inside it to activate the search field | Search box is activated, cursor appears in the field, and placeholder text is visible |
| 3 | Approver types the keyword 'maintenance' into the search box | Text 'maintenance' appears in the search box as typed, character by character |
| 4 | Approver presses Enter key or clicks the search icon button | System initiates search query and displays loading indicator while processing |
| 5 | System processes the search and returns results | Search results are displayed within 2 seconds showing only schedule change requests that contain the keyword 'maintenance' in any of their detail fields |
| 6 | Approver reviews the search results and verifies each displayed request contains the keyword 'maintenance' | All displayed requests contain 'maintenance' in description, comments, or other detail fields, with the keyword highlighted or emphasized in the results |
| 7 | Approver notes the response time from initiating search to results display | Search results are returned and displayed within 2 seconds as per performance requirement |
| 8 | Approver clicks 'Clear Search' button or deletes text from search box and presses Enter | Search is cleared, search box is empty, and full unfiltered list of all schedule change requests is displayed |

**Postconditions:**
- Search is cleared and system returns to default view
- All schedule change requests are visible without any search filtering applied
- Search box is empty and ready for new search input
- System performance remains within acceptable limits

---

### Test Case: Save and reuse filter presets
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 6 mins

**Preconditions:**
- Approver is logged into the system with valid credentials
- Approver has appropriate permissions to view and manage schedule change requests
- Filter preset functionality is enabled for the approver role
- Multiple schedule change requests exist with varying priorities and statuses
- At least 3 requests with 'High' priority and 'Pending' status exist in the system
- Approval dashboard is accessible and fully loaded
- Approver has not previously saved a preset named 'Urgent Requests'

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Approver navigates to the approval dashboard | Dashboard loads successfully displaying all schedule change requests with filter options and preset management controls visible |
| 2 | Approver applies multiple filters: selects 'Pending' from status dropdown and 'High' from priority dropdown | Both filters are applied and displayed as active filters in the filter panel |
| 3 | Approver clicks 'Apply Filters' button to view filtered results | Filtered list displays only requests with 'Pending' status and 'High' priority within 2 seconds |
| 4 | Approver clicks 'Save Preset' or 'Save Filter' button | Dialog box or modal appears prompting for preset name and optional description |
| 5 | Approver enters preset name 'Urgent Requests' in the name field | Text 'Urgent Requests' appears in the preset name field |
| 6 | Approver clicks 'Save' button in the preset dialog | System displays success message 'Preset saved successfully', dialog closes, and 'Urgent Requests' appears in the saved presets list or dropdown |
| 7 | Approver clicks 'Clear Filters' to reset the view | All filters are cleared and full unfiltered list of schedule change requests is displayed |
| 8 | Approver locates the saved presets dropdown or list and selects 'Urgent Requests' preset | Preset 'Urgent Requests' is selected from the list |
| 9 | Approver clicks 'Load Preset' or 'Apply' button | System automatically applies the saved filters (Status: Pending, Priority: High) and displays matching requests within 2 seconds |
| 10 | Approver verifies that the loaded preset displays the same filtered results as when originally saved | Filtered list shows only requests with 'Pending' status and 'High' priority, matching the original filter criteria |

**Postconditions:**
- Filter preset 'Urgent Requests' is saved in the system and associated with the approver's profile
- Preset is available for future use in the saved presets list
- Current view displays filtered results based on the loaded preset
- Preset can be edited or deleted by the approver
- System audit log records preset creation event

---

## Story: As System Administrator, I want to manage user roles and permissions for approval workflows to achieve secure and compliant access control
**Story ID:** story-9

### Test Case: Assign and enforce user roles
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Admin user is authenticated and logged into the system
- User management console is accessible
- Test user account exists in the system without 'Approver' role
- UserRoles and Permissions tables are properly configured
- Approval dashboard is available and functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to user management console as Admin | User management console loads successfully displaying list of users and their current roles |
| 2 | Search for and select the test user from the user list | Test user profile is displayed with current role information |
| 3 | Click on 'Edit Roles' or 'Assign Role' button for the selected user | Role assignment interface opens showing available roles (Scheduler, Approver, Auditor, Admin) |
| 4 | Select 'Approver' role from the available roles list | 'Approver' role is highlighted/selected in the interface |
| 5 | Click 'Save' button to confirm role assignment | Success message is displayed confirming role assignment. Role change is saved to UserRoles table and logged with admin username and timestamp |
| 6 | Verify the audit log for the role change entry | Audit log shows new entry with user ID, assigned role 'Approver', admin who made the change, and timestamp |
| 7 | Log out from admin account and log in as the test user with newly assigned 'Approver' role | Test user successfully logs into the system |
| 8 | Navigate to the approval dashboard | Approval dashboard loads successfully showing pending approval requests and approval actions available to 'Approver' role |
| 9 | Attempt to perform an action restricted to 'Approver' role (e.g., approve a pending schedule change) | Action is permitted and executes successfully, confirming 'Approver' permissions are enforced |
| 10 | Attempt to access an unauthorized action for 'Approver' role (e.g., access admin configuration settings or user management console) | Access is denied with appropriate error message (e.g., 'You do not have permission to access this resource' or 403 Forbidden) |
| 11 | Verify that unauthorized action attempt is logged in security audit log | Security audit log contains entry of unauthorized access attempt with user ID, attempted action, and timestamp |

**Postconditions:**
- Test user has 'Approver' role assigned in the system
- Role assignment is logged in audit trail
- User can access Approver-specific functions
- User cannot access functions outside Approver permissions
- All access attempts are properly logged

---

### Test Case: Restrict role management access
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- System has role-based access control configured
- Non-admin test user account exists and is authenticated
- Admin test user account exists and is authenticated
- Role management page URL is known
- Access control is properly configured to restrict role management to admins only

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system as a non-admin user (e.g., user with 'Scheduler' or 'Approver' role) | Non-admin user successfully logs into the system and lands on their default dashboard |
| 2 | Attempt to navigate to the role management page by entering the URL directly in the browser or clicking on role management link if visible | Access is denied. System displays error message such as 'Access Denied - Insufficient Permissions' or 'You must be an administrator to access this page'. HTTP 403 Forbidden status is returned |
| 3 | Verify that role management navigation option is not visible in the user interface for non-admin user | Role management menu item or link is not displayed in navigation menu or sidebar for non-admin user |
| 4 | Attempt to access role management API endpoint directly (GET /api/user-roles) using non-admin credentials | API request is rejected with 403 Forbidden status and appropriate error message in response body |
| 5 | Verify that the unauthorized access attempt is logged in security audit log | Security audit log contains entry showing non-admin user attempted to access role management with timestamp and denial status |
| 6 | Log out from non-admin account and log in as an admin user | Admin user successfully logs into the system |
| 7 | Navigate to the role management page using the same URL or navigation link | Role management page loads successfully displaying user list, roles, and management controls |
| 8 | Verify that all role management functions are accessible (view users, assign roles, modify roles) | Admin can view complete user list with current roles, access role assignment interface, and all management functions are enabled and functional |
| 9 | Access role management API endpoint (GET /api/user-roles) using admin credentials | API request succeeds with 200 OK status and returns user roles data in response |
| 10 | Verify admin access is logged in audit trail | Audit log shows admin user accessed role management page with timestamp |

**Postconditions:**
- Non-admin users remain unable to access role management functions
- Admin users retain full access to role management
- All access attempts (both denied and granted) are logged in audit trail
- System security posture is maintained with proper access controls enforced

---

