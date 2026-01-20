# Manual Test Cases

## Story: As Approver, I want to perform approval of schedule change requests to achieve timely decision making
**Story ID:** story-2

### Test Case: Validate display of pending schedule change requests
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Approver user account exists with valid credentials
- Approver has been assigned pending schedule change requests
- At least one schedule change request is in pending status
- System is accessible and operational
- Approver has appropriate role-based permissions

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the system login page and enter valid approver credentials (username and password), then click Login button | Approver is successfully authenticated and redirected to the dashboard displaying pending approvals within 3 seconds |
| 2 | Review the pending approvals dashboard and select a pending schedule change request from the list by clicking on it | Request details page opens showing complete information including requester name, requested changes, reason for change, submission date, and any attached documents or files |
| 3 | Review the request details and attachments, enter approval comments in the comments field, and click the Approve button | Request status immediately updates to 'Approved', confirmation message is displayed to the approver, and the request is removed from the pending approvals list |

**Postconditions:**
- Schedule change request status is updated to 'Approved' in the database
- Approval action is logged with timestamp and approver details
- Requester receives notification of approval
- Request no longer appears in pending approvals dashboard

---

### Test Case: Verify rejection requires mandatory comments
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Approver is logged into the system
- At least one schedule change request is pending approval
- Approver has permissions to reject requests
- Validation rules for mandatory comments are configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | From the pending approvals dashboard, select a schedule change request and click on it to open details | Request details page is displayed with options to Approve or Reject |
| 2 | Click the Reject button without entering any comments in the comments field | Rejection form is displayed with the comment field highlighted, validation error message appears stating 'Comments are required for rejection', and the submission is blocked |
| 3 | Enter detailed rejection comments in the comments field explaining the reason for rejection, then click Submit | Request status immediately updates to 'Rejected', confirmation message is displayed, rejection comments are saved, and the request is removed from pending approvals list |

**Postconditions:**
- Schedule change request status is updated to 'Rejected' in the database
- Rejection comments are stored with the request
- Approval action is logged with timestamp, approver details, and comments
- Requester receives notification of rejection with comments

---

### Test Case: Test multi-level approval routing
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Multi-level approval workflow is configured in the system
- First-level approver account exists and is active
- Second-level approver account exists and is active
- Schedule change request type requires multi-level approval
- Approval routing rules are properly defined

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Submit a schedule change request that requires multi-level approval through the request submission interface | Request is successfully submitted and automatically routed to the first-level approver, appearing in their pending approvals dashboard with status 'Pending - Level 1 Approval' |
| 2 | Log in as the first-level approver, navigate to pending approvals, select the request, enter approval comments, and click Approve | First-level approval is recorded, request status updates to 'Pending - Level 2 Approval', and the request is automatically routed to the second-level approver's pending approvals dashboard |
| 3 | Log in as the second-level approver, navigate to pending approvals, select the request, review first-level approval details, enter approval comments, and click Approve | Second-level approval is recorded, request status updates to 'Approved', confirmation message is displayed, and the request is marked as fully approved with all approval levels completed |

**Postconditions:**
- Schedule change request status is 'Approved' with all approval levels completed
- Both first-level and second-level approval actions are logged with timestamps
- Request no longer appears in any approver's pending list
- Requester receives notification of final approval
- Audit trail shows complete multi-level approval workflow

---

## Story: As Approver, I want to perform viewing of approval history to achieve audit and compliance tracking
**Story ID:** story-4

### Test Case: Validate display of approval history for a schedule change request
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Approver or auditor is logged into the system with valid credentials
- At least one schedule change request exists with approval history
- Multiple approval actions have been recorded for the request
- User has authorized role to view approval history
- ApprovalActions table contains historical data

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule change requests list and click on a specific schedule change request to open its details page | Schedule change request details page is displayed showing request information, current status, and available tabs including 'Approval History' |
| 2 | Click on the 'Approval History' tab on the request details page | Approval history tab loads within 2 seconds displaying a chronological list of all approval actions in reverse chronological order (most recent first) |
| 3 | Review each approval action entry in the history list to verify all required information is displayed | Each approval action shows complete details including approver full name, decision (Approved/Rejected), comments entered by approver, and timestamp in readable format (date and time). All data is accurate and matches the recorded approval actions |

**Postconditions:**
- Approval history remains accessible for future reference
- No data is modified during the viewing process
- User session remains active
- Audit log records the history access action

---

### Test Case: Test export of approval history report
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in with authorized role
- Schedule change request with approval history exists
- User is viewing the approval history tab
- PDF export functionality is enabled
- User has appropriate permissions to export reports

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | On the approval history tab, locate and click the 'Export to PDF' button | PDF report generation process initiates, progress indicator is displayed, and PDF file is automatically generated and downloaded to the user's default download location |
| 2 | Navigate to the download location, locate the exported PDF file, and open it using a PDF reader application | PDF report opens successfully and contains complete approval history details including request information, chronological list of all approval actions with approver names, decisions, comments, timestamps, and proper formatting for readability |

**Postconditions:**
- PDF file is saved in user's download folder
- Original approval history data remains unchanged
- Export action is logged in audit trail
- PDF contains accurate snapshot of approval history at time of export

---

### Test Case: Verify access control for approval history
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Role-based access control is configured for approval history
- Unauthorized user account exists without approval history permissions
- Authorized approver account exists with proper permissions
- Schedule change request with approval history exists
- Security policies are enforced

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as an unauthorized user (without approval history access permissions) and attempt to navigate to a schedule change request's approval history tab or directly access the approval history URL | Access is denied, system displays 'Access Denied' or 'Unauthorized Access' error message, and user is prevented from viewing the approval history. User may be redirected to an error page or their dashboard |
| 2 | Log out from the unauthorized user account, then log in as an authorized approver with proper permissions to view approval history | Authorized approver successfully logs in and can navigate to schedule change request details |
| 3 | Navigate to the schedule change request details page and click on the 'Approval History' tab | Approval history tab is accessible, loads within 2 seconds, and displays complete chronological approval history with all approval action details visible to the authorized approver |

**Postconditions:**
- Access control policies remain enforced
- Unauthorized access attempts are logged in security audit trail
- Authorized users maintain proper access to approval history
- No security vulnerabilities are exposed

---

## Story: As System Administrator, I want to perform configuration of approval workflow rules to achieve flexible and maintainable approval processes
**Story ID:** story-5

### Test Case: Validate creation and saving of workflow configuration
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with System Administrator role
- WorkflowConfigurations table is accessible
- API endpoints GET/POST /api/workflow-configurations are operational
- At least one approver role and user exist in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | System Administrator navigates to workflow configuration page | Configuration UI is displayed with options to create new workflow, view existing workflows, and configuration form fields |
| 2 | Click 'Create New Workflow' button | New workflow configuration form is displayed with empty fields for workflow name, approvers, approval levels, and routing rules |
| 3 | Enter workflow name, select approver roles and users, define multi-level approval sequence, and set routing rules | All entered data is accepted and displayed correctly in the form fields without validation errors |
| 4 | Click 'Save' button to save the workflow configuration | Configuration is saved successfully, confirmation message is displayed, and workflow appears in the list with 'Inactive' status |
| 5 | Select the saved workflow from the list and click 'Activate' button | Workflow status changes to 'Active', activation confirmation message is displayed, and configuration is applied to the system |
| 6 | Wait for 5 minutes and verify workflow is operational | Workflow configuration changes are propagated and the workflow is fully active and ready to process approval requests |

**Postconditions:**
- New workflow configuration is saved in WorkflowConfigurations table
- Workflow status is set to 'Active'
- Configuration is applied and operational within 5 minutes
- Workflow is available for processing approval requests

---

### Test Case: Verify validation prevents invalid configurations
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with System Administrator role
- Workflow configuration page is accessible
- Validation rules are configured in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to workflow configuration page and click 'Create New Workflow' | New workflow configuration form is displayed |
| 2 | Enter workflow name but leave approver roles and users fields empty | Form accepts the partial input without immediate validation |
| 3 | Click 'Save' button with incomplete configuration | Validation errors are displayed indicating required fields: 'Approver roles required', 'At least one approver user must be selected', save operation is blocked |
| 4 | Add approvers but create conflicting routing rules (e.g., circular dependencies or contradictory conditions) | Validation errors are displayed indicating conflicting rules with specific details about the conflict, save operation is blocked |
| 5 | Correct all validation errors by filling required fields and resolving conflicting routing rules | Validation errors disappear as corrections are made, form shows no validation errors |
| 6 | Click 'Save' button with corrected configuration | Configuration is saved successfully, confirmation message is displayed, and workflow appears in the list |

**Postconditions:**
- Valid workflow configuration is saved in the system
- Invalid configurations are prevented from being saved
- Validation messages guide administrator to correct errors

---

### Test Case: Test access restriction to workflow configuration
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Two user accounts exist: one with Admin role and one with non-admin role (e.g., Approver or Employee)
- Workflow configuration page URL is known
- Security role validation is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in to the system using non-admin user credentials | User is successfully logged in and redirected to their default dashboard |
| 2 | Attempt to navigate to workflow configuration page by entering URL directly or through navigation menu | Access denied message is displayed: 'You do not have permission to access this page. Admin role required.' User is not able to view or access the configuration page |
| 3 | Log out from non-admin user account | User is successfully logged out and redirected to login page |
| 4 | Log in to the system using Admin user credentials | Admin user is successfully logged in and redirected to admin dashboard |
| 5 | Navigate to workflow configuration page | Full access is granted, workflow configuration page is displayed with all configuration options, create/edit/delete capabilities are available |
| 6 | Verify all workflow configuration features are accessible (view, create, edit, activate, deactivate) | All workflow configuration features are fully functional and accessible to the Admin user |

**Postconditions:**
- Non-admin users remain restricted from workflow configuration access
- Admin users have full access to workflow configuration
- Security role validation is confirmed working correctly

---

## Story: As Approver, I want to perform filtering and searching of schedule change requests to achieve efficient workload management
**Story ID:** story-7

### Test Case: Validate filtering by status and date range
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Approver role
- Multiple schedule change requests exist with various statuses (Pending, Approved, Rejected)
- Schedule change requests exist with submission dates spanning more than 7 days
- Approver has authorization to view the test schedule change requests
- Pending approvals dashboard is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to pending approvals dashboard | Dashboard is displayed showing all pending schedule change requests assigned to the approver without any filters applied |
| 2 | Locate and click on the status filter dropdown | Status filter dropdown opens showing available status options: All, Pending, Approved, Rejected |
| 3 | Select 'Pending' from the status filter dropdown | Status filter is applied, dropdown shows 'Pending' as selected |
| 4 | Locate and click on the date range filter, select 'Last 7 days' option | Date range filter is applied showing 'Last 7 days', date range displays current date minus 7 days to current date |
| 5 | Click 'Apply Filters' button | Filtered list is displayed within 2 seconds showing only schedule change requests with status 'Pending' submitted within the last 7 days, request count is updated to reflect filtered results |
| 6 | Verify each displayed request matches the filter criteria by checking status and submission date | All displayed requests have status 'Pending' and submission dates within the last 7 days |
| 7 | Click 'Clear Filters' button | All filters are removed, full list of pending approvals assigned to the approver is displayed, filter controls reset to default state |

**Postconditions:**
- Filters are cleared and system returns to unfiltered view
- Filter functionality is confirmed working correctly
- No data is modified during the test

---

### Test Case: Test keyword search functionality
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Approver role
- Multiple schedule change requests exist with varying details and descriptions
- At least one request contains a known unique keyword in its details
- Search functionality is enabled on pending approvals dashboard

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to pending approvals dashboard | Dashboard is displayed with search box visible and full list of pending schedule change requests |
| 2 | Locate the keyword search input field | Search input field is visible and active, placeholder text indicates 'Search requests...' |
| 3 | Enter a keyword that is known to exist in at least one request's details (e.g., 'vacation', 'emergency', or specific employee name) | Keyword is entered in the search field and displayed correctly |
| 4 | Press Enter or click 'Search' button | Search is executed within 2 seconds, list is filtered to show only requests containing the entered keyword in their details, matching keyword is highlighted in the results |
| 5 | Verify that all displayed requests contain the searched keyword in their details | All displayed requests contain the keyword in request title, description, or other detail fields |
| 6 | Clear the search field and enter a keyword that does not exist in any request (e.g., 'xyzabc123nonexistent') | Non-existent keyword is entered in the search field |
| 7 | Press Enter or click 'Search' button | Search is executed within 2 seconds, no results are displayed, message 'No schedule change requests found matching your search criteria' is shown |
| 8 | Clear the search field | Search is cleared, full list of pending approvals is restored and displayed |

**Postconditions:**
- Search field is cleared
- Full unfiltered list is displayed
- Search functionality is confirmed working for both existing and non-existing keywords

---

### Test Case: Verify sorting of filtered results
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Approver role
- Multiple schedule change requests exist with different submission dates and priority levels
- At least 5 requests are available for meaningful sorting verification
- Requests have varied submission dates and priority values (High, Medium, Low)
- Pending approvals dashboard is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to pending approvals dashboard | Dashboard is displayed with list of schedule change requests in default sort order |
| 2 | Apply any filter (e.g., status 'Pending') to create a filtered result set | Filtered list is displayed showing only pending requests |
| 3 | Locate the 'Submission Date' column header and click to sort descending | Sort indicator (down arrow) appears on Submission Date column header, requests are reordered from newest to oldest submission date |
| 4 | Verify the order by checking submission dates of first and last visible requests | First request has the most recent submission date, last request has the oldest submission date, all requests are in descending chronological order |
| 5 | Click on 'Submission Date' column header again to toggle sort to ascending | Sort indicator changes to up arrow, requests are reordered from oldest to newest submission date |
| 6 | Locate the 'Priority' column header and click to sort ascending | Sort indicator (up arrow) appears on Priority column header, requests are reordered from lowest to highest priority (Low, Medium, High) |
| 7 | Verify the order by checking priority values of displayed requests | Requests are ordered with Low priority first, followed by Medium, then High priority requests last, all requests maintain the filtered criteria while being sorted |
| 8 | Click on 'Priority' column header again to toggle sort to descending | Sort indicator changes to down arrow, requests are reordered from highest to lowest priority (High, Medium, Low) |

**Postconditions:**
- Filtered results remain filtered while sorting is applied
- Sort functionality works correctly for both submission date and priority columns
- No data is modified during sorting operations

---

## Story: As Approver, I want to perform delegation of approval tasks to achieve workload distribution
**Story ID:** story-11

### Test Case: Validate creation of approval delegation
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Approver role
- At least one qualified delegate user exists in the system
- Approver has pending approval tasks assigned
- Delegations table is accessible and operational
- API endpoint POST /api/delegations is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the delegation settings page from the approver dashboard | Delegation UI is displayed with options to create new delegation, showing delegate selection dropdown and date range fields |
| 2 | Click on the delegate user dropdown and select a qualified user from the list | Selected delegate user is highlighted and displayed in the delegate field |
| 3 | Set the delegation start date to current date using the date picker | Start date is populated with the selected date in the correct format |
| 4 | Set the delegation end date to a future date (e.g., 7 days from current date) using the date picker | End date is populated with the selected date and is after the start date |
| 5 | Click the 'Save Delegation' or 'Create Delegation' button | System displays success message confirming delegation has been saved successfully, and delegation appears in the active delegations list |
| 6 | Log out from the Approver account and log in with the delegate user credentials | Delegate user is successfully logged into the system |
| 7 | Navigate to the approvals or tasks section as the delegate user | Delegate can see and access the delegated approval tasks that were originally assigned to the Approver, with clear indication that these are delegated tasks |

**Postconditions:**
- Delegation is active and stored in the Delegations table
- Delegate user has access to the Approver's pending approval tasks
- Approver can view the active delegation in their delegation settings
- Delegation action is logged in the audit log with timestamp and user details

---

### Test Case: Test revocation of delegation
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Approver role
- An active delegation exists that was created by the Approver
- Delegate user currently has access to delegated approval tasks
- API endpoint for delegation management is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the delegation settings page from the approver dashboard | Delegation UI is displayed showing the list of active delegations |
| 2 | Locate the active delegation in the delegations list and identify the revoke option (button or link) | Active delegation is visible with delegate name, date range, and a 'Revoke' or 'Cancel' button |
| 3 | Click the 'Revoke Delegation' button for the active delegation | System displays a confirmation dialog asking to confirm the revocation action |
| 4 | Confirm the revocation by clicking 'Yes' or 'Confirm' in the confirmation dialog | System displays success message confirming delegation has been revoked, and the delegation is removed from the active delegations list or marked as revoked |
| 5 | Log out from the Approver account and log in with the delegate user credentials | Delegate user is successfully logged into the system |
| 6 | Navigate to the approvals or tasks section as the delegate user | Delegate can no longer see or access the previously delegated approval tasks; the tasks are no longer assigned to the delegate |
| 7 | Log back in as the Approver and verify the approval tasks are back in the Approver's queue | Approval tasks are visible in the Approver's pending tasks list and are no longer delegated |

**Postconditions:**
- Delegation is revoked and no longer active
- Delegate user no longer has access to the previously delegated approval tasks
- Approval tasks are returned to the original Approver
- Revocation action is logged in the audit log with timestamp and user details

---

### Test Case: Verify audit logging of delegation actions
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Approver role
- At least one qualified delegate user exists in the system
- Audit logging system is enabled and operational
- User has permissions to view audit logs or access to audit log reports
- API endpoints for delegation and audit logs are available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the delegation settings page and create a new delegation by selecting a delegate user and setting start and end dates | Delegation is created successfully and confirmation message is displayed |
| 2 | Click 'Save Delegation' to complete the delegation creation | System saves the delegation and displays it in the active delegations list |
| 3 | Navigate to the audit log section or access audit log reports | Audit log interface is displayed with search and filter options |
| 4 | Search or filter audit logs for delegation creation actions by the current Approver user | Audit log displays an entry for the delegation creation action with details including: action type (Delegation Created), Approver username, delegate username, timestamp, start date, and end date |
| 5 | Return to the delegation settings page and revoke the previously created delegation | Delegation is revoked successfully and confirmation message is displayed |
| 6 | Navigate back to the audit log section and refresh or search for recent delegation actions | Audit log interface displays updated entries including the revocation action |
| 7 | Search or filter audit logs for delegation revocation actions by the current Approver user | Audit log displays an entry for the delegation revocation action with details including: action type (Delegation Revoked), Approver username, delegate username, revocation timestamp, and original delegation details |
| 8 | Verify that both audit log entries (creation and revocation) contain accurate timestamps in chronological order | Both audit log entries are present with accurate timestamps showing creation occurred before revocation, and all user details are correctly recorded |

**Postconditions:**
- Audit log contains complete record of delegation creation with all required details
- Audit log contains complete record of delegation revocation with all required details
- All delegation actions are traceable with user identification and timestamps
- Audit trail demonstrates 100% logging of delegation actions as per success metrics

---

