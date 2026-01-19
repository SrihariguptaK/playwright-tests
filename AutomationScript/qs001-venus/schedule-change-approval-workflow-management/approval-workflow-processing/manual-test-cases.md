# Manual Test Cases

## Story: As Approver, I want to view pending schedule change requests to efficiently manage approvals
**Story ID:** story-2

### Test Case: Verify pending requests dashboard displays correct data
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User account with approver role exists in the system
- At least one pending schedule change request is assigned to the approver
- Test data includes requests with various statuses and attachments
- System is accessible and operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the system login page and enter valid approver credentials | User is successfully authenticated and redirected to the dashboard page |
| 2 | Observe the pending requests dashboard upon successful login | Dashboard loads within 3 seconds and displays a list of all pending schedule change requests assigned to the logged-in approver with summary information including employee name, request date, and status |
| 3 | Click on a specific pending request from the list to view its details | Request details page opens displaying complete information including employee details, requested schedule changes, submission date, current status, and any attached documents or files |

**Postconditions:**
- User remains logged in as approver
- Dashboard state is preserved for further actions
- No data modifications have occurred

---

### Test Case: Test filtering functionality on dashboard
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with approver role
- Dashboard is loaded with multiple pending requests
- Test data includes requests from different employees and date ranges
- Filtering controls are visible and enabled on the dashboard

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate the employee name filter field and enter a specific employee name or select from dropdown | Dashboard refreshes and displays only the schedule change requests submitted by the specified employee, hiding all other requests |
| 2 | Locate the date range filter controls and select a start date and end date | Dashboard updates to show only requests submitted within the specified date range, with request count updated accordingly |
| 3 | Click the 'Clear Filters' or 'Reset' button on the dashboard | All applied filters are removed and the dashboard returns to displaying all pending schedule change requests assigned to the approver |

**Postconditions:**
- All filters are cleared
- Dashboard displays complete list of pending requests
- Filter controls are reset to default state

---

### Test Case: Ensure unauthorized users cannot access dashboard
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User account without approver role exists in the system (e.g., employee or viewer role)
- Dashboard URL and API endpoints are known
- Security and role-based access control is configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login to the system using credentials of a non-approver user (employee or other role) | User is authenticated but when attempting to navigate to the pending requests dashboard, access is denied with an appropriate error message such as 'Access Denied' or 'Insufficient Permissions' |
| 2 | Using a REST client or browser developer tools, attempt to directly access the API endpoint GET /api/schedule-change-requests?status=pending&approverId={id} with the non-approver user's authentication token | API returns HTTP 403 Forbidden or 401 Unauthorized status code with an authorization error message indicating the user does not have permission to access this resource |

**Postconditions:**
- Non-approver user remains unable to access dashboard
- No unauthorized data exposure has occurred
- Security logs record the unauthorized access attempts

---

## Story: As Approver, I want to approve or reject schedule change requests to ensure accurate schedule management
**Story ID:** story-3

### Test Case: Approve schedule change request successfully
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with approver role
- At least one pending schedule change request exists and is assigned to the approver
- Request has complete details and attachments available
- Database is accessible for status updates and audit logging

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the pending requests dashboard and select a specific pending schedule change request to view | Request details page loads displaying complete information including employee name, requested schedule changes, submission date, reason for change, and any attached supporting documents |
| 2 | Review the request details and click the 'Approve' button | System processes the approval within 2 seconds, updates the request status to 'Approved', and displays a confirmation message such as 'Schedule change request has been approved successfully' |
| 3 | Navigate to the audit logs section or query the ApprovalLogs table to verify the approval action was logged | Audit log contains a new entry for this approval action with accurate details including request ID, approver user ID and name, action type 'Approved', timestamp of approval, and any additional metadata |

**Postconditions:**
- Request status is permanently updated to 'Approved' in the database
- Audit log entry is created and persisted
- Request is removed from pending requests list
- Approver can proceed to review other requests

---

### Test Case: Reject schedule change request with mandatory comments
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with approver role
- At least one pending schedule change request exists and is assigned to the approver
- Request details are accessible
- Rejection comments field validation is configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the pending requests dashboard and select a specific pending schedule change request to view | Request details page loads displaying complete information including employee name, requested schedule changes, submission date, reason for change, and any attached supporting documents |
| 2 | Click the 'Reject' button without entering any comments in the rejection comments field | System displays a validation error message such as 'Comments are required when rejecting a request' or 'Please provide a reason for rejection', preventing submission until comments are provided |
| 3 | Enter meaningful rejection comments in the comments field (e.g., 'Request conflicts with operational requirements') and click the 'Reject' or 'Submit' button | System processes the rejection within 2 seconds, updates the request status to 'Rejected', saves the rejection comments, and displays a confirmation message such as 'Schedule change request has been rejected' |

**Postconditions:**
- Request status is updated to 'Rejected' in the database
- Rejection comments are saved and associated with the request
- Audit log entry is created for the rejection action
- Request is removed from pending requests list

---

### Test Case: Verify audit logging of approval actions
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with approver role
- At least one pending schedule change request exists
- Audit logging system is enabled and operational
- Access to audit logs is available for verification

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Select a pending schedule change request and either approve it by clicking 'Approve' or reject it by entering comments and clicking 'Reject' | System processes the approval or rejection action successfully, updates the request status accordingly, and displays a confirmation message to the approver |
| 2 | Navigate to the audit logs interface or query the ApprovalLogs table using the request ID to retrieve audit records for the processed request | Audit log displays an accurate and complete record of the action including request ID, action type (Approved or Rejected), approver user ID and name, timestamp with date and time, rejection comments if applicable, and previous status vs new status |

**Postconditions:**
- Audit log entry is permanently stored in the database
- Audit trail maintains data integrity for compliance
- Log entry is available for future audits and reporting

---

