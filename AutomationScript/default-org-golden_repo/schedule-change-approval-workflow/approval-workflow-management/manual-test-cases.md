# Manual Test Cases

## Story: As Manager, I want to review and approve schedule change requests to ensure operational continuity
**Story ID:** story-12

### Test Case: Verify manager can view and approve schedule change requests
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Manager user account exists with valid credentials and approval permissions
- At least one pending schedule change request exists in the system
- Manager is assigned as the approver for the pending request
- System is accessible and all services are running
- Database contains ScheduleChangeRequests with status 'Pending'

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the system login page and enter valid manager credentials (username and password), then click Login button | Manager is successfully authenticated and redirected to the home page or dashboard |
| 2 | Click on the 'Approvals' or 'Approval Dashboard' menu item in the navigation | Approval dashboard page loads and displays a list of all pending schedule change requests assigned to the manager with columns showing request ID, employee name, requested date, request type, and submission date |
| 3 | Click on a specific pending request from the list to view its details | Request detail page opens displaying complete information including employee details, current schedule, requested schedule, reason for change, submission date, any attached documents/files, and previous comments if any |
| 4 | Review all displayed information and attachments, then click the 'Approve' button | A comment dialog box appears prompting the manager to enter approval comments |
| 5 | Enter a meaningful approval comment in the text field (e.g., 'Approved due to valid business reason') and click 'Submit' or 'Confirm Approval' button | System processes the approval, displays a success message, request status changes to 'Approved', timestamp and manager details are logged, and a notification is sent to the requester. The request is removed from the pending list or marked as approved |

**Postconditions:**
- Request status is updated to 'Approved' in the database
- Approval action is logged in ApprovalActions table with timestamp and manager user ID
- Requester receives notification about the approval
- Request no longer appears in the pending approvals list
- Audit trail contains complete record of the approval action

---

### Test Case: Verify rejection with mandatory comment
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Manager user is logged into the system with valid approval permissions
- At least one pending schedule change request exists and is assigned to the manager
- Manager has navigated to the approval dashboard
- System validation rules for mandatory comments are active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | From the approval dashboard, click on a pending schedule change request to open its details | Request detail page loads showing all request information, attachments, and action buttons (Approve, Reject, Request Info) |
| 2 | Click the 'Reject' button without entering any comment in the comment field | System displays a validation error message indicating 'Comment is mandatory for rejection' or similar message. The rejection action is not processed and the request status remains unchanged |
| 3 | Enter a detailed rejection comment in the comment text field (e.g., 'Rejected due to insufficient staffing coverage during requested period') | Comment text is accepted and displayed in the comment field without validation errors |
| 4 | Click the 'Reject' or 'Submit Rejection' button | System processes the rejection successfully, displays a success confirmation message, request status updates to 'Rejected', the rejection comment is saved, timestamp and manager details are logged, and a notification is sent to the requester |

**Postconditions:**
- Request status is updated to 'Rejected' in ScheduleChangeRequests table
- Rejection comment is stored and associated with the request
- Rejection action is logged in ApprovalActions table with timestamp and manager ID
- Requester receives notification with rejection reason
- Request is removed from pending list and moved to rejected requests
- Complete audit trail exists for the rejection action

---

### Test Case: Ensure unauthorized users cannot access approval actions
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Non-manager user account exists in the system without approval permissions
- Role-based access control is properly configured
- API endpoints for approvals are protected with authorization checks
- At least one pending schedule change request exists in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system using non-manager user credentials (e.g., regular employee account) | User is successfully authenticated and redirected to their appropriate dashboard without approval menu options |
| 2 | Attempt to manually navigate to the approval dashboard URL (e.g., /approvals or /approval-dashboard) by typing it in the browser address bar | System denies access and displays an error message such as 'Access Denied: You do not have permission to view this page' or redirects to an unauthorized access page with HTTP 403 status |
| 3 | Using API testing tool or browser developer console, attempt to directly call the approval API endpoint GET /api/approvals/pending with the non-manager user's authentication token | API returns HTTP 403 Forbidden status code with error message indicating insufficient permissions, and no approval data is returned |
| 4 | Attempt to call the approval action API endpoint POST /api/approvals/actions with a valid request ID and approval action using the non-manager user's authentication token | API returns HTTP 403 Forbidden status code with error message 'Unauthorized: User does not have approval permissions', and no approval action is processed or recorded |

**Postconditions:**
- No approval actions are processed or logged for the unauthorized user
- Request status remains unchanged
- Security event may be logged indicating unauthorized access attempt
- System integrity is maintained with no unauthorized data access
- User remains restricted to their authorized functionality only

---

## Story: As Approver, I want to request additional information on schedule change requests to make informed decisions
**Story ID:** story-13

### Test Case: Verify approver can request additional information with comments
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Approver user account exists with valid credentials and approval permissions
- At least one pending schedule change request exists in the system
- Approver is assigned to review the pending request
- Requester user account is active and can receive notifications
- System notification service is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system as an approver and navigate to the approval dashboard | Approver is successfully logged in and approval dashboard displays with list of pending schedule change requests |
| 2 | Click on a specific schedule change request from the pending list to open its details | Request detail page opens displaying complete information including employee details, current schedule, requested schedule, reason for change, attachments, and action buttons (Approve, Reject, Request Additional Information) |
| 3 | Click the 'Request Additional Information' or 'Request Info' button | A comment dialog or text field appears prompting the approver to enter details about what additional information is needed |
| 4 | Enter specific comments in the text field describing the additional information needed (e.g., 'Please provide coverage plan for your current shift assignments during the requested time off period') | Comment text is accepted and displayed in the input field without validation errors |
| 5 | Click 'Submit' or 'Send Request' button to submit the information request | System processes the request successfully, displays confirmation message 'Information request sent successfully', request status updates to 'Information Requested' or 'Pending Additional Info', and a notification is sent to the requester |
| 6 | Log out as approver and log in as the requester user who submitted the original schedule change request | Requester logs in successfully and sees a notification indicating that additional information has been requested on their schedule change request |
| 7 | Requester navigates to their schedule change requests and opens the request with information requested status | Request details page displays showing the approver's comments requesting additional information, along with an option to update or respond to the request |
| 8 | Requester enters the additional information in the response field or updates the request details (e.g., adds coverage plan document and explanatory comments), then clicks 'Submit Update' or 'Respond' button | System accepts the updated information, displays success message, request status updates to 'Under Review' or 'Information Provided', and a notification is sent to the approver |
| 9 | Log out as requester and log back in as the approver | Approver logs in and sees a notification that the requester has provided additional information on the schedule change request |
| 10 | Approver opens the updated request to review the newly provided information | Request detail page displays with the updated information, requester's response comments, any new attachments, and the complete communication history between approver and requester |

**Postconditions:**
- Request status is updated to reflect information request and subsequent response
- All information requests and responses are logged in ApprovalActions table with timestamps
- Complete audit trail exists showing approver's information request and requester's response
- Both approver and requester received appropriate notifications
- Request is available for approver to continue review process
- Communication history is preserved and visible in the request details

---

### Test Case: Ensure mandatory comments for information requests
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- Approver user is logged into the system with valid approval permissions
- At least one pending schedule change request exists and is accessible to the approver
- Approver has navigated to the request detail page
- System validation rules for mandatory comments on information requests are active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | From the approval dashboard, click on a pending schedule change request to open its details | Request detail page loads displaying all request information and action buttons including 'Request Additional Information' |
| 2 | Click the 'Request Additional Information' button without entering any text in the comment field | A comment input dialog or field appears for entering the information request details |
| 3 | Leave the comment field empty and click 'Submit' or 'Send Request' button | System displays a validation error message such as 'Comment is required when requesting additional information' or 'Please specify what additional information is needed'. The information request is not processed, no notification is sent, and the request status remains unchanged |
| 4 | Verify that the request status has not changed and no action has been logged | Request status remains 'Pending', no entry is created in ApprovalActions table, and requester has not received any notification |

**Postconditions:**
- Request status remains unchanged at 'Pending'
- No information request action is logged in the system
- No notification is sent to the requester
- Approver remains on the request detail page with the option to properly submit an information request with comments
- System data integrity is maintained with no incomplete records

---

