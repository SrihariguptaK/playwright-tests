# Manual Test Cases

## Story: As Approver, I want to review and decide on schedule change requests to ensure authorized modifications
**Story ID:** story-13

### Test Case: Validate approval decision submission with comments
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Approver user account exists with valid credentials and Approver role assigned
- At least one schedule change request is in 'Pending' status and assigned to the logged-in approver
- Request has complete details including requester information, schedule changes, and justification
- At least one document is attached to the request
- System is accessible and all services are running

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page and enter valid approver credentials (username and password), then click Login button | Approver is successfully authenticated and redirected to the dashboard home page |
| 2 | Click on 'Pending Approvals' menu item or navigate to the pending approvals dashboard | List of pending schedule change requests assigned to the approver is displayed with columns showing request ID, requester name, submission date, and request type |
| 3 | Select a specific pending request from the list by clicking on the request row or 'View Details' button | Request details page opens displaying complete information including requester details, current schedule, proposed schedule, justification, submission timestamp, and attached documents section |
| 4 | Review all request details and click on attached document links to view supporting documentation | All request information is clearly visible and attached documents open successfully for review in a new tab or viewer |
| 5 | Locate the decision section, select 'Approve' option from the decision radio buttons or dropdown menu | 'Approve' decision is selected and highlighted, comments text area becomes available for input |
| 6 | Enter detailed comments in the comments text area explaining the rationale for approval (e.g., 'Request approved as justification is valid and no conflicts identified') | Comments are entered successfully in the text area with character count displayed if applicable |
| 7 | Click 'Submit Decision' button to finalize the approval | System processes the submission, displays a success confirmation message (e.g., 'Decision submitted successfully'), request status updates to 'Approved', and approver is redirected to pending approvals list or confirmation page |
| 8 | Verify the request no longer appears in the pending approvals list | The approved request is removed from the pending list and the count of pending requests is decremented by one |

**Postconditions:**
- Request status is updated to 'Approved' in the database
- Decision timestamp and approver identity are logged in the system
- Comments are saved and associated with the approval decision
- Requester receives notification of approval decision
- Audit trail entry is created with complete decision details
- Request is moved to approved requests archive

---

### Test Case: Verify rejection of decision submission without selection
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Approver user account exists with valid credentials and Approver role assigned
- At least one schedule change request is in 'Pending' status and assigned to the logged-in approver
- System validation rules are configured to require decision selection before submission
- System is accessible and all services are running

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page and enter valid approver credentials, then click Login button | Approver is successfully authenticated and redirected to the dashboard |
| 2 | Navigate to 'Pending Approvals' section from the main menu | List of pending schedule change requests is displayed |
| 3 | Click on a pending request to open the request details page | Request details page opens showing all request information, decision options (Approve/Reject/Request More Info), and comments field |
| 4 | Without selecting any decision option (Approve, Reject, or Request More Info), optionally enter comments in the comments text area | Comments are entered but no decision radio button or option is selected |
| 5 | Click 'Submit Decision' button without selecting a decision | System blocks the submission and displays a validation error message such as 'Please select a decision before submitting' or 'Decision selection is required' near the decision options or at the top of the form |
| 6 | Verify that the request status remains unchanged and the page remains on the request details view | Request status is still 'Pending', no changes are saved to the database, and the approver remains on the same page to make corrections |
| 7 | Verify the decision options are highlighted or marked to indicate required field | Decision section is visually indicated as required (e.g., red border, asterisk, or error styling) |

**Postconditions:**
- Request status remains 'Pending' in the database
- No decision record is created or logged
- No notifications are sent to the requester
- Approver remains on the request details page to complete the required action
- No audit trail entry is created for this attempted submission

---

### Test Case: Test audit logging of approval decisions
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Approver user account exists with valid credentials and Approver role assigned
- Administrator user account exists with permissions to view audit logs
- At least one schedule change request is in 'Pending' status and assigned to the approver
- Audit logging functionality is enabled and configured in the system
- System is accessible and all services are running

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login as approver, navigate to pending approvals, and select a request to review | Approver is logged in and request details page is displayed |
| 2 | Select a decision option (e.g., 'Approve'), enter comments such as 'Approved based on valid business justification and resource availability', and note the current system timestamp | Decision is selected and comments are entered in the text area |
| 3 | Click 'Submit Decision' button to submit the approval decision | System displays success confirmation message, decision is saved, and request status is updated to 'Approved' |
| 4 | Note the approver's user ID and the exact timestamp of submission from the confirmation message or system clock | Submission timestamp and approver identity are captured for verification |
| 5 | Logout from the approver account and login as administrator with valid admin credentials | Administrator is successfully authenticated and redirected to admin dashboard |
| 6 | Navigate to 'Audit Logs' or 'System Logs' section from the administrator menu | Audit logs page is displayed with search and filter options |
| 7 | Search or filter audit logs by the request ID, approver user ID, or timestamp range corresponding to the submitted decision | Audit log entries matching the search criteria are displayed in a table or list format |
| 8 | Locate and verify the audit log entry for the approval decision contains: request ID, decision type ('Approved'), approver user ID, timestamp, and comments text | Audit log entry is present and displays accurate information including: correct request ID, decision='Approved', approver ID matching the logged-in approver, timestamp within acceptable range (±1 minute of submission), and exact comments text entered by approver |
| 9 | Verify the audit log entry is immutable and displays creation metadata (created by, created date) | Audit log entry shows as read-only with no edit or delete options, and includes system-generated metadata |

**Postconditions:**
- Audit log entry exists in the database with complete decision details
- Audit log entry is immutable and tamper-proof
- Timestamp is accurate and matches the decision submission time
- Approver identity is correctly recorded in the audit trail
- Comments are fully captured in the audit log
- Audit log is accessible to authorized administrators for compliance and review purposes

---

## Story: As Approver, I want to receive notifications for new schedule change requests to ensure timely review
**Story ID:** story-15

### Test Case: Validate email notification sent on new request assignment
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Approver user account exists with valid email address configured in the system
- Email notification service is configured and operational
- Approver has notification preferences enabled for email notifications
- System has capability to assign schedule change requests to approvers
- Email server is accessible and functioning properly
- Test email inbox is accessible for verification

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Note the current system time before initiating the test | Current timestamp is recorded for measuring notification delivery time |
| 2 | As a requester or administrator, create and submit a new schedule change request and assign it to a specific approver | Schedule change request is successfully created and assigned to the target approver, request status is set to 'Pending Approval' |
| 3 | Monitor the system notification queue or logs to verify notification trigger event is fired | System detects the new assignment and triggers email notification process within seconds of assignment |
| 4 | Wait for up to 1 minute and check the approver's email inbox for the notification email | Email notification is received in the approver's inbox within 1 minute of request assignment, meeting the performance requirement |
| 5 | Open the notification email and verify the sender is the system notification address (e.g., noreply@schedulesystem.com) | Email sender is correctly identified as the system notification service |
| 6 | Verify the email subject line contains relevant information such as 'New Schedule Change Request Requires Your Approval' or similar clear subject | Email subject is clear, professional, and indicates the purpose of the notification |
| 7 | Review the email body content to verify it includes: request summary (request ID, requester name, request type, submission date), brief description of the schedule change, and a direct clickable link to review the request | Email body contains complete request summary with all required information: request ID, requester name, request type, submission date, schedule change description, and a properly formatted hyperlink to the request review page |
| 8 | Click on the direct link provided in the email notification | Link opens the application in a web browser and navigates directly to the specific request review page, with the request details displayed (may require login if not already authenticated) |
| 9 | Verify the timestamp of email receipt matches within 1 minute of the request assignment time noted in step 1 | Email delivery time is within the 1-minute SLA requirement from the time of request assignment |

**Postconditions:**
- Email notification is successfully delivered to approver's inbox
- Notification delivery is logged in the system with timestamp
- Approver can access the request directly via the email link
- Notification record is created in the database preventing duplicate sends
- Email delivery time meets the 1-minute performance requirement

---

### Test Case: Verify in-app alert on approver login
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Approver user account exists with valid credentials
- At least one new schedule change request is assigned to the approver and is in 'Pending Approval' status
- Approver has not yet logged in since the request was assigned (to ensure alert is new)
- In-app notification feature is enabled in the system
- System is accessible and all services are running

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Ensure at least one pending approval request exists for the test approver by creating and assigning a new schedule change request | New schedule change request is created and assigned to the approver, status is 'Pending Approval' |
| 2 | Navigate to the application login page and enter the approver's valid credentials (username and password) | Login credentials are entered in the respective fields |
| 3 | Click the Login button to authenticate | Approver is successfully authenticated and redirected to the dashboard or home page |
| 4 | Immediately upon page load, observe the top navigation bar, notification bell icon, or alert panel for in-app alerts | In-app alert is prominently displayed showing notification of new approval requests, typically as a badge count on notification icon, banner message, or popup alert |
| 5 | Verify the alert content includes a list or summary of new pending approval requests with request IDs and requester names | Alert displays clear information listing new requests such as 'You have 1 new approval request' or 'New request from [Requester Name] - Request ID: [ID]' |
| 6 | Click on the in-app alert notification or the notification bell icon to expand alert details | Alert expands to show detailed list of pending requests with clickable links for each request |
| 7 | Click on the link or button within the alert corresponding to a specific pending request | System navigates directly to the request review page for the selected request, displaying complete request details including requester information, schedule changes, justification, and attached documents |
| 8 | Verify the URL and page content confirm navigation to the correct request review page matching the request ID from the alert | Request review page displays the correct request matching the ID clicked in the alert, with all details visible and ready for review |

**Postconditions:**
- In-app alert is displayed successfully upon approver login
- Alert provides accurate information about pending requests
- Navigation link from alert to request review page functions correctly
- Alert can be dismissed or marked as read after viewing
- User experience is smooth and notifications are non-intrusive

---

### Test Case: Test prevention of duplicate notifications
- **ID:** tc-006
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Approver user account exists with valid email address configured
- Email notification service is operational
- System has duplicate notification prevention logic implemented
- Test environment allows simulation of multiple assignment processing events
- Access to notification logs or database to verify notification records
- Email inbox is accessible for verification

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Clear or note the current state of the approver's email inbox and in-app notifications to establish a baseline | Baseline state is established with count of existing notifications recorded |
| 2 | Create a new schedule change request and assign it to the target approver for the first time | Request is created and assigned successfully, assignment event is triggered in the system |
| 3 | Verify that the first notification is sent by checking the notification logs or database for a notification record with the request ID and approver ID | One notification record is created in the database with status 'Sent', timestamp is recorded, and email is delivered to approver's inbox |
| 4 | Simulate or trigger the same request assignment event again (this could be done by re-running the assignment process, triggering a system event, or using an API call to process the same assignment) | System processes the duplicate assignment event or trigger |
| 5 | Wait for up to 2 minutes to allow sufficient time for any potential duplicate notification to be sent | Waiting period completes |
| 6 | Check the notification logs or database to verify the total number of notification records for this specific request ID and approver combination | Only one notification record exists in the database for this request-approver pair, no duplicate records are created despite multiple processing attempts |
| 7 | Check the approver's email inbox to count the number of notification emails received for this specific request | Only one email notification is present in the inbox for this request, no duplicate emails were sent |
| 8 | Review system logs for duplicate detection messages or warnings indicating that duplicate notification was prevented | System logs show evidence of duplicate detection logic executing successfully, such as 'Duplicate notification prevented for Request ID [ID]' or similar log entry |
| 9 | Repeat steps 4-7 one more time to test multiple duplicate attempts (trigger assignment a third time) | System continues to prevent duplicate notifications, maintaining only one notification record and one email in inbox regardless of multiple processing attempts |

**Postconditions:**
- Only one notification record exists in the database for the request-approver combination
- Only one email notification was delivered to the approver's inbox
- Duplicate prevention logic is confirmed to be working correctly
- System logs document the duplicate prevention actions
- No unnecessary notifications clutter the approver's inbox or alert system
- Database integrity is maintained without duplicate notification records

---

