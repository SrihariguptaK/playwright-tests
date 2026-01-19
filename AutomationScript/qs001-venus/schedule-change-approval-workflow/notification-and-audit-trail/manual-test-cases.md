# Manual Test Cases

## Story: As Employee, I want to receive notifications about my schedule change request status to stay informed
**Story ID:** story-26

### Test Case: Verify notification sent upon schedule change request submission
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as an employee with valid credentials
- Employee has permission to submit schedule change requests
- Email service is configured and operational
- In-app notification service is running
- Employee has a valid email address in their profile

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule change request page | Schedule change request form is displayed with all required fields |
| 2 | Fill in all required fields for the schedule change request (date, time, reason) | All fields accept input and display entered data correctly |
| 3 | Click the Submit button to submit the schedule change request | Request is submitted successfully and confirmation message is displayed on screen |
| 4 | Check the employee's email inbox for submission confirmation notification | Email notification is received containing submission confirmation, request details, and reference number |
| 5 | Navigate to the notification center in the user profile | Notification center page loads successfully |
| 6 | Check the notification list for the submission confirmation | In-app notification is displayed with correct request details including date, time, request ID, and submission timestamp |

**Postconditions:**
- Schedule change request is saved in the system with pending status
- Submission confirmation notification is logged in notification history
- Email notification is sent and recorded in email logs
- In-app notification is visible in employee's notification center

---

### Test Case: Validate notification sent upon approval decision
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- A schedule change request exists in pending status
- User is logged in as an approver with valid credentials
- Approver has permission to approve/reject schedule change requests
- Employee who submitted the request has valid email and notification settings
- Notification service is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login as approver and navigate to the pending schedule change requests page | Pending requests page is displayed with list of requests awaiting approval |
| 2 | Select a specific schedule change request from the list | Request details are displayed including employee name, requested changes, and reason |
| 3 | Review the request details and click the Approve button | Approval confirmation dialog is displayed |
| 4 | Add approval comments (optional) and confirm the approval action | Request status is updated to Approved and success message is displayed |
| 5 | Logout as approver and login as the employee who submitted the request | Employee successfully logs in and dashboard is displayed |
| 6 | Navigate to the notification center in the employee's user profile | Notification center displays with list of notifications |
| 7 | Locate and click on the approval notification | Notification content is displayed showing approval status, approver name, approval timestamp, request details, and next steps for the employee |
| 8 | Verify the notification content includes actionable information | Notification contains complete information: approved schedule details, effective date, and any required follow-up actions |

**Postconditions:**
- Request status is permanently updated to Approved
- Approval notification is logged in employee's notification history
- Email notification is sent to employee's registered email
- Audit trail records the approval action with timestamp and approver details

---

### Test Case: Ensure notifications are delivered within 5 minutes
- **ID:** tc-003
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- User is logged in as an employee with valid credentials
- System clock is synchronized and accurate
- Notification service is running and monitoring is enabled
- Email service has no delivery delays
- Test environment has timestamp logging enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Record the current system timestamp before triggering the notification event | Timestamp is recorded accurately (T0) |
| 2 | Submit a schedule change request as an employee | Request is submitted successfully and submission timestamp is recorded (T1) |
| 3 | Monitor the email inbox for the submission confirmation notification | Email notification is received |
| 4 | Record the timestamp when the email notification is received (T2) | Email receipt timestamp is captured |
| 5 | Calculate the time difference between submission (T1) and email receipt (T2) | Time difference is 5 minutes or less |
| 6 | Check the in-app notification center for the notification | In-app notification is visible in the notification center |
| 7 | Verify the notification timestamp in the system logs | System log shows notification was generated and sent within 5 minutes of the triggering event |
| 8 | Trigger an approval decision notification by having an approver approve the request | Approval action is completed and timestamp is recorded (T3) |
| 9 | Monitor for the approval notification delivery and record receipt time (T4) | Approval notification is received within 5 minutes (T4 - T3 ≤ 5 minutes) |

**Postconditions:**
- All notifications are delivered within the 5-minute SLA
- Notification delivery times are logged for performance monitoring
- No notifications are pending or delayed in the queue

---

## Story: As Auditor, I want to access the audit trail of schedule change approvals to ensure compliance and traceability
**Story ID:** story-27

### Test Case: Verify auditor can view and filter audit trail records
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User has valid auditor credentials and role assigned
- Audit trail database contains historical approval records
- At least 10 schedule change approval records exist with different dates and users
- Audit trail page is accessible and functional
- Export functionality is enabled and configured

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the audit portal login page | Login page is displayed with username and password fields |
| 2 | Enter valid auditor credentials and click Login | Authentication is successful and auditor dashboard is displayed |
| 3 | Navigate to the schedule change approval audit trail page from the main menu | Audit trail viewer page loads successfully displaying all audit records in chronological order |
| 4 | Verify the audit trail displays key information columns: timestamp, user ID, action type, request ID, and comments | All columns are visible and populated with data for each audit record |
| 5 | Locate the filter panel and select a specific date range (e.g., last 30 days) | Date range filter is applied and only records within the selected range are displayed |
| 6 | Apply an additional filter by selecting a specific user from the user dropdown | Audit records are further filtered to show only actions performed by the selected user within the date range |
| 7 | Verify the filtered results match the applied criteria | All displayed records fall within the selected date range and are associated with the selected user |
| 8 | Click the Export as CSV button | CSV file download is initiated |
| 9 | Open the downloaded CSV file | CSV file contains all filtered audit records with correct data in proper format including all columns: timestamp, user ID, action, request ID, comments |
| 10 | Verify the CSV data matches the on-screen filtered results | All records in CSV match exactly with the filtered records displayed in the audit trail viewer |

**Postconditions:**
- Audit trail remains unchanged and intact
- Filter selections can be cleared to view all records again
- CSV export is saved successfully to local system
- Audit access is logged in security logs

---

### Test Case: Ensure access restriction to audit trail for unauthorized users
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Test user account exists with non-auditor role (e.g., employee or manager)
- User does not have auditor permissions assigned
- Access control and authorization mechanisms are properly configured
- Audit trail page URL is known
- Security logging is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page | Login page is displayed |
| 2 | Login using credentials of a non-auditor user (employee or manager role) | User is successfully authenticated and redirected to their role-appropriate dashboard |
| 3 | Verify that the audit trail menu option is not visible in the navigation menu | Audit trail link is not displayed in the user's navigation menu |
| 4 | Attempt to directly access the audit trail page by entering the URL in the browser | Access is denied and an appropriate error message is displayed: 'Access Denied - You do not have permission to view this page' or HTTP 403 Forbidden |
| 5 | Verify the user is redirected to an error page or their dashboard | User is redirected away from the audit trail page to either an access denied page or their home dashboard |
| 6 | Check the security logs for the unauthorized access attempt | Security log contains an entry recording the unauthorized access attempt with user ID, timestamp, and attempted resource |
| 7 | Attempt to access audit trail API endpoint directly using API testing tool with non-auditor credentials | API returns HTTP 403 Forbidden status code with error message indicating insufficient permissions |

**Postconditions:**
- Non-auditor user remains unable to access audit trail
- No audit data is exposed to unauthorized user
- Security event is logged for compliance tracking
- User session remains active for their authorized functions

---

### Test Case: Validate immutability of audit trail data
- **ID:** tc-006
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- User is logged in as auditor with full audit trail access
- Existing audit records are present in the database
- API testing tool is available and configured
- Database access logs are enabled
- Security monitoring is active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Login as auditor and navigate to the audit trail page | Audit trail viewer is displayed with existing records |
| 2 | Select a specific audit log entry and look for edit or delete options in the UI | No edit, delete, or modify buttons are available for any audit record |
| 3 | Right-click on an audit record to check for context menu options | Context menu does not contain any options to modify or delete the record |
| 4 | Attempt to modify an audit record by inspecting the page elements and trying to enable edit mode | No edit functionality is available through UI manipulation |
| 5 | Using API testing tool, send a PUT request to modify an existing audit log entry via the API endpoint | API returns HTTP 405 Method Not Allowed or HTTP 403 Forbidden with error message indicating audit logs cannot be modified |
| 6 | Using API testing tool, send a DELETE request to remove an audit log entry via the API endpoint | API returns HTTP 405 Method Not Allowed or HTTP 403 Forbidden with error message indicating audit logs cannot be deleted |
| 7 | Check the security logs for the modification attempts | Security log contains entries for both modification attempts with timestamps, user ID, and attempted actions flagged as security events |
| 8 | Verify the original audit record remains unchanged in the audit trail viewer | Audit record displays with original data intact, no modifications are reflected |
| 9 | Check database logs to confirm no write operations were executed on audit trail tables | Database logs show no UPDATE or DELETE operations on audit trail records, only SELECT operations are logged |

**Postconditions:**
- All audit trail records remain unchanged and intact
- Modification attempts are logged as security events
- Audit trail integrity is maintained
- Security team is alerted to unauthorized modification attempts
- Database audit logs confirm no data tampering occurred

---

## Story: As Approver, I want to receive notifications for pending schedule change requests to ensure timely action
**Story ID:** story-28

### Test Case: Verify notification sent to approver upon assignment
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Approver account is active and configured in the system
- Approver has valid email address registered
- NotificationService is running and operational
- User with permission to submit schedule change requests is logged in
- Approval workflow is properly configured with assignment rules

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as a user with schedule change request submission permissions | User successfully logs in and accesses the schedule change request form |
| 2 | Fill out the schedule change request form with valid data (employee name, current schedule, requested schedule, reason, effective date) | Form accepts all input data without validation errors |
| 3 | Submit the schedule change request | System displays success message confirming request submission and assigns request to designated approver |
| 4 | Check the approver's email inbox | Email notification is received containing the schedule change request details, request ID, and submission timestamp |
| 5 | Log in as the assigned approver and navigate to the in-app notifications section | In-app notification is visible in the notification center with unread status indicator |
| 6 | Click on the in-app notification to view details | Notification displays complete request summary including requester name, schedule details, submission date, deadline, and a direct link to the approval interface |
| 7 | Click the direct link within the notification | System navigates directly to the approval interface showing the full schedule change request details ready for review |

**Postconditions:**
- Notification is marked as read in the approver's notification history
- Schedule change request remains in pending status awaiting approval decision
- Notification record is logged in the system database
- Approver has accessed the request details through the notification link

---

### Test Case: Ensure notifications are delivered within 5 minutes
- **ID:** tc-002
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- System clock is synchronized and accurate
- NotificationService is operational with no delays
- Approver account is active with valid email and in-app notification settings enabled
- Network connectivity is stable
- Email server is operational and accessible
- Timer or stopwatch is available to measure delivery time

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Note the current system timestamp before triggering the notification event | Baseline timestamp is recorded for comparison (e.g., 10:00:00 AM) |
| 2 | Submit a schedule change request that triggers automatic assignment to an approver | System confirms request submission and displays assignment confirmation with timestamp |
| 3 | Start timer immediately after request submission confirmation | Timer begins counting from zero |
| 4 | Monitor the approver's email inbox for incoming notification | Email notification arrives in the inbox |
| 5 | Record the email received timestamp and calculate time difference from submission | Time difference between submission and email receipt is 5 minutes or less |
| 6 | Log in as the approver and check the in-app notification center | In-app notification is present in the notification list |
| 7 | Verify the in-app notification timestamp and calculate time difference from submission | Time difference between submission and in-app notification creation is 5 minutes or less |
| 8 | Stop the timer and document the total delivery time for both notification channels | Both email and in-app notifications were delivered within the 5-minute performance requirement |

**Postconditions:**
- Notification delivery time is documented and meets performance criteria
- Both email and in-app notifications are successfully delivered
- Notification timestamps are recorded in system logs
- Performance metric data is available for reporting

---

### Test Case: Validate notification access and privacy
- **ID:** tc-003
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Multiple user accounts exist in the system with different roles
- At least one approver account with pending notifications exists
- At least one unauthorized user account exists (non-approver role)
- Security and authentication mechanisms are properly configured
- Authorization rules are enforced at API and UI levels
- Test user credentials are available for both authorized and unauthorized accounts

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as an authorized approver and navigate to the notification history section | Approver successfully accesses their notification history showing all notifications assigned to them |
| 2 | Note the notification ID or URL of a specific notification in the approver's history | Notification identifier is recorded for testing unauthorized access (e.g., /notifications/12345) |
| 3 | Log out from the approver account | User is successfully logged out and session is terminated |
| 4 | Log in as an unauthorized user (different role, not assigned as approver for this request) | Unauthorized user successfully logs in with their own credentials |
| 5 | Attempt to navigate directly to the approver's notification history page using the URL | System denies access and displays 'Access Denied' or '403 Forbidden' error message |
| 6 | Attempt to access the specific notification using the previously recorded notification ID or URL | System blocks access and displays error message indicating insufficient permissions |
| 7 | Attempt to make a direct API call to retrieve the approver's notifications using unauthorized credentials (e.g., GET /api/notifications) | API returns 401 Unauthorized or 403 Forbidden status code with appropriate error message |
| 8 | Verify that no notification data is exposed in the error response or browser console | Error messages do not contain sensitive notification content or approver information |
| 9 | Log out from unauthorized user account and log back in as the original approver | Approver can still access their notifications normally, confirming no data corruption occurred |

**Postconditions:**
- Unauthorized access attempts are logged in security audit logs
- Approver's notification data remains secure and private
- No sensitive information was exposed during unauthorized access attempts
- System security controls are validated as functioning correctly
- Authorized approver retains normal access to their notifications

---

