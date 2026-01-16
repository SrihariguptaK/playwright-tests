# Manual Test Cases

## Story: As Underwriting Specialist, I want to receive automatic referral flags to achieve timely review of complex applications
**Story ID:** story-21

### Test Case: Validate automatic referral flagging on application submission
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User has valid credentials to submit applications
- Underwriting rules engine is operational and accessible
- Underwriting specialist dashboard is accessible
- Test application data meets at least one referral criteria
- Database is accessible for logging referral decisions

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the application submission portal with valid credentials | User is successfully authenticated and redirected to application submission page |
| 2 | Fill out application form with data that meets referral criteria (e.g., high risk occupation, elevated coverage amount, or adverse medical history) | All required fields are populated with valid data meeting referral triggers |
| 3 | Submit the application by clicking the Submit button | Application is submitted successfully and confirmation message is displayed |
| 4 | Verify system sends application data to underwriting rules engine via POST /api/underwriting/evaluate endpoint | API call is made successfully and rules engine returns referral flag response within 2 seconds |
| 5 | Log into the underwriting specialist dashboard with specialist credentials | Specialist is authenticated and dashboard loads successfully |
| 6 | Navigate to the referrals section or filter applications by referral status | Submitted application is displayed in the dashboard with visible referral flag indicator |
| 7 | Access the referral log database or audit trail for the submitted application | Referral decision entry exists with accurate timestamp, rule reference, and application ID |
| 8 | Verify the timestamp of the referral flag is within 2 seconds of application submission time | Timestamp difference between submission and referral flagging is 2 seconds or less |

**Postconditions:**
- Application status is updated to 'Referral Flagged' in the system
- Referral log entry is permanently stored in the database
- Application remains visible in specialist dashboard until processed
- System is ready to accept new application submissions

---

### Test Case: Verify notification alert for new referrals
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Underwriting specialist account is active and configured to receive notifications
- Notification service is operational
- Application submission system is functional
- Test application data triggers referral criteria
- Specialist has permissions to clear referral flags

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Ensure underwriting specialist is logged into the system or has notification preferences configured | Specialist account is active and notification settings are enabled |
| 2 | Submit a new application with data that triggers referral criteria (e.g., coverage amount exceeding threshold) | Application is submitted successfully and processed by underwriting rules engine |
| 3 | Check notification delivery mechanism (email, in-app notification, or dashboard alert) | Notification alert is sent to the underwriting specialist within 2 seconds of referral flagging |
| 4 | Verify notification content includes application ID, referral reason summary, and timestamp | Notification contains all required information for specialist to identify the referral |
| 5 | Log into underwriting specialist dashboard | Dashboard loads successfully and displays active referrals section |
| 6 | Locate the referral flagged application in the dashboard | Application is visible with referral flag indicator and matches the notification details |
| 7 | Click on the referral flagged application to view details | Application details page opens showing referral status and relevant information |
| 8 | Clear the referral flag by clicking the Clear or Process button | System prompts for confirmation of flag clearance action |
| 9 | Confirm the clearance action | Referral flag status is updated to 'Cleared' or 'Processed' in the system |
| 10 | Verify notification is cleared or marked as resolved in the notification center | Notification status is updated and no longer appears in active alerts |
| 11 | Refresh the dashboard and verify the application no longer appears in active referrals | Application is removed from active referrals list or moved to processed referrals section |

**Postconditions:**
- Referral flag is cleared and status is updated in the database
- Notification is marked as resolved
- Application is moved to processed referrals or appropriate status
- Audit log records the clearance action with specialist ID and timestamp
- System is ready to process new referrals

---

## Story: As Underwriting Specialist, I want to view detailed referral reasons to achieve better understanding of flagged applications
**Story ID:** story-22

### Test Case: Verify referral reason details display
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- At least one application has been flagged for referral with documented reasons
- Underwriting specialist account with proper authorization exists
- Unauthorized user account exists for negative testing
- Referral logs and rules engine metadata are accessible
- GET /api/referrals/{id}/details endpoint is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system as an authorized underwriting specialist | Specialist is successfully authenticated and has access to underwriting dashboard |
| 2 | Navigate to the referrals section of the dashboard | List of referral flagged applications is displayed |
| 3 | Select a referral flagged application from the list by clicking on it | Application details page loads successfully |
| 4 | Locate and view the referral reasons section on the application details page | Referral reason codes and detailed descriptions are displayed clearly |
| 5 | Verify each referral reason includes the specific underwriting rule code that triggered it | Rule codes are displayed alongside each referral reason (e.g., RULE-001, RULE-045) |
| 6 | Click on a rule code link to view the complete rule details | System displays the full underwriting rule definition, criteria, and thresholds |
| 7 | Measure the time taken from clicking the application to displaying referral details | Referral detail retrieval completes within 1 second |
| 8 | Verify API call to GET /api/referrals/{id}/details returns response within performance threshold | API response time is 1 second or less with status code 200 |
| 9 | Log out from the specialist account | User is successfully logged out and session is terminated |
| 10 | Log into the system with an unauthorized user account (non-specialist role) | User is authenticated but does not have specialist privileges |
| 11 | Attempt to access the referral flagged application details directly via URL or navigation | Access denied error message is displayed (HTTP 403 Forbidden or equivalent) |
| 12 | Attempt to call GET /api/referrals/{id}/details API endpoint with unauthorized credentials | API returns 403 Forbidden status with appropriate error message |
| 13 | Log out from unauthorized account and log back in as authorized specialist | Specialist is authenticated and has full access restored |
| 14 | Navigate back to the referral flagged application details page | Application details with referral reasons are displayed |
| 15 | Locate and access the referral history section | Complete referral history is displayed in chronological order |
| 16 | Verify each history entry includes timestamp, rule triggered, and status change | All history entries show accurate timestamps in format (YYYY-MM-DD HH:MM:SS), rule codes, and status transitions |
| 17 | Verify the initial referral flagging timestamp matches the application submission processing time | Timestamps are consistent and show referral was flagged within 2 seconds of submission |
| 18 | Check if any subsequent changes to referral status are logged with specialist ID | All status changes include the specialist who made the change and accurate timestamp |

**Postconditions:**
- Referral details remain accessible for authorized specialists
- Unauthorized users continue to be blocked from accessing referral information
- Referral history is preserved and audit trail is intact
- No data modifications occurred during read-only operations
- System performance metrics are logged for monitoring

---

## Story: As System Administrator, I want to monitor the integration health with the underwriting rules engine to achieve system reliability and quick issue resolution
**Story ID:** story-27

### Test Case: Validate integration health monitoring and alerts
- **ID:** tc-027-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- User is logged in with System Administrator role
- Integration monitoring dashboard is accessible
- Underwriting rules engine integration is active
- Alert notification system is configured and operational
- Test environment allows simulation of integration failures
- Historical performance data exists for at least 24 hours

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the integration monitoring dashboard by accessing the admin panel and selecting 'Integration Monitoring' option | Integration monitoring dashboard loads successfully and displays the main interface |
| 2 | Verify the current status section displays real-time integration status with the underwriting rules engine | Current status is displayed showing 'Active' or 'Connected' state with timestamp of last update (within 30 seconds) |
| 3 | Review the logs section on the dashboard for recent integration activities | Recent logs are displayed showing API calls, response times, and any errors with timestamps and details |
| 4 | Check the latency metrics displayed on the dashboard | Latency metrics are visible showing average response times, min/max values, and trend graphs |
| 5 | Simulate an integration failure by triggering a test failure scenario or temporarily disconnecting the rules engine connection | Integration status changes to 'Failed' or 'Disconnected' state immediately |
| 6 | Verify that the error is logged in the dashboard logs section | Error entry appears in logs with timestamp, error type, error message, and failure details |
| 7 | Check for alert notification delivery to administrator | Alert notification is sent within 5 minutes via configured channels (email, system notification) containing error details and timestamp |
| 8 | Acknowledge the alert notification from the notification panel | Alert status updates to 'Acknowledged' with administrator name and timestamp |
| 9 | Restore the integration connection to normal state | Integration status returns to 'Active' or 'Connected' and recovery is logged |
| 10 | Navigate to the historical performance reports section of the dashboard | Historical performance reports interface is displayed with date range selector and report options |
| 11 | Select a date range covering the simulated failure period and generate the performance report | Report is generated showing uptime percentage, number of failures, average latency, error count, and timeline graph accurately reflecting the simulated failure |
| 12 | Verify the report includes the simulated failure event with correct timestamp and duration | Failure event is accurately recorded in the report with exact start time, end time, duration, and error details |

**Postconditions:**
- Integration status is restored to normal 'Active' state
- All simulated failures are logged in system history
- Alert notifications have been sent and acknowledged
- Historical report accurately reflects the test activities
- No residual errors remain in the system
- Dashboard displays current accurate status

---

## Story: As Underwriting Specialist, I want to receive notifications for updated referrals and questions to achieve timely follow-up and decision-making
**Story ID:** story-28

### Test Case: Verify notification delivery for referral updates
- **ID:** tc-028-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Underwriting Specialist role
- At least one referral exists in the system assigned to the logged-in specialist
- Notification preferences are configured for the specialist (email and system alerts enabled)
- Notification system is operational and connected
- Email service is configured and functional
- Specialist has valid email address in their profile

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the referrals list and select an existing referral assigned to the current specialist | Referral details page opens displaying current status and information |
| 2 | Note the current referral status and timestamp before making changes | Current status is clearly visible (e.g., 'Pending Review', 'In Progress') with last updated timestamp |
| 3 | Update the referral status to a different state (e.g., from 'Pending Review' to 'Under Investigation') | Status update is saved successfully and confirmation message is displayed |
| 4 | Verify that a notification is generated immediately after the status update | System generates notification event within 1 second as indicated by system logs or notification queue |
| 5 | Check the system notification panel or bell icon in the application header | New notification appears in the notification panel showing referral ID, updated status, and timestamp within 1 second of the update |
| 6 | Verify the notification content includes relevant details about the referral update | Notification displays referral reference number, previous status, new status, who made the change, and timestamp |
| 7 | Check the specialist's email inbox for the notification email | Email notification is received within 1 second containing the same referral update information with actionable link to the referral |
| 8 | Click on the notification in the system notification panel | Notification is marked as read and the system navigates to the updated referral details page |
| 9 | Verify the notification is visible and actionable by checking available actions | Notification shows options to 'View Referral', 'Acknowledge', or 'Dismiss' and all actions are clickable |
| 10 | Click the 'Acknowledge' button on the notification | Notification status updates to 'Acknowledged' with timestamp and specialist name recorded |
| 11 | Navigate to the notification history section from the user profile or settings menu | Notification history page opens displaying all past notifications in chronological order |
| 12 | Search for the acknowledged notification using the referral ID or date filter | Acknowledged notification appears in search results showing status as 'Acknowledged', acknowledgment timestamp, and full notification details |
| 13 | Verify the notification history shows the complete audit trail | History displays notification sent time, delivery status, read time, and acknowledgment time with all timestamps accurate |

**Postconditions:**
- Referral status is updated to the new state
- Notification is successfully delivered via both system alert and email
- Notification is acknowledged and recorded in history
- Notification status shows as 'Acknowledged' in the system
- Notification history contains complete audit trail of the notification
- Specialist can access the updated referral from notification link

---

