# Manual Test Cases

## Story: As Scheduler, I want to receive notifications for schedule changes to stay informed and adjust plans accordingly
**Story ID:** story-25

### Test Case: Validate notification sent on schedule change
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Scheduler role
- Scheduling system is operational and accessible
- Email, SMS, and in-app notification services are configured and active
- Test scheduler has valid email address and phone number registered
- At least one schedule entry exists in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduling module and select an existing schedule entry | Schedule entry details are displayed with edit options available |
| 2 | Update a schedule entry by modifying the date, time, or resource assignment | System saves the changes successfully and displays confirmation message |
| 3 | Verify that the system detects the change and triggers notification process | System detects the schedule change and initiates notification generation within seconds |
| 4 | Check the registered email inbox for notification | Email notification is received containing accurate schedule change details including old values, new values, timestamp, and change initiator |
| 5 | Check the registered phone for SMS notification | SMS notification is received with concise schedule change summary and reference number |
| 6 | Check the in-app notification center within the application | In-app notification appears in the notification center with complete schedule change details and acknowledge option |
| 7 | Click on the acknowledge button in the in-app notification | Notification is marked as acknowledged, acknowledgment timestamp is displayed, and notification status changes to 'Read' |
| 8 | Navigate to notification logs or audit trail section | Acknowledgment is recorded in the system logs with scheduler name, timestamp, and notification ID |

**Postconditions:**
- Schedule entry is updated with new values
- Notifications are delivered via all three channels (email, SMS, in-app)
- Acknowledgment is logged in the system
- Notification status is marked as acknowledged
- Audit trail contains complete notification delivery and acknowledgment records

---

### Test Case: Verify retry mechanism on notification failure
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- User is logged in with Scheduler role and administrative access to notification settings
- Scheduling system is operational
- Test environment allows simulation of notification delivery failures
- Access to notification logs and monitoring dashboard is available
- At least one schedule entry exists for modification

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Configure the test environment to simulate notification delivery failure for email service | Email service is set to reject or timeout notification requests |
| 2 | Update a schedule entry to trigger notification | Schedule change is saved and notification process is initiated |
| 3 | Monitor the notification delivery process in real-time | System attempts to send notification and encounters delivery failure |
| 4 | Observe the retry mechanism activation | System automatically initiates first retry attempt after initial failure |
| 5 | Continue monitoring for subsequent retry attempts | System performs second and third retry attempts with appropriate intervals between retries |
| 6 | Access notification logs from the system dashboard | Notification logs display all retry attempts (initial attempt plus 3 retries) with individual timestamps and failure reasons |
| 7 | Restore email service to normal operation | Email service is now accepting notification requests |
| 8 | Verify if notification is delivered after service restoration during retry window | Notification is successfully delivered on one of the retry attempts, or final failure is logged if all retries exhausted |
| 9 | Review final notification status in logs | System logs show either successful delivery with retry count or permanent failure status after 3 retry attempts |

**Postconditions:**
- All retry attempts are logged with timestamps and status
- Notification is either successfully delivered or marked as permanently failed
- System maintains data integrity despite delivery failures
- Email service is restored to normal operation
- Audit trail contains complete retry history

---

### Test Case: Ensure notifications are sent within SLA
- **ID:** tc-003
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 20 mins

**Preconditions:**
- User is logged in with Scheduler role
- Scheduling system is fully operational with normal load
- All notification channels (email, SMS, in-app) are active and responsive
- System clock is synchronized and accurate
- Access to system logs and performance monitoring tools is available
- Multiple schedule entries exist for testing

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Record the current system timestamp as test start time | Baseline timestamp is captured for SLA measurement |
| 2 | Update the first schedule entry and record the exact modification timestamp | First schedule change is saved with timestamp T1 recorded |
| 3 | Update the second schedule entry and record the exact modification timestamp | Second schedule change is saved with timestamp T2 recorded |
| 4 | Update the third schedule entry and record the exact modification timestamp | Third schedule change is saved with timestamp T3 recorded |
| 5 | Monitor notification delivery for the first schedule change | Notification for first change is received within 5 minutes of T1 |
| 6 | Monitor notification delivery for the second schedule change | Notification for second change is received within 5 minutes of T2 |
| 7 | Monitor notification delivery for the third schedule change | Notification for third change is received within 5 minutes of T3 |
| 8 | Calculate the delivery time for each notification by comparing modification timestamp with delivery timestamp | All three notifications show delivery time of less than or equal to 5 minutes (300 seconds) |
| 9 | Access system logs and filter for the test period | System logs display all notification events with timestamps |
| 10 | Review logs for any delays, errors, or warnings during the notification delivery process | No delays beyond 5-minute SLA are recorded, no critical errors are logged, and all notifications show successful delivery status |
| 11 | Generate performance report for the notification delivery times | Report confirms 100% compliance with 5-minute SLA for all tested notifications |

**Postconditions:**
- All schedule changes are successfully saved
- All notifications are delivered within the 5-minute SLA
- System logs contain complete delivery timeline for each notification
- No performance degradation or errors are recorded
- SLA compliance is documented and verified

---

## Story: As Scheduler, I want to customize notification channels for schedule changes to receive alerts via my preferred method
**Story ID:** story-28

### Test Case: Validate saving and updating notification preferences
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in with Scheduler role
- User has existing notification preferences configured in the system
- Notification preferences UI is accessible from user settings
- User has valid email address and phone number registered
- All notification channels (email, SMS, in-app) are operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to user settings or profile section | User settings page is displayed with navigation options |
| 2 | Click on notification preferences or notification settings option | Notification preferences UI is displayed showing current preferences with checkboxes or toggles for email, SMS, and in-app notifications |
| 3 | Review the currently selected notification channels | Current preferences are clearly indicated with checked boxes or enabled toggles matching the saved preferences |
| 4 | Deselect one currently enabled channel (e.g., uncheck email notification) | Checkbox or toggle changes state to indicate deselection |
| 5 | Select a previously disabled channel (e.g., enable SMS notification) | Checkbox or toggle changes state to indicate selection |
| 6 | Click the Save or Update button to save the new preferences | System displays success message confirming preferences have been saved, and UI reflects the updated selections |
| 7 | Navigate away from the preferences page and return to verify persistence | Updated preferences are still displayed correctly, confirming they were saved to the database |
| 8 | Trigger a notification event by updating a schedule entry | Schedule change is saved and notification process is initiated |
| 9 | Check only the selected notification channels for notification delivery | Notification is received only via the newly selected channels (SMS and in-app), and NOT via the deselected channel (email) |
| 10 | Verify the deselected channel did not receive notification | Email inbox shows no new notification for the schedule change, confirming preference is respected |

**Postconditions:**
- Notification preferences are updated and saved in the database
- Notifications are delivered only via selected channels
- Preference changes are logged in the system audit trail
- User interface reflects current saved preferences
- No notifications are sent to deselected channels

---

### Test Case: Verify validation of invalid channel inputs
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Scheduler role
- Notification preferences UI is accessible
- Email and SMS channels require contact information input
- System has validation rules for email format and phone number format
- User has permission to modify notification preferences

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to notification preferences UI | Notification preferences page is displayed with input fields for email and phone number |
| 2 | Enable email notification channel and enter an invalid email address (e.g., 'invalidemail.com' without @ symbol) | Email input field accepts the text entry |
| 3 | Click Save or move focus away from the email field to trigger validation | System displays validation error message indicating invalid email format (e.g., 'Please enter a valid email address') |
| 4 | Verify that preferences are not saved with invalid email | Save operation is blocked and error message remains visible, preferences remain unchanged |
| 5 | Enable SMS notification channel and enter an invalid phone number (e.g., '123' or 'abcd1234') | Phone number input field accepts the text entry |
| 6 | Click Save or move focus away from the phone field to trigger validation | System displays validation error message indicating invalid phone number format (e.g., 'Please enter a valid phone number') |
| 7 | Verify that preferences are not saved with invalid phone number | Save operation is blocked and error message remains visible, preferences remain unchanged |
| 8 | Correct the email address to a valid format (e.g., 'scheduler@example.com') | Email validation error clears and field shows valid state indicator |
| 9 | Correct the phone number to a valid format (e.g., '+1234567890' or '(123) 456-7890') | Phone number validation error clears and field shows valid state indicator |
| 10 | Click Save button with all valid inputs | System accepts the inputs, saves preferences successfully, and displays confirmation message |
| 11 | Verify that the corrected contact information is saved | Preferences page shows the updated valid email and phone number, confirming successful save |

**Postconditions:**
- Invalid inputs are rejected and not saved to the database
- Valid inputs are accepted and saved successfully
- User receives clear validation error messages for invalid inputs
- System maintains data integrity by preventing invalid contact information
- Validation events are logged in the system

---

### Test Case: Ensure immediate effect of preference changes
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role
- User has existing notification preferences configured
- Notification preferences UI is accessible
- All notification channels are operational and ready to deliver
- At least one schedule entry exists for triggering notifications
- System is configured for real-time preference updates

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to notification preferences UI | Notification preferences page is displayed with current settings visible |
| 2 | Note the currently enabled notification channels (e.g., email and in-app are enabled, SMS is disabled) | Current preference state is clearly visible and documented |
| 3 | Change notification preferences by disabling email and enabling SMS | UI reflects the selection changes with email unchecked and SMS checked |
| 4 | Click Save button to update preferences | System displays success message confirming preferences are saved immediately without delay |
| 5 | Record the exact timestamp when preferences were saved | Timestamp is captured for verification of immediate effect |
| 6 | Immediately navigate to the scheduling module without logging out or waiting | Scheduling module is displayed and ready for interaction |
| 7 | Trigger a notification event by updating a schedule entry within seconds of saving preferences | Schedule change is saved successfully and notification process is initiated |
| 8 | Monitor notification delivery across all channels | Notification delivery process begins immediately after schedule change |
| 9 | Check SMS channel for notification delivery | SMS notification is received with schedule change details, confirming newly enabled preference is active |
| 10 | Check in-app notification center | In-app notification is received, confirming this channel remains active as per updated preferences |
| 11 | Check email inbox to verify no notification was sent | No email notification is received, confirming the disabled preference took immediate effect |
| 12 | Review notification delivery logs | Logs show notification was sent only to SMS and in-app channels, with no attempt to send email, confirming immediate application of updated preferences |

**Postconditions:**
- Notification preferences are updated and active immediately
- Notifications are sent according to the updated preferences without delay
- No caching or delay affects preference application
- System logs reflect the preference change timestamp and subsequent notification delivery channels
- User experience confirms real-time preference updates

---

## Story: As Scheduler, I want to view notification history for schedule changes to track past alerts and responses
**Story ID:** story-31

### Test Case: Validate access to notification history
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User has valid scheduler credentials
- Notification history database contains test data with at least 50 notification records
- Test notifications include various types: schedule changes, acknowledgments, and alerts
- Export functionality is enabled in the system
- User has appropriate permissions to access notification history

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page and enter valid scheduler credentials | User is successfully authenticated and redirected to the scheduler dashboard |
| 2 | Locate and click on the 'Notification History' menu item or navigation link | Notification history page loads and displays a list of past notifications with columns for date/time, notification type, content preview, and acknowledgment status |
| 3 | Verify that notification records are displayed with all required fields: timestamp, notification content, acknowledgment status, and recipient information | All notification records show complete information in a structured table or list format with proper formatting |
| 4 | Click on the filter dropdown and select 'Acknowledged' status filter | The notification list refreshes and displays only notifications with 'Acknowledged' status |
| 5 | Clear the status filter and enter a search term in the search box (e.g., specific date or keyword from notification content) | Search results are displayed showing only notifications matching the search criteria, with matching text highlighted |
| 6 | Apply multiple filters simultaneously (e.g., date range filter and notification type filter) | Filtered results display notifications that match all applied filter criteria |
| 7 | Click on the 'Export' button and select export format (CSV or PDF) | Export dialog appears with format options and confirmation button |
| 8 | Confirm the export action and wait for file generation | File downloads successfully to the default download location |
| 9 | Open the exported file and verify its contents | Exported file contains all visible notification records with correct data matching the displayed information, including all columns and proper formatting |

**Postconditions:**
- User remains logged in to the system
- Notification history page remains accessible
- Exported file is saved in the download folder
- No data modifications have occurred in the notification history database
- Applied filters can be cleared to return to full list view

---

### Test Case: Verify access control enforcement
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Test environment has multiple user roles configured (scheduler, non-scheduler, guest)
- Unauthorized test user account exists without scheduler privileges
- Authorized scheduler user account exists with proper permissions
- Role-based access control (RBAC) is enabled in the system
- Notification history endpoint requires authentication and authorization

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page and enter credentials for an unauthorized user (non-scheduler role) | User is successfully authenticated and redirected to their appropriate dashboard based on role |
| 2 | Attempt to access the notification history page by entering the URL directly or clicking on the navigation link if visible | Access is denied and an appropriate error message is displayed: 'Access Denied: You do not have permission to view notification history' or similar message |
| 3 | Verify that the user is redirected to an error page or their default dashboard | User is redirected away from the notification history page and no notification data is visible |
| 4 | Attempt to access the notification history API endpoint directly using browser developer tools or API client | API returns 403 Forbidden status code with error message indicating insufficient permissions |
| 5 | Log out from the unauthorized user account | User is successfully logged out and redirected to the login page |
| 6 | Log in with valid scheduler credentials that have proper authorization | Scheduler user is successfully authenticated and redirected to the scheduler dashboard |
| 7 | Navigate to the notification history page using the navigation menu | Access is granted and the notification history page loads successfully displaying notification records |
| 8 | Verify that all notification history features are accessible (filters, search, export) | All functionality is available and operational for the authorized scheduler user |

**Postconditions:**
- Unauthorized user access attempt is logged in security audit logs
- Authorized scheduler user has full access to notification history
- No unauthorized data exposure has occurred
- System security controls remain intact
- Access control rules are enforced consistently

---

### Test Case: Ensure performance of notification history queries
- **ID:** tc-003
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Notification history database contains at least 10,000 notification records for performance testing
- User has valid scheduler credentials with access to notification history
- System performance monitoring tools are available to measure response times
- Pagination is configured with default page size (e.g., 50 records per page)
- Network conditions are stable for accurate performance measurement

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as a scheduler user and navigate to the notification history page | User is authenticated and redirected to the scheduler dashboard |
| 2 | Open browser developer tools and navigate to the Network tab to monitor API requests | Network monitoring is active and ready to capture request/response times |
| 3 | Click on the 'Notification History' link to load the notification history page with large dataset | Notification history page loads and displays the first page of results |
| 4 | Measure the API response time for the GET /notifications/history request in the Network tab | Response time is under 2 seconds, and the first page of paginated results (50 records) is displayed correctly |
| 5 | Verify that pagination controls are displayed showing total pages and current page number | Pagination controls show correct total count and page navigation options (Next, Previous, Page numbers) |
| 6 | Click on the 'Next' button to navigate to page 2 of the notification history | Page 2 loads within 2 seconds showing the next set of notification records |
| 7 | Measure the response time for the page 2 request in the Network tab | Response time remains under 2 seconds with no errors or timeouts |
| 8 | Navigate to a middle page (e.g., page 50) by entering the page number or clicking multiple times | Target page loads successfully within 2 seconds displaying correct notification records |
| 9 | Navigate to the last page of results using the pagination controls | Last page loads within 2 seconds showing the remaining notification records |
| 10 | Apply a filter to the large dataset and measure the query response time | Filtered results are returned within 2 seconds with pagination applied to filtered data |
| 11 | Perform a search query on the large dataset and measure response time | Search results are displayed within 2 seconds with matching records highlighted |
| 12 | Verify that no errors, timeouts, or performance degradation occurred during navigation | All page loads completed successfully without errors, and UI remains responsive throughout testing |

**Postconditions:**
- All performance metrics are documented and meet the 2-second requirement
- Pagination functionality works correctly across all pages
- Database queries are optimized and indexed properly
- No memory leaks or performance degradation observed
- User remains logged in and notification history page is still accessible

---

