# Manual Test Cases

## Story: As Scheduler, I want to receive in-app alerts for scheduling conflicts to act immediately
**Story ID:** story-13

### Test Case: Verify in-app alert displays upon scheduling conflict
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- User is logged in as a Scheduler
- Application is open and active
- At least one existing booking is present in the system
- Conflict detection engine is operational
- WebSocket or push notification service is connected

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Scheduler creates a new booking that conflicts with an existing booking (same resource, overlapping time) | In-app alert is displayed immediately on the screen with conflict notification |
| 2 | Scheduler reviews the alert details displayed in the notification | Alert shows accurate conflict information including conflicting booking IDs, resource names, time slots, and affected parties |
| 3 | Scheduler clicks the acknowledge/dismiss button on the alert | Alert is removed from the interface and no longer visible on screen |

**Postconditions:**
- Alert has been dismissed from the UI
- Conflicting booking remains in the system until manually resolved
- Alert dismissal is logged in the system

---

### Test Case: Ensure alerts persist until user dismissal or conflict resolution
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- User is logged in as a Scheduler
- Application is open and active
- A scheduling conflict exists in the system
- In-app alert for the conflict has been triggered

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Scheduler receives alert for an unresolved conflict and observes the alert on screen | Alert remains visible and prominently displayed in the application interface |
| 2 | Scheduler navigates to different pages within the application without taking action on the alert | Alert persists on screen across different pages and remains visible until action is taken |
| 3 | Scheduler clicks the dismiss button on the alert | Alert is removed from the screen and no longer displayed |

**Postconditions:**
- Alert is no longer visible in the UI
- Underlying conflict still exists in the system
- User dismissal action is recorded

---

### Test Case: Test alert delivery latency under 1 second
- **ID:** tc-003
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as a Scheduler
- Application is open and active
- System performance monitoring tools are available
- Conflict detection engine is operational
- Timer or timestamp logging is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Record the exact timestamp when a scheduling conflict is created (e.g., by creating overlapping booking) | Conflict detection event is triggered and timestamp is captured |
| 2 | Observe when the in-app alert appears on the screen and record the timestamp | Alert appears in the application interface and display timestamp is captured |
| 3 | Calculate the time difference between conflict creation and alert display | Time difference is less than 1 second, meeting the performance requirement |

**Postconditions:**
- Alert delivery latency is measured and documented
- Performance metrics are logged
- Alert is displayed on screen

---

## Story: As Scheduler, I want to receive email notifications for scheduling conflicts to stay informed when away from the app
**Story ID:** story-14

### Test Case: Verify email notification is sent upon scheduling conflict
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is registered as a Scheduler with a valid email address
- Email notification service (SMTP) is configured and operational
- Conflict detection engine is active
- Email notification preferences are enabled for the user
- Test email inbox is accessible for verification

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create a scheduling conflict by booking a resource that overlaps with an existing booking | Conflict detection event is triggered and email notification generation process begins |
| 2 | Wait up to 5 minutes and check the scheduler's email inbox for the notification | Email with conflict details is received in the inbox, containing subject line indicating scheduling conflict |
| 3 | Open the email and review its content | Email contains detailed conflict information including conflicting booking IDs, resource names, time slots, affected parties, and actionable links |

**Postconditions:**
- Email notification has been successfully delivered
- Email content is accurate and complete
- Delivery is logged in the email service

---

### Test Case: Test user preference configuration for email notifications
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as a Scheduler
- User settings or preferences page is accessible
- Email notification feature is available in user preferences
- Default notification preferences are set

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to user settings/preferences page and locate email notification settings | Email notification preferences section is displayed with toggle or checkbox options |
| 2 | Update email notification preferences (e.g., enable or disable conflict notifications) and save changes | Preferences are saved successfully with confirmation message displayed |
| 3 | Trigger a scheduling conflict event in the system | Email is sent or suppressed according to the saved preferences (email received if enabled, not received if disabled) |
| 4 | Verify email inbox matches the configured preference setting | Email delivery behavior matches the user's preference configuration |

**Postconditions:**
- User preferences are persisted in the system
- Email notification behavior reflects updated preferences
- Preference changes are logged

---

### Test Case: Ensure email delivery success rate is above 99%
- **ID:** tc-006
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Email service is configured and operational
- Test environment has access to email delivery monitoring tools
- Multiple valid test email addresses are available (minimum 100)
- Conflict detection can be triggered programmatically or in batch
- Email delivery tracking and logging is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Prepare a batch of at least 100 scheduling conflicts that will trigger email notifications to different valid email addresses | Batch of conflict events is ready for execution with corresponding recipient email addresses |
| 2 | Trigger all conflict events and initiate email notification sending process | Email service processes all notification requests and attempts delivery to all recipients |
| 3 | Monitor email delivery status using email service logs or delivery reports for all sent emails | Delivery status is tracked for each email (delivered, bounced, failed) |
| 4 | Calculate the delivery success rate by dividing successfully delivered emails by total emails sent | At least 99% of emails are marked as successfully delivered (99 out of 100 minimum) |

**Postconditions:**
- Email delivery metrics are documented
- Success rate meets or exceeds 99% threshold
- Any failed deliveries are logged for investigation

---

## Story: As Scheduler, I want to acknowledge and dismiss conflict alerts to manage my notifications
**Story ID:** story-17

### Test Case: Verify user can acknowledge and dismiss conflict alerts
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in as a Scheduler with valid credentials
- User has permissions to manage alerts
- At least one active conflict alert exists in the system
- Alert management system is operational
- User session is authenticated

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the alerts section where conflict alerts are displayed | Alerts section loads successfully and displays all active conflict alerts |
| 2 | Verify that the conflict alert is visible in the UI with all relevant details (resource, time, severity) | Alert is displayed in UI with complete information including alert type, timestamp, and affected resources |
| 3 | Locate and click the 'Acknowledge' button on the conflict alert | Alert status changes to 'Acknowledged' with visual indicator (e.g., color change, icon update, or status label) |
| 4 | Verify the acknowledge action is reflected in the alert display | Alert shows acknowledged status and remains visible in the interface |
| 5 | Locate and click the 'Dismiss' button on the acknowledged alert | Alert is immediately removed from the UI within 1 second |
| 6 | Verify the dismissal action is logged by checking the audit log or system logs | Dismissal action is logged with user ID, timestamp, and alert ID in the system logs |
| 7 | Refresh the alerts page or navigate away and return to verify alert persistence | Dismissed alert does not reappear in the alerts list |

**Postconditions:**
- Alert is removed from the active alerts interface
- Dismissal action is logged with user and timestamp information
- Alert status is updated to 'Dismissed' in the database
- User can continue managing other alerts without interference

---

### Test Case: Ensure dismissed alerts do not reappear unless conflict persists
- **ID:** tc-002
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as a Scheduler with valid credentials
- User has permissions to manage alerts
- At least one active conflict alert exists in the system
- Alert management system is operational
- User session is authenticated

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the alerts section and identify an active conflict alert | Active conflict alert is displayed in the UI with all details |
| 2 | Acknowledge the conflict alert by clicking the 'Acknowledge' button | Alert status changes to 'Acknowledged' |
| 3 | Dismiss the alert by clicking the 'Dismiss' button | Alert is removed from the UI immediately and dismissal is logged |
| 4 | Wait for 5 seconds without making any changes to the underlying conflict | No changes occur in the system; conflict status remains unchanged |
| 5 | Refresh the alerts page or navigate away and return to the alerts section | Dismissed alert does not reappear in the alerts list |
| 6 | Verify the alert remains dismissed by checking the alerts dashboard multiple times over a 2-minute period | Alert does not reappear as long as the conflict status remains unchanged |
| 7 | Simulate a change in conflict status by resolving the underlying conflict in the system | Conflict is marked as resolved in the system |
| 8 | Recreate the same conflict condition that triggered the original alert | System detects the new conflict occurrence |
| 9 | Check the alerts dashboard for new alert generation | A new alert is generated and displayed in the UI for the reoccurring conflict |
| 10 | Verify the new alert has a different alert ID and timestamp than the previously dismissed alert | New alert has unique identifier and current timestamp, confirming it is a new alert instance |

**Postconditions:**
- Dismissed alert remains dismissed when conflict status is unchanged
- New alert is generated only when conflict reoccurs after resolution
- Alert management system correctly distinguishes between dismissed and new alerts
- System maintains data integrity for alert lifecycle management

---

## Story: As Scheduler, I want to view conflict alerts on a dashboard to monitor scheduling issues
**Story ID:** story-19

### Test Case: Verify dashboard displays active conflict alerts
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as a Scheduler with valid credentials
- User has authenticated scheduler access to the dashboard
- Multiple active conflict alerts exist in the system with varying resources, times, and severity levels
- Conflict alert database is accessible and operational
- Dashboard application is running and accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the conflict dashboard by clicking on the dashboard menu or accessing the dashboard URL | Conflict dashboard loads successfully and displays the main interface |
| 2 | Verify that all active conflict alerts are displayed on the dashboard | Dashboard shows a complete list of active conflict alerts with key information (resource name, time, severity, alert ID) |
| 3 | Check that each alert displays relevant details including resource, timestamp, and severity level | Each alert entry shows complete information in a clear, readable format |
| 4 | Locate the filter options on the dashboard (resource filter, time filter, severity filter) | Filter controls are visible and accessible on the dashboard interface |
| 5 | Apply a resource filter by selecting a specific resource from the filter dropdown | Alerts list updates immediately to show only alerts related to the selected resource |
| 6 | Clear the resource filter and apply a severity filter by selecting a specific severity level | Alerts list updates to display only alerts matching the selected severity level |
| 7 | Apply a time filter by selecting a specific time range or date | Alerts list updates to show only alerts within the specified time range |
| 8 | Apply multiple filters simultaneously (resource + severity + time) | Alerts list updates to show only alerts matching all applied filter criteria |
| 9 | Clear all filters to return to the full list of active alerts | Dashboard displays all active conflict alerts again |
| 10 | Select a specific conflict alert from the list by clicking on it | System navigates to the detailed conflict view showing comprehensive information about the selected alert |
| 11 | Verify the detailed view contains complete conflict information including affected resources, timeline, severity, and resolution options | Detailed conflict view displays all relevant information in an organized format |
| 12 | Navigate back to the dashboard from the detailed view | Dashboard reloads with the same filter settings and alert list as before |

**Postconditions:**
- Dashboard displays accurate and current conflict alert information
- Filter functionality works correctly for all filter types
- Navigation to detailed views functions properly
- User can effectively monitor and manage scheduling conflicts
- Dashboard state is maintained during navigation

---

### Test Case: Ensure dashboard data refreshes within 2 seconds
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as a Scheduler with valid credentials
- User has authenticated scheduler access to the dashboard
- Conflict dashboard is open and displaying current alerts
- System has capability to generate new conflict alerts
- Real-time data refresh mechanism is enabled
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open the conflict dashboard and note the current number of active alerts displayed | Dashboard loads with current list of active conflict alerts and count is visible |
| 2 | Prepare a timer or stopwatch to measure the refresh time | Timer is ready to measure the time between alert generation and dashboard update |
| 3 | Generate a new conflict alert in the system (through backend process, API call, or by creating a scheduling conflict) | New conflict alert is successfully created in the system and stored in the conflict alert database |
| 4 | Start the timer immediately after the new conflict alert is generated | Timer begins counting to measure refresh latency |
| 5 | Observe the dashboard without manually refreshing the page | Dashboard automatically updates to display the new conflict alert |
| 6 | Stop the timer when the new alert appears on the dashboard | Timer shows the elapsed time between alert generation and dashboard display |
| 7 | Verify that the elapsed time is 2 seconds or less | Dashboard refresh time is within the 2-second performance requirement |
| 8 | Verify the new alert displays with correct information (resource, time, severity) | New alert shows accurate and complete information matching the generated conflict |
| 9 | Check that the alert count has increased by one | Total alert count on dashboard reflects the addition of the new alert |
| 10 | Repeat the test by generating another new conflict alert and measuring refresh time again | Dashboard consistently updates within 2 seconds for the second alert as well |

**Postconditions:**
- Dashboard demonstrates real-time refresh capability within performance requirements
- New alerts are displayed accurately and promptly
- Automatic refresh mechanism functions without manual intervention
- Dashboard maintains data integrity during real-time updates
- Performance metrics meet the 2-second refresh requirement

---

