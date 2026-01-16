# Manual Test Cases

## Story: As Scheduler, I want to receive real-time alerts for scheduling conflicts to act promptly
**Story ID:** story-13

### Test Case: Verify alert delivery within 5 seconds
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Scheduler
- Alert notification system is operational
- At least one notification channel is configured for the user
- Conflict detection engine is running
- Test environment has accurate time synchronization

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create a scheduling conflict by booking the same resource for overlapping time slots | Scheduling conflict is detected by the system and logged in conflict detection engine |
| 2 | Start timer immediately after conflict is created | Timer starts recording alert delivery time |
| 3 | Monitor all configured notification channels (in-app, email, SMS) for alert delivery | Alert is received on at least one configured channel |
| 4 | Stop timer when alert is received and record the delivery time | Alert delivery time is recorded and is less than or equal to 5 seconds from conflict creation |
| 5 | Verify alert delivery confirmation in system logs | System logs show successful alert delivery with timestamp within 5 seconds |

**Postconditions:**
- Alert is successfully delivered to Scheduler
- Alert delivery time is logged in the system
- Alert appears in user's active notifications
- Conflict remains unresolved and visible in the system

---

### Test Case: Validate alert content and user acknowledgment
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in as Scheduler
- A scheduling conflict has been created and detected
- Alert has been delivered to the user
- User has access to notification interface

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open the received alert notification | Alert notification opens and displays full content |
| 2 | Review alert content for conflict details including resource name, conflicting time slots, and affected bookings | Alert contains detailed conflict information: resource identifier, date/time of conflict, booking IDs involved, and conflict type |
| 3 | Verify alert includes actionable information such as links to affected bookings | Alert provides clickable links or references to navigate to conflict details |
| 4 | Click the 'Acknowledge' button on the alert | Alert status changes to 'Acknowledged' and confirmation message is displayed |
| 5 | Click the 'Dismiss' button to remove alert from active notifications | Alert is removed from active notifications list |
| 6 | Navigate to alert history to verify dismissed alert is recorded | Dismissed alert appears in alert history with 'Acknowledged' and 'Dismissed' status and timestamp |

**Postconditions:**
- Alert status is updated to acknowledged and dismissed
- Alert is removed from active notifications
- Alert is preserved in alert history
- User action is logged with timestamp

---

### Test Case: Test user alert preference configuration
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as Scheduler
- User has access to alert preferences settings
- Multiple notification channels are available (in-app, email, SMS)
- User profile is fully configured with contact information

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to user profile or settings page | Settings page loads successfully with alert preferences section visible |
| 2 | Locate alert preferences configuration section | Alert preferences section displays all available notification channels with toggle options |
| 3 | Select specific notification channels (e.g., enable in-app and email, disable SMS) | Selected channels are highlighted/checked, unselected channels are unchecked |
| 4 | Click 'Save' or 'Update Preferences' button | Success message displays confirming preferences have been saved |
| 5 | Refresh the page and verify saved preferences persist | Previously selected notification channels remain checked after page refresh |
| 6 | Trigger a scheduling conflict to test alert delivery | Scheduling conflict is created and detected by the system |
| 7 | Monitor all notification channels for alert delivery | Alert is received only via configured channels (in-app and email), no alert received via disabled channels (SMS) |
| 8 | Verify no alerts are sent to disabled notification channels | SMS channel shows no alert received, confirming preference configuration is respected |

**Postconditions:**
- User alert preferences are saved in the system
- Alerts are delivered only through configured channels
- Disabled channels do not receive alerts
- User preferences are persisted for future alerts

---

## Story: As Resource Manager, I want to receive alerts for double bookings to resolve conflicts quickly
**Story ID:** story-14

### Test Case: Verify alert delivery to Resource Manager within 5 seconds
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as Resource Manager
- Alert notification system is operational
- At least one notification channel is configured for Resource Manager
- Conflict detection engine is running and monitoring bookings
- Test environment has accurate time synchronization
- Resources are available for booking

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create a double booking conflict by booking the same resource for the same time slot twice | Double booking conflict is created and detected by the conflict detection engine |
| 2 | Start timer immediately upon double booking creation | Timer begins tracking alert delivery time from moment of conflict detection |
| 3 | Monitor configured notification channels for Resource Manager (in-app, email, SMS) | System processes the conflict and initiates alert generation |
| 4 | Check for alert arrival on any configured notification channel | Alert is received by Resource Manager on at least one configured channel |
| 5 | Stop timer when alert is received and calculate delivery time | Alert delivery time is 5 seconds or less from the moment of double booking detection |
| 6 | Verify alert delivery confirmation in system logs via GET /alerts/status endpoint | System logs confirm successful alert delivery with timestamp showing delivery within 5 seconds |

**Postconditions:**
- Alert is successfully delivered to Resource Manager
- Alert delivery time meets performance requirement of under 5 seconds
- Alert appears in Resource Manager's active notifications
- Double booking conflict remains active and unresolved
- Alert delivery is logged in system audit trail

---

### Test Case: Validate alert content and acknowledgment by Resource Manager
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in as Resource Manager
- A double booking conflict has been created and detected
- Alert has been delivered to Resource Manager
- Resource Manager has access to notification interface
- Alert history feature is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate and open the received double booking alert notification | Alert notification opens displaying full alert details |
| 2 | Review alert content for detailed conflict information including resource name, booking IDs, time slots, and parties involved | Alert displays comprehensive conflict information: resource identifier, both booking IDs, conflicting date/time range, requestor names, and conflict severity |
| 3 | Verify alert includes actionable elements such as links to booking details and resolution options | Alert contains clickable links to view each conflicting booking and options to initiate resolution workflow |
| 4 | Click the 'Acknowledge' button on the alert | Alert status updates to 'Acknowledged', acknowledgment timestamp is recorded, and confirmation message appears |
| 5 | Click the 'Dismiss' button to remove alert from active view | Alert is removed from active notifications list and user receives confirmation of dismissal |
| 6 | Navigate to alert history section to verify the dismissed alert is preserved | Alert appears in alert history with complete details, 'Acknowledged' status, dismissal timestamp, and Resource Manager's user ID |
| 7 | Verify alert history entry is accessible and searchable | Alert can be retrieved from history using filters such as date, resource, or conflict type |

**Postconditions:**
- Alert status is updated to acknowledged and dismissed in the system
- Alert is removed from active notifications for Resource Manager
- Alert is permanently stored in alert history with full audit trail
- Resource Manager's acknowledgment action is logged with timestamp
- Double booking conflict remains visible in conflict management interface for resolution

---

## Story: As Scheduler, I want to receive conflict alerts via email to stay informed when away from the system
**Story ID:** story-17

### Test Case: Verify email alert delivery within 5 seconds
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User account is active and configured in the system
- User has valid email address registered in profile
- Email alert preferences are enabled for the user
- Email server is operational and accessible
- Conflict detection engine is running
- User is logged into the system with scheduler role

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create a scheduling conflict by assigning the same resource to two overlapping time slots | System detects the scheduling conflict and triggers conflict detection engine |
| 2 | Note the exact timestamp when the conflict was created | Timestamp is recorded for delivery time calculation |
| 3 | Monitor the email inbox associated with the user account | Email alert is received in the inbox |
| 4 | Check the received timestamp of the email alert | Email alert is received within 5 seconds of the conflict creation timestamp |
| 5 | Verify the email sender and subject line | Email is from the system notification address with subject indicating scheduling conflict |

**Postconditions:**
- Email alert is successfully delivered to user inbox
- Conflict remains active in the system until resolved
- Email delivery status is logged in the system
- User can access the email for conflict details

---

### Test Case: Validate email alert content and formatting
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User has received a conflict alert email in their inbox
- Email client is accessible (desktop or mobile)
- Conflict details are available in the system
- Email alert preferences are enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open the received conflict alert email in desktop email client | Email opens successfully and displays content properly formatted |
| 2 | Verify email contains conflict type information | Email clearly displays the type of scheduling conflict (e.g., resource overlap, time conflict) |
| 3 | Verify email contains affected resources details | Email lists all resources involved in the conflict with their identifiers |
| 4 | Verify email contains time and date information | Email displays the conflicting time slots with dates in readable format |
| 5 | Verify email contains actionable links or instructions | Email includes link to view conflict in system or instructions to resolve |
| 6 | Open the same email on a mobile device | Email is responsive and displays all information clearly on mobile screen without horizontal scrolling |
| 7 | Verify all text is readable and images/icons render correctly on mobile | Content is properly formatted for mobile viewing with appropriate font sizes and spacing |

**Postconditions:**
- Email content is verified as complete and accurate
- Email formatting is confirmed for both desktop and mobile
- User has clear understanding of the conflict from email alone

---

### Test Case: Test user preference changes for email alerts
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged into the system with scheduler role
- User has access to preferences/settings page
- Email alert feature is available in the system
- User currently has email alerts enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to user preferences or settings page | Preferences page loads successfully displaying notification settings |
| 2 | Locate the email alerts toggle or checkbox for conflict notifications | Email alert preference control is visible and currently enabled/checked |
| 3 | Disable email alerts by unchecking the option or toggling it off | Toggle switches to disabled state with visual confirmation |
| 4 | Click Save or Apply button to save preferences | System displays success message confirming preference has been saved |
| 5 | Refresh the preferences page or navigate away and return | Email alert preference remains disabled, confirming persistence |
| 6 | Create a scheduling conflict by assigning overlapping resources | System detects and displays the conflict in the UI |
| 7 | Wait for 10 seconds and check the user's email inbox | No email alert is received for the conflict |
| 8 | Verify in-app notification is still displayed | Conflict alert appears in the system UI, confirming only email is disabled |

**Postconditions:**
- Email alerts remain disabled for the user
- User preference is saved in the database
- No email alerts are sent for subsequent conflicts
- In-app notifications continue to function normally

---

## Story: As Scheduler, I want to acknowledge and dismiss conflict alerts to manage notifications effectively
**Story ID:** story-18

### Test Case: Verify alert acknowledgment functionality
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged into the system with scheduler role
- At least one active conflict alert exists in the system
- Alert is displayed in the active notifications list
- User has permission to acknowledge alerts
- Alert management UI is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the notifications or alerts section of the application | Alerts page loads displaying list of active conflict alerts |
| 2 | Identify and view the conflict alert in the active alerts list | Alert is displayed with conflict details, timestamp, and available actions |
| 3 | Note the current count of active alerts displayed | Active alert count is visible (e.g., '5 active alerts') |
| 4 | Click or tap the 'Acknowledge' button for the selected alert | System processes the acknowledgment request and provides visual feedback (e.g., loading indicator) |
| 5 | Verify the alert status changes to 'Acknowledged' | Alert status is updated and displayed as 'Acknowledged' with timestamp |
| 6 | Check the active alerts list | Alert is removed from the active alerts list and active count decreases by one |
| 7 | Navigate to acknowledged or archived alerts section | Previously acknowledged alert appears in the acknowledged alerts list |
| 8 | Verify the acknowledgment timestamp and user information | Alert shows who acknowledged it and when, with accurate timestamp |

**Postconditions:**
- Alert status is permanently updated to 'Acknowledged' in database
- Alert is removed from active notifications
- Alert appears in acknowledged alerts history
- Active alert count is decremented
- User action is logged in audit trail

---

### Test Case: Verify alert dismissal with authorization
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Two user accounts exist: one with dismissal authorization and one without
- At least one active conflict alert exists in the system
- Both users have access to view alerts
- Authorization rules are configured for alert dismissal
- Alert management system is operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the system as a user with authorized dismissal permissions (e.g., Senior Scheduler or Admin) | User successfully logs in and has access to alert management |
| 2 | Navigate to the active alerts list and select a conflict alert | Alert details are displayed with 'Dismiss' button visible and enabled |
| 3 | Click the 'Dismiss' button for the selected alert | System prompts for confirmation of dismissal action |
| 4 | Confirm the dismissal action | Alert is dismissed successfully with confirmation message displayed |
| 5 | Verify the alert is removed from active alerts list | Alert no longer appears in active alerts and is moved to dismissed alerts history |
| 6 | Log out and log in as a user without dismissal authorization (e.g., Junior Scheduler or Viewer role) | Unauthorized user successfully logs in with limited permissions |
| 7 | Navigate to the active alerts list and select a conflict alert | Alert details are displayed but 'Dismiss' button is either hidden, disabled, or grayed out |
| 8 | Attempt to dismiss the alert (if button is visible, click it; otherwise try API call or direct URL) | System prevents dismissal and displays error message: 'You do not have permission to dismiss alerts' or similar |
| 9 | Verify the alert remains in the active alerts list | Alert status is unchanged and remains active in the system |
| 10 | Check system logs for the unauthorized dismissal attempt | Unauthorized attempt is logged with user ID, timestamp, and action denied |

**Postconditions:**
- Authorized user successfully dismissed alert is recorded in history
- Unauthorized user's alert remains active and unchanged
- Security event is logged for unauthorized attempt
- Permission controls are validated as functioning correctly
- Alert dismissal authorization rules are enforced

---

### Test Case: Ensure alert history logs actions
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged into the system with scheduler role
- At least one active conflict alert exists
- Alert history feature is enabled and accessible
- User has permission to acknowledge or dismiss alerts
- Audit logging is enabled in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the active alerts section and select a conflict alert | Alert details are displayed with available actions (Acknowledge/Dismiss) |
| 2 | Note the alert ID and current timestamp before taking action | Alert ID and timestamp are recorded for verification |
| 3 | Click 'Acknowledge' button for the selected alert | Alert is acknowledged successfully with confirmation message |
| 4 | Navigate to the alert history or audit log section | Alert history page loads displaying chronological list of alert actions |
| 5 | Search or filter for the acknowledged alert by alert ID | Alert history entry is found showing the acknowledgment action |
| 6 | Verify the history entry contains: alert ID, action type (Acknowledged), user who performed action, and timestamp | All required information is present and accurate in the history log |
| 7 | Create or select another active conflict alert | New alert is available for testing dismissal action |
| 8 | Dismiss the alert using the 'Dismiss' button | Alert is dismissed successfully with confirmation |
| 9 | Return to alert history and search for the dismissed alert | History entry for dismissal action is found |
| 10 | Verify the dismissal entry contains: alert ID, action type (Dismissed), user who performed action, timestamp, and any dismissal reason if provided | Complete dismissal information is logged accurately in alert history |
| 11 | Verify both actions appear in chronological order in the history | Alert history displays both acknowledgment and dismissal actions in correct sequence with proper timestamps |

**Postconditions:**
- All alert actions are permanently recorded in alert history
- Audit trail is complete and accurate for compliance
- History entries are searchable and filterable
- User actions are traceable for accountability
- System maintains data integrity of alert action logs

---

## Story: As Scheduler, I want to configure alert preferences to receive notifications relevant to my role
**Story ID:** story-19

### Test Case: Verify alert preference modification and persistence
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in as a Scheduler
- User has valid authentication credentials
- Alert preference settings page is accessible
- User profile database is operational
- At least one alert channel is available (in-app, email, or SMS)
- Default alert preferences are currently set

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to user profile or settings menu | User profile or settings menu is displayed with navigation options |
| 2 | Click on 'Alert Preferences' or 'Notification Settings' option | Alert preference settings UI is displayed showing current preference configuration including alert types, channels, and frequency options |
| 3 | Review current alert type settings (conflicts, reminders) | Current alert type selections are visible with checkboxes or toggle switches showing enabled/disabled state |
| 4 | Select or deselect desired alert types (e.g., enable 'Conflicts', disable 'Reminders') | Alert type selections update visually to reflect the changes made |
| 5 | Change alert channel from current setting to a different option (e.g., from 'In-app only' to 'Email and In-app') | Selected channels are highlighted or checked, showing the new channel configuration |
| 6 | Modify frequency setting (e.g., change from 'Immediate' to 'Daily digest') | Frequency dropdown or radio button updates to show the newly selected frequency option |
| 7 | Click 'Save' or 'Apply' button to save preferences | System displays success message confirming preferences have been saved successfully |
| 8 | Navigate away from the alert preferences page and return to it | Previously saved preferences are displayed correctly, confirming persistence across navigation |
| 9 | Create or trigger a test alert condition that matches the configured alert type (e.g., create a scheduling conflict) | Alert is generated in the system |
| 10 | Verify alert delivery through the configured channels | Alert is delivered only through the selected channels (e.g., email and in-app) and not through unselected channels (e.g., SMS) |
| 11 | Check alert delivery timing matches the configured frequency | If 'Immediate' was selected, alert is delivered instantly; if 'Daily digest' was selected, alert is queued for digest delivery |
| 12 | Log out and log back in to the system | User successfully logs back in |
| 13 | Access alert preferences settings again | All previously configured preferences are retained and displayed correctly, confirming persistence across sessions |

**Postconditions:**
- User alert preferences are saved in the user profile database
- Alert delivery system is configured according to user preferences
- Preferences persist across sessions and page navigation
- Future alerts will be delivered according to the updated preferences
- System logs reflect the preference changes

---

### Test Case: Validate preference input validation
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in as a Scheduler
- User has access to alert preference settings
- Alert preference settings page is accessible
- Validation rules are configured in the system
- API endpoints for preference validation are operational

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to alert preferences settings page | Alert preference settings UI is displayed with all configuration options |
| 2 | Attempt to deselect all alert types (no conflicts, no reminders) | System displays validation error message indicating at least one alert type must be selected, or allows the selection but warns user |
| 3 | Attempt to deselect all alert channels (no in-app, no email, no SMS) | System displays validation error message: 'At least one alert channel must be selected' and prevents saving |
| 4 | Select SMS channel and enter an invalid phone number format (e.g., 'abc123' or incomplete number) | System displays validation error: 'Invalid phone number format. Please enter a valid phone number' and highlights the invalid field |
| 5 | Select email channel and enter an invalid email address (e.g., 'invalidemail' or 'test@') | System displays validation error: 'Invalid email address format. Please enter a valid email' and highlights the invalid field |
| 6 | Attempt to select a frequency option that is not supported (if applicable through API manipulation or direct input) | System displays validation error: 'Invalid frequency option selected' and resets to a valid default option |
| 7 | Try to save preferences with validation errors present | System prevents saving and displays message: 'Please correct the errors before saving preferences' with all validation errors listed |
| 8 | Correct one validation error but leave others unresolved | System still prevents saving and continues to display remaining validation errors |
| 9 | Correct all validation errors with valid inputs | Validation error messages disappear and fields are marked as valid |
| 10 | Click 'Save' button with all valid inputs | System successfully saves preferences and displays success confirmation message |
| 11 | Attempt to submit preferences using API with invalid JSON payload or missing required fields | API returns appropriate error response (400 Bad Request) with detailed validation error messages |
| 12 | Verify that invalid preferences were not saved to the database | Previous valid preferences remain unchanged in the system; no invalid data is persisted |

**Postconditions:**
- Invalid preferences are not saved to the database
- User is informed of all validation errors clearly
- System maintains data integrity by rejecting invalid inputs
- Previous valid preferences remain intact
- Validation error messages are cleared once errors are corrected
- System logs validation failures for audit purposes

---

