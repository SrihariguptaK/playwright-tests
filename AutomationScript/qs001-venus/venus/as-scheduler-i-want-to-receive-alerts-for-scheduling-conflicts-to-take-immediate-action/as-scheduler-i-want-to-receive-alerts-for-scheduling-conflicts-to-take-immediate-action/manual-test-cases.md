# Manual Test Cases

## Story: As Scheduler, I want to receive alerts for scheduling conflicts to take immediate action
**Story ID:** story-6

### Test Case: Validate alert notification for detected conflict
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User account is active and logged into the system
- User has valid notification preferences configured
- Notification service is operational and accessible
- At least one scheduling conflict exists or can be triggered in the system
- User has permissions to receive scheduling alerts

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Trigger or simulate a scheduling conflict in the system (e.g., double-booking a resource or overlapping appointments) | System detects the scheduling conflict and generates an alert notification within 5 seconds |
| 2 | Navigate to user profile settings and check notification preferences section | Notification settings page displays correctly showing user's configured preferences (in-app, email, or SMS) are properly set and active |
| 3 | Check the chosen notification method (in-app notification center, email inbox, or SMS messages) for the alert | Alert is received via the user's chosen notification method and contains accurate conflict details including: conflict type, affected resources, time/date of conflict, and conflicting parties involved |

**Postconditions:**
- Alert notification is successfully delivered to the user
- Alert details are accurate and match the detected conflict
- System logs the alert delivery in the notification history
- User is able to view and act upon the alert information

---

### Test Case: Ensure alerts are customizable
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged into the system with valid credentials
- User has access to alert settings configuration
- System has default alert preferences set for the user
- Notification service supports multiple delivery methods (in-app, email, SMS)
- User has valid email address and/or phone number registered in the system

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to user settings menu and select 'Alert Settings' or 'Notification Preferences' option | Alert settings page is displayed showing all available notification options including in-app notifications, email alerts, and SMS alerts with current preference selections visible |
| 2 | Modify alert preferences by selecting or deselecting notification methods (e.g., enable SMS alerts, disable email alerts, keep in-app enabled) and click 'Save' or 'Update Preferences' button | System displays a success message confirming preferences are saved successfully, and the updated preferences are reflected in the settings page |
| 3 | Trigger or simulate a scheduling conflict in the system after preference changes have been saved | System detects the conflict and sends alert notification according to the newly configured preferences (only through the selected notification methods), and alert is not sent through disabled notification channels |

**Postconditions:**
- User's alert preferences are updated in the system database
- Future alerts are sent only through the newly configured notification methods
- System respects user's customized alert settings for all subsequent conflicts
- Alert delivery logs reflect the updated preference settings

---

