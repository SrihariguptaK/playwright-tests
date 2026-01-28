# Manual Test Cases

## Story: As User, I want to receive notifications for scheduling conflicts to achieve timely adjustments
**Story ID:** story-5

### Test Case: Validate notification delivery for detected conflicts
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User account is active and logged into the system
- User has valid notification preferences configured (email, SMS, or in-app)
- User has at least one existing scheduled event in the calendar
- Notification service is running and operational
- User has granted necessary permissions for receiving notifications

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create a new event that overlaps with an existing event in the user's calendar to trigger a scheduling conflict | System detects the scheduling conflict and generates a notification within 2 seconds |
| 2 | Navigate to user profile settings and check the configured notification preferences | User's preferred notification channel (email, SMS, or in-app) is displayed and active |
| 3 | Verify that the notification is sent via the user's preferred channel by checking the respective inbox/notification center | Notification is successfully delivered through the preferred channel within 2 seconds of conflict detection |
| 4 | Open the received notification and review its content | Notification contains all relevant conflict details including: conflicting event names, date and time of both events, duration of overlap, and a direct link to resolve the conflict |
| 5 | Verify the notification delivery status in the system logs or admin panel | Notification delivery status shows as 'Delivered' with timestamp matching the conflict detection time |

**Postconditions:**
- Notification is marked as delivered in the system
- User has received the conflict notification via their preferred channel
- Notification delivery is logged in the system with timestamp
- Conflict remains unresolved until user takes action

---

### Test Case: Ensure notifications are not sent for non-conflicting events
- **ID:** tc-002
- **Type:** edge-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User account is active and logged into the system
- User has notification preferences configured
- User's calendar is accessible and functional
- Notification service is running and operational
- No existing scheduling conflicts are present in the user's calendar

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Schedule the first event in the user's calendar with a specific date, start time, and end time (e.g., Meeting A from 10:00 AM to 11:00 AM) | First event is successfully created and saved in the calendar without any conflicts detected |
| 2 | Schedule a second event in the user's calendar that does not overlap with the first event (e.g., Meeting B from 2:00 PM to 3:00 PM on the same day) | Second event is successfully created and saved in the calendar. System confirms no scheduling conflict exists between the two events |
| 3 | Access the notification logs via admin panel or API endpoint to check for any conflict notifications generated | Notification logs show no conflict notifications were generated or sent for these two events |
| 4 | Check the user's notification center, email inbox, and SMS messages (based on configured preferences) | User has not received any conflict notifications. No new notifications appear in any of the notification channels |
| 5 | Verify the system's conflict detection logic by reviewing event timestamps and overlap calculations | System correctly identifies that the events do not overlap and no conflict detection is triggered |

**Postconditions:**
- Both non-conflicting events remain scheduled in the calendar
- No notifications are present in the notification logs
- User's notification channels remain clear of conflict alerts
- System maintains accurate conflict detection without false positives

---

