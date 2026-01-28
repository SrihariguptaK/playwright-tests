# Manual Test Cases

## Story: As Scheduler, I want to receive alerts for scheduling conflicts to achieve timely adjustments.
**Story ID:** story-6

### Test Case: Validate alert delivery for detected conflicts
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is authenticated and logged into the system
- Notification service is running and operational
- User has valid contact information (email/phone) configured
- User has alert notifications enabled in preferences
- At least two scheduling items exist that can create a conflict

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Create or modify a schedule entry that conflicts with an existing schedule (e.g., overlapping time slots for the same resource) | System detects the scheduling conflict and triggers the conflict detection mechanism |
| 2 | System processes the detected conflict and prepares an alert notification | Alert notification is prepared with conflict details including affected schedules, time slots, and resources |
| 3 | System sends the alert to the user via configured notification channels (email, SMS, or in-app) | Alert is dispatched successfully through the notification service within 5 seconds of conflict detection |
| 4 | User checks their notification channels (email inbox, SMS messages, or in-app notification center) | User receives the alert notification containing the scheduling conflict information |
| 5 | User opens and reviews the alert notification | Alert displays complete conflict details including: conflicting schedule names, affected time periods, resources involved, and conflict severity |
| 6 | Verify the timestamp of alert delivery against the conflict detection time | Alert delivery timestamp is within 5 seconds of the conflict detection timestamp |

**Postconditions:**
- Alert is marked as delivered in the notification service
- Alert appears in user's notification history
- Scheduling conflict remains active until resolved
- System logs the alert delivery status

---

### Test Case: Ensure alerts contain actionable insights
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is authenticated and logged into the system
- Notification service is operational
- A scheduling conflict exists in the system
- User has permissions to modify schedules
- Alert notification feature is enabled for the user

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | System detects a scheduling conflict and triggers the alert generation process | System initiates alert preparation with conflict analysis |
| 2 | System sends an alert notification for the scheduling conflict via the user's preferred notification channel | Alert is dispatched successfully to the user with complete payload |
| 3 | User receives and opens the alert notification | Alert notification is displayed to the user |
| 4 | User reviews the alert content for conflict details | Alert includes detailed information: conflict description, affected schedules, conflicting time slots, resources involved, and conflict type |
| 5 | User examines the actionable insights section of the alert | Alert contains suggested actions such as: reschedule options, alternative time slots, resource reassignment suggestions, or conflict resolution recommendations |
| 6 | User selects one of the suggested actions from the alert (e.g., clicks on a reschedule link or navigates to the scheduling interface) | User is directed to the appropriate interface to implement the suggested action |
| 7 | User implements the suggested action to resolve the conflict (e.g., modifies schedule time, reassigns resource, or cancels conflicting entry) | Schedule modification is saved successfully |
| 8 | System validates that the conflict has been resolved | Conflict is removed from active conflicts list and user receives confirmation that the conflict has been successfully resolved |

**Postconditions:**
- Scheduling conflict is resolved and no longer active
- Alert is marked as actioned in the system
- Updated schedule is saved and reflected in the system
- No overlapping conflicts exist for the affected resources
- System logs the conflict resolution action

---

