# Manual Test Cases

## Story: As Scheduler, I want to detect scheduling conflicts in real-time to avoid double bookings
**Story ID:** story-5

### Test Case: Validate conflict detection for overlapping events
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is authenticated and logged into the scheduling system
- User has permission to create and schedule events
- Event database is accessible and operational
- No existing events are scheduled in the 10:00-12:00 time slot
- System conflict detection feature is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduling interface and select 'Create New Event' | Event creation form is displayed with all required fields (title, start time, end time, participants) |
| 2 | Enter event details: Title='Meeting A', Start Time='10:00', End Time='11:00', and click 'Schedule' | Event 'Meeting A' is scheduled successfully and appears in the calendar view for the 10:00-11:00 time slot |
| 3 | Verify the first event is saved by refreshing the calendar view | Event 'Meeting A' remains visible in the calendar at 10:00-11:00 time slot |
| 4 | Click 'Create New Event' again to schedule a second event | Event creation form is displayed again with empty fields ready for new input |
| 5 | Enter event details: Title='Meeting B', Start Time='10:30', End Time='11:30', and click 'Schedule' | System detects the overlap between 10:30-11:00 with existing 'Meeting A' and prevents immediate scheduling |
| 6 | Check for conflict alert notification on the screen | User receives a conflict alert notification within 2 seconds indicating overlap with 'Meeting A' from 10:30 to 11:00 |
| 7 | Review the conflict details displayed in the alert | Alert shows both conflicting events with their time slots: 'Meeting A (10:00-11:00)' and 'Meeting B (10:30-11:30)' with the overlapping period highlighted |
| 8 | Verify that 'Meeting B' was not added to the calendar | Only 'Meeting A' appears in the calendar; 'Meeting B' is not scheduled |

**Postconditions:**
- Only the first event 'Meeting A' (10:00-11:00) remains scheduled in the system
- The second event 'Meeting B' is not saved to the database
- Conflict alert has been displayed to the user
- User can modify the second event time to resolve the conflict
- System remains in a consistent state ready for next scheduling action

---

### Test Case: Ensure no conflict detection for non-overlapping events
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is authenticated and logged into the scheduling system
- User has permission to create and schedule events
- Event database is accessible and operational
- No existing events are scheduled in the 10:00-13:00 time slot
- System conflict detection feature is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduling interface and select 'Create New Event' | Event creation form is displayed with all required fields (title, start time, end time, participants) |
| 2 | Enter event details: Title='Meeting A', Start Time='10:00', End Time='11:00', and click 'Schedule' | Event 'Meeting A' is scheduled successfully without any conflict alerts and appears in the calendar view for the 10:00-11:00 time slot |
| 3 | Verify the first event is saved by checking the calendar view | Event 'Meeting A' is visible in the calendar at 10:00-11:00 time slot with confirmed status |
| 4 | Click 'Create New Event' to schedule a second event immediately after the first | Event creation form is displayed again with empty fields ready for new input |
| 5 | Enter event details: Title='Meeting B', Start Time='11:00', End Time='12:00', and click 'Schedule' | System processes the request and completes the conflict check within 2 seconds without detecting any overlap |
| 6 | Verify that 'Meeting B' is scheduled successfully | Event 'Meeting B' is scheduled successfully and appears in the calendar view for the 11:00-12:00 time slot immediately following 'Meeting A' |
| 7 | Check for any conflict alert notifications on the screen or notification panel | No conflict alert is displayed; user does not receive any conflict notification |
| 8 | Verify both events are visible in the calendar view | Both 'Meeting A' (10:00-11:00) and 'Meeting B' (11:00-12:00) are displayed consecutively in the calendar without any conflict indicators |
| 9 | Check the event database or event list to confirm both events are saved | Both events are successfully saved in the system with correct time slots and no conflict flags |

**Postconditions:**
- Both events 'Meeting A' (10:00-11:00) and 'Meeting B' (11:00-12:00) are successfully scheduled in the system
- No conflict alerts were generated during the scheduling process
- Both events are saved to the database with active status
- Calendar displays both events consecutively without overlap
- System is ready to accept additional scheduling requests

---

