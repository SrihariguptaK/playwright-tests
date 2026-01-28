# Manual Test Cases

## Story: As Scheduler, I want to detect scheduling conflicts in real-time to achieve efficient resource allocation.
**Story ID:** story-3

### Test Case: Validate conflict detection with overlapping schedules
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is authenticated and logged into the scheduling system
- At least one existing booking is present in the scheduling database
- User has permissions to create new scheduling requests
- API endpoint /api/schedule/check is accessible and operational
- Scheduling database is online and responsive

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduling interface and access the new booking form | New booking form is displayed with all required fields (date, time, resource, duration) |
| 2 | Enter scheduling details that overlap with an existing booking (same resource, overlapping time slot) | Form accepts the input and displays entered values correctly |
| 3 | Submit the scheduling request by clicking the Submit button | System processes the request and performs conflict detection within 2 seconds |
| 4 | Observe the system response for conflict detection alert | System detects the conflict and displays an alert message to the user indicating the scheduling conflict with details of the overlapping booking |
| 5 | Navigate to the conflict log section in the system | Conflict log interface is displayed with list of all detected conflicts |
| 6 | Check the conflict log for the newly detected conflict entry | Conflict is recorded in the system with timestamp, conflicting schedules, resource details, and user information |
| 7 | Review the alert message displayed to the user | Alert provides clear information about the conflict and offers actionable options for resolution (e.g., modify time, select different resource, cancel request) |

**Postconditions:**
- Conflict is logged in the system database
- User is aware of the scheduling conflict
- Original existing booking remains unchanged
- New conflicting booking is not created
- System is ready to accept new scheduling requests

---

### Test Case: Ensure no false positives in conflict detection
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is authenticated and logged into the scheduling system
- Existing bookings are present in the scheduling database
- User has permissions to create new scheduling requests
- API endpoint /api/schedule/check is accessible and operational
- Scheduling database is online and responsive

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduling interface and access the new booking form | New booking form is displayed with all required fields available for input |
| 2 | Enter scheduling details that do not overlap with any existing bookings (different time slot or different resource) | Form accepts the input and all entered values are displayed correctly |
| 3 | Submit the scheduling request by clicking the Submit button | System processes the request and performs conflict detection check within 2 seconds |
| 4 | Observe the system response for any conflict alerts | System does not detect any conflicts and proceeds with booking creation without displaying any conflict alerts |
| 5 | Verify that a success confirmation message is displayed | System displays a success message confirming the booking has been created successfully |
| 6 | Navigate to the conflict log section in the system | Conflict log interface is displayed showing existing conflict entries |
| 7 | Check the conflict log for any new entries related to the submitted request | No new entries are added to the conflict log for this non-conflicting booking request |
| 8 | Review the user interface for any alert messages | No conflict alert is generated or displayed to the user |
| 9 | Verify the new booking appears in the schedule view | New booking is successfully created and visible in the scheduling calendar/list view |

**Postconditions:**
- New booking is successfully created in the system
- No false conflict entries are logged
- Scheduling database is updated with the new booking
- User receives confirmation of successful booking
- System is ready to accept additional scheduling requests

---

