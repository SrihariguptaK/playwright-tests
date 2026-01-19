# Manual Test Cases

## Story: As Scheduler, I want to view resource availability in real-time to make informed scheduling decisions
**Story ID:** story-5

### Test Case: Verify real-time resource availability display
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role
- Scheduling interface is accessible
- At least one resource exists in the system with existing bookings
- Database contains current booking data
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduling interface from the main dashboard | Scheduling interface loads successfully and displays the resource selection panel |
| 2 | Select a specific resource from the resource list | Availability calendar displays for the selected resource showing current bookings in occupied slots and free slots clearly marked as available |
| 3 | Verify the calendar shows existing bookings with time slots and booking details | All current bookings are visible with accurate time ranges, and free slots are distinguishable from booked slots |
| 4 | Create a new booking for the selected resource by choosing an available time slot and saving | Booking is created successfully and confirmation message is displayed |
| 5 | Observe the availability calendar without refreshing the page | Availability calendar updates within 1 second to reflect the new booking, showing the previously free slot now as occupied |
| 6 | Click on the resource type filter dropdown and select a specific resource type | Calendar updates immediately to display only resources matching the selected type with their respective availability |
| 7 | Clear the filter or select a different resource type | Calendar refreshes to show the newly filtered set of resources with accurate availability data |

**Postconditions:**
- New booking is saved in the database
- Availability calendar reflects all current bookings accurately
- Filter settings can be reset or modified for subsequent searches
- System remains in ready state for additional scheduling operations

---

### Test Case: Ensure availability data refresh latency under 1 second
- **ID:** tc-002
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Scheduler role
- Scheduling interface is open with a resource availability view displayed
- Access to modify bookings externally (via API or another user session)
- System monitoring tools or browser developer tools available to measure response time
- At least one resource with existing bookings is available

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open the availability calendar for a specific resource in the scheduling interface | Availability calendar displays with current bookings and free slots |
| 2 | Using an external method (API call, different user session, or admin panel), create a new booking for the same resource | External booking is successfully created in the system |
| 3 | Start a timer and observe the availability view in the original session without manual refresh | Availability view automatically updates within 1 second to show the new booking created externally |
| 4 | Externally modify an existing booking (change time or cancel) for the resource being viewed | Modified booking change is saved successfully in the system |
| 5 | Observe the UI response time for the availability update | UI updates within 1 second with no noticeable delay, displaying the modified booking information |
| 6 | Compare the displayed availability data with the actual booking records in the database or via API query | Displayed availability matches actual bookings exactly with 100% accuracy - all booked slots, free slots, and booking details are correct |
| 7 | Perform multiple rapid external booking changes and monitor UI updates | Each change is reflected in the UI within 1 second, maintaining data accuracy throughout |

**Postconditions:**
- All external booking modifications are accurately reflected in the availability view
- System maintains real-time synchronization between database and UI
- Performance metrics confirm sub-1-second refresh latency
- No data inconsistencies exist between displayed and actual availability

---

### Test Case: Test integration of availability view with scheduling form
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in with Scheduler role
- Scheduling interface and availability calendar are accessible
- Resources exist with both available and unavailable time slots
- Scheduling form is functional and integrated with availability view
- Conflict detection system is active

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open the scheduling interface and display the availability calendar for a resource | Availability calendar loads showing current bookings and free slots |
| 2 | Click on an available (free) time slot in the availability calendar | Scheduling form opens or becomes active with the selected resource and time slot pre-filled automatically |
| 3 | Verify that the resource name, date, start time, and end time fields in the scheduling form match the selected slot | All fields are accurately pre-populated with the selected resource and time slot information |
| 4 | Navigate back to the availability calendar and click on a time slot that is already booked (unavailable) | System prevents the scheduling form from opening for booking, or opens the form in view-only mode showing existing booking details |
| 5 | Attempt to manually modify the scheduling form to book the unavailable slot by changing the time to overlap with an existing booking | System detects the conflict and prevents the booking action, displaying a conflict alert message indicating the resource is unavailable for the selected time |
| 6 | Review the conflict alert message for clarity and actionable information | Alert clearly states the conflict reason, shows the conflicting booking details, and suggests alternative available time slots |
| 7 | Select a different available time slot from the calendar and complete the booking form with all required information | Scheduling form accepts all inputs without conflict warnings |
| 8 | Submit the booking for the available slot | Booking succeeds without any conflict errors, confirmation message is displayed, and the new booking appears in the availability calendar |
| 9 | Verify the availability calendar updates to show the newly booked slot as unavailable | Calendar reflects the new booking immediately, showing the slot as occupied |

**Postconditions:**
- New booking is successfully saved in the system
- Availability calendar accurately reflects all bookings including the new one
- No conflicting bookings exist for the resource
- Conflict detection system remains active for future booking attempts
- System is ready for additional scheduling operations

---

## Story: As Scheduler, I want the system to prevent saving schedules with conflicts unless authorized to override
**Story ID:** story-7

### Test Case: Block save on conflicting schedule without override
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with standard Scheduler role without override authorization
- Scheduling interface is accessible
- At least one resource exists with an existing booking
- Conflict detection system is enabled and functional
- User does not have override permissions in their role

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduling interface and open the booking form | Booking form loads successfully with all required fields available |
| 2 | Select a resource that already has a booking for a specific time slot | Resource is selected and available for scheduling attempt |
| 3 | Enter booking details that create a time conflict with the existing booking (overlapping start/end times) | Form accepts the input and allows proceeding to save |
| 4 | Click the Save button to attempt saving the conflicting schedule | System detects the conflict, blocks the save operation, and displays a clear conflict error message indicating the resource is already booked for the selected time |
| 5 | Verify that no override option or button is presented to the non-authorized user | Override option is not visible or accessible, confirming proper role-based access control |
| 6 | Attempt to bypass the block by resubmitting the form multiple times or using browser refresh | System consistently prevents the save operation, displaying the conflict message each time without allowing the conflicting schedule to be saved |
| 7 | Check the database or booking list to verify the conflicting schedule was not saved | No new conflicting booking exists in the system; only the original booking remains, confirming the save was successfully blocked |
| 8 | Verify the original booking remains unchanged and intact | Original booking data is unaffected and remains accurate in the system |

**Postconditions:**
- No conflicting schedule is saved in the database
- Original booking remains intact and unchanged
- User receives clear feedback about why the save was blocked
- System maintains schedule integrity
- Audit log shows the blocked save attempt (if logging is implemented for failed attempts)

---

### Test Case: Allow override save for authorized user
- **ID:** tc-005
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with a role that has override authorization (e.g., Senior Scheduler, Manager)
- Scheduling interface is accessible
- At least one resource exists with an existing booking creating a conflict scenario
- Conflict detection and override system are enabled
- Audit logging system is active and functional
- User has valid authorization credentials

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as an authorized user with override permissions | User successfully logs in and has access to scheduling interface with override capabilities |
| 2 | Navigate to the scheduling interface and create a booking that conflicts with an existing schedule | Booking form is filled with conflicting time slot details |
| 3 | Click the Save button to attempt saving the conflicting schedule | System detects the conflict and displays a conflict warning message along with an 'Override' option button clearly visible to the authorized user |
| 4 | Verify the override option is presented with appropriate warning text about the implications of overriding | Override button is visible with warning text explaining that proceeding will create a conflicting schedule |
| 5 | Click the Override button to proceed with the conflicting save | System prompts for authorization credentials (password re-entry, confirmation dialog, or additional authentication) |
| 6 | Enter valid authorization credentials and confirm the override action | Credentials are accepted, and the system processes the override request |
| 7 | Submit the override confirmation | Conflicting schedule is saved successfully, and a confirmation message is displayed indicating the override was successful |
| 8 | Navigate to the audit log or system logs section | Audit log interface loads successfully |
| 9 | Search for the most recent override action entry in the audit log | Override action is logged with complete details including user identity (username/ID), timestamp (date and time), resource affected, conflicting booking details, and override reason if captured |
| 10 | Verify the logged entry contains all required information and is accurate | All override details are accurately recorded with correct user information and precise timestamp |
| 11 | Check the scheduling view to confirm both the original and new conflicting bookings are now visible | Both bookings are displayed in the system, showing the conflict exists as an override |

**Postconditions:**
- Conflicting schedule is successfully saved in the database
- Both original and overridden bookings exist in the system
- Override action is fully logged in audit trail with user and timestamp
- System maintains data integrity despite the conflict
- Authorization credentials are not stored in logs
- User can continue with normal scheduling operations

---

### Test Case: Send notifications on override save
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 12 mins

**Preconditions:**
- User is logged in with override authorization role
- Scheduling interface is accessible
- Notification system is configured and operational
- Stakeholder contact information (email/phone) is configured in the system
- At least one stakeholder is designated to receive override notifications
- A conflicting booking scenario exists
- Email/notification service is active and reachable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log in as an authorized user and navigate to the scheduling interface | User is logged in successfully with override permissions and scheduling interface is displayed |
| 2 | Create a booking that conflicts with an existing schedule | Conflicting booking details are entered in the form |
| 3 | Attempt to save the conflicting schedule and click the Override option when presented | Override option is displayed and selected |
| 4 | Provide authorization credentials and confirm the override action to complete the save | Override is processed successfully, conflicting schedule is saved, and confirmation message is displayed |
| 5 | Wait for notification processing (typically a few seconds) and check the notification queue or logs | System triggers notification sending process immediately after override save completion |
| 6 | Access the stakeholder's notification inbox (email, system notifications, or SMS) designated to receive override alerts | Notification is sent to all configured stakeholders |
| 7 | Open and review the notification content | Notification includes complete override details: user who performed the override (name and ID), timestamp of override action, resource affected, original booking details, new conflicting booking details, and reason for override if provided |
| 8 | Verify the notification subject line clearly indicates it is an override alert | Subject line is clear and descriptive (e.g., 'Schedule Override Alert: Conflicting Booking Created') |
| 9 | Check the timestamp of notification delivery against the override action timestamp | Notification is delivered promptly within acceptable timeframe (within 1-2 minutes of override action), confirming stakeholders receive timely alerts |
| 10 | Verify all designated stakeholders received the notification | All configured stakeholders have received the notification successfully without delivery failures |
| 11 | Check notification logs or delivery status in the system | Notification delivery is logged with successful delivery status for each recipient |

**Postconditions:**
- Override save is completed and recorded
- Notifications are successfully sent to all stakeholders
- Notification delivery is logged in the system
- Stakeholders are informed of the override action with complete details
- System is ready to send notifications for future override actions
- No notification delivery errors are present

---

## Story: As Scheduler, I want the system to provide alternative time slot suggestions when conflicts occur to facilitate quick rescheduling
**Story ID:** story-10

### Test Case: Verify alternative time slot suggestions generation
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least one resource is available in the system
- Resource calendars contain both occupied and free time slots
- Scheduling form is accessible and functional
- System has access to Resource availability API

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduling form and enter booking details (resource, date, time) that create a scheduling conflict with an existing booking | System detects the scheduling conflict and triggers alternative time slot suggestion generation |
| 2 | Start timer and wait for system to generate alternative time slot suggestions | System generates and displays multiple alternative time slot suggestions within 2 seconds of conflict detection |
| 3 | Review the list of suggested alternative time slots displayed by the system | All suggested slots are valid, available, and conflict-free with existing bookings for the selected resource |
| 4 | Select one of the alternative time slots from the suggestions list | Selected alternative slot is highlighted and system prepares to update the scheduling form |
| 5 | Confirm the selection of the alternative slot | Scheduling form automatically updates with the selected alternative slot details including date and time fields |

**Postconditions:**
- Scheduling form displays the selected alternative time slot
- No conflict warnings are present
- Form is ready for final submission
- Original conflicting time slot is no longer selected

---

### Test Case: Test application of selected alternative slot
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Scheduler role
- A scheduling conflict has been detected
- Alternative time slot suggestions have been generated and displayed
- At least one valid alternative slot is available for selection
- Scheduling form is in editable state

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | From the displayed alternative time slot suggestions, click on a preferred alternative slot | Selected alternative slot is highlighted and marked as chosen |
| 2 | Observe the scheduling form fields after selection | All scheduling form fields (date, time, duration, resource) update automatically to reflect the selected alternative slot details |
| 3 | Verify that all form fields contain correct information from the selected alternative | Date field shows alternative date, time field shows alternative time, resource remains the same, and all other relevant fields are populated correctly |
| 4 | Click the Submit or Save button to complete the booking with the alternative slot | System processes the booking request and saves the schedule successfully |
| 5 | Wait for confirmation message and check for any conflict alerts or error messages | Booking is saved successfully without any conflicts, confirmation message is displayed, and no conflict alerts or error messages appear |
| 6 | Navigate to the resource calendar or schedule view to verify the booking | New booking appears in the calendar at the selected alternative time slot with correct details and no overlapping conflicts |

**Postconditions:**
- Booking is successfully saved in the system
- Resource calendar reflects the new booking at alternative time slot
- No scheduling conflicts exist
- Confirmation of successful booking is displayed
- System returns to normal scheduling state

---

### Test Case: Ensure suggestion generation performance
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role
- Multiple resources with varying availability exist in the system
- System performance monitoring tools are available
- Resource availability API is operational
- Network connection is stable
- System is under normal load conditions

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open the scheduling form and enter booking details that will create a conflict with existing bookings | System detects the scheduling conflict and initiates alternative slot suggestion process |
| 2 | Start a timer or use browser developer tools to measure response time when conflict is detected | Timer starts accurately at the moment of conflict detection |
| 3 | Wait for alternative time slot suggestions to be generated and displayed | Alternative time slot suggestions are returned and displayed within 2 seconds of conflict detection |
| 4 | Record the exact time taken for suggestion generation | Recorded time is at or below 2 seconds threshold |
| 5 | Monitor system performance metrics including CPU usage, memory consumption, and API response times during suggestion generation | No significant degradation in system performance is observed, all metrics remain within acceptable ranges |
| 6 | Review each suggested alternative time slot for accuracy by cross-referencing with resource calendars | All suggested slots are verified as conflict-free and accurately reflect actual resource availability |
| 7 | Repeat the test with different resources and time periods to ensure consistent performance | Suggestion generation consistently completes within 2 seconds across multiple test scenarios |

**Postconditions:**
- System performance remains stable
- All suggested alternatives are verified as accurate and conflict-free
- Performance metrics are documented and within acceptable thresholds
- No system errors or timeouts occurred
- Response time consistently meets the 2-second requirement

---

