# Manual Test Cases

## Story: As Scheduler, I want to receive immediate conflict detection when creating a schedule to avoid double-booking resources
**Story ID:** story-1

### Test Case: Validate immediate conflict detection on overlapping schedule creation
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Scheduler role permissions
- Scheduling database is accessible and populated with existing schedules
- At least one resource is already booked for a specific date and time slot
- Schedule creation interface is accessible
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule creation page from the main dashboard | Schedule creation form is displayed with fields for date, time, and resource selection |
| 2 | Select a date from the date picker that has existing bookings | Date is selected and displayed in the date field |
| 3 | Enter a start time that overlaps with an existing booking (e.g., 10:00 AM when 9:00 AM - 11:00 AM is already booked) | Time is entered in the start time field |
| 4 | Enter an end time for the schedule (e.g., 12:00 PM) | Time is entered in the end time field |
| 5 | Select a resource from the dropdown that is already booked for the selected time slot | System immediately displays a conflict alert message indicating the resource is already booked with specific conflict details (existing booking time and resource name) |
| 6 | Attempt to click the 'Save' or 'Submit' button to save the schedule | System blocks the submission, keeps the Save button disabled or shows an error message, and displays clear conflict details including the conflicting schedule information |
| 7 | Review the conflict details displayed on screen | Conflict details clearly show the resource name, conflicting date, conflicting time range, and any additional relevant information |

**Postconditions:**
- Schedule is not saved to the database
- Conflict alert remains visible on screen
- User remains on the schedule creation page
- No double-booking has occurred
- System is ready for user to modify the schedule

---

### Test Case: Verify conflict detection response time under 1 second
- **ID:** tc-002
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 30 mins

**Preconditions:**
- Performance testing environment is set up
- User is logged in with Scheduler role permissions
- Scheduling database contains representative test data
- Performance monitoring tools are configured and running
- System logs are enabled and accessible
- Load testing tool is configured for concurrent user simulation
- Baseline system performance metrics are recorded

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open the schedule creation interface and prepare to create a schedule with overlapping resource | Schedule creation form is displayed and ready for input |
| 2 | Start performance timer and enter date, time, and resource that conflicts with an existing booking | All fields are populated with conflicting schedule data |
| 3 | Observe and measure the time from last input field completion to conflict alert display | Conflict alert is displayed within 1 second of completing the resource selection |
| 4 | Record the response time from performance monitoring tool | Response time is logged and shows value less than or equal to 1000 milliseconds |
| 5 | Configure load testing tool to simulate 1000 concurrent users attempting to create overlapping schedules | Load testing tool is configured with 1000 virtual users ready to execute |
| 6 | Execute the load test with all 1000 concurrent users creating conflicting schedules simultaneously | Load test runs successfully with all 1000 users executing schedule creation attempts |
| 7 | Monitor and collect response times for all conflict detection operations during the load test | All conflict detections are processed and response times are recorded for each user |
| 8 | Analyze the collected response time data to verify all responses are within 1 second SLA | 95th percentile response time is at or below 1 second, meeting the performance SLA criteria |
| 9 | Access system logs and filter for conflict detection API calls during the test period | System logs display all conflict detection requests with timestamps |
| 10 | Verify response times in system logs match the performance criteria (under 1 second) | Log entries confirm response times meet performance criteria with timestamps showing sub-second processing |

**Postconditions:**
- Performance test data is saved for analysis
- System logs contain complete performance metrics
- System returns to normal operational state
- No schedules from the test are persisted in the database
- Performance baseline is updated if needed

---

### Test Case: Ensure system supports multiple resource types in conflict detection
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- User is logged in with Scheduler role permissions
- Multiple resource types are configured in the system (e.g., rooms, equipment, personnel)
- Scheduling database contains existing bookings for different resource types
- Schedule creation interface supports all resource types
- At least one resource of each type has existing bookings

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule creation page | Schedule creation form is displayed with resource type selection available |
| 2 | Select 'Room' as the resource type from the resource type dropdown | Resource type is set to 'Room' and available rooms are displayed in the resource dropdown |
| 3 | Enter date and time that conflicts with an existing room booking, then select the conflicting room resource | System immediately displays conflict alert for the room resource with specific conflict details |
| 4 | Clear the form and select 'Equipment' as the resource type | Form is cleared, resource type is set to 'Equipment', and available equipment items are displayed |
| 5 | Enter date and time that conflicts with an existing equipment booking, then select the conflicting equipment resource | System immediately displays conflict alert for the equipment resource with specific conflict details |
| 6 | Clear the form and select 'Personnel' as the resource type | Form is cleared, resource type is set to 'Personnel', and available personnel are displayed |
| 7 | Enter date and time that conflicts with an existing personnel booking, then select the conflicting personnel resource | System immediately displays conflict alert for the personnel resource with specific conflict details |
| 8 | Clear the form and select 'Room' resource type again | Form is cleared and ready for new room schedule input |
| 9 | Enter date, time, and select a room resource that does NOT conflict with any existing bookings | No conflict alert is displayed, form remains in valid state, and Save button is enabled |
| 10 | Repeat step 9 for 'Equipment' resource type with non-conflicting schedule | No conflict alert is displayed for equipment, form is valid, and Save button is enabled |
| 11 | Repeat step 9 for 'Personnel' resource type with non-conflicting schedule | No conflict alert is displayed for personnel, form is valid, and Save button is enabled |
| 12 | Click the 'Save' button to save the valid non-conflicting personnel schedule | Schedule is saved successfully, confirmation message is displayed |
| 13 | Navigate back to schedule creation and create another non-conflicting schedule for a room resource | Schedule creation form is displayed and ready for input |
| 14 | Enter valid non-conflicting room schedule details and click 'Save' | Room schedule is saved successfully with confirmation message displayed |
| 15 | Create a third non-conflicting schedule for an equipment resource and save | Equipment schedule is saved successfully with confirmation message, all three schedules for different resource types are now in the system |

**Postconditions:**
- Three valid schedules are saved in the database (one for each resource type)
- No conflicts exist in the scheduling system
- All resource types have been validated for conflict detection capability
- System is ready for additional schedule creation
- Confirmation messages have been displayed for all successful saves

---

