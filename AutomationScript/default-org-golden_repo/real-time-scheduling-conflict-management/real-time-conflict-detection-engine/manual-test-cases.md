# Manual Test Cases

## Story: As Scheduler, I want to receive immediate alerts for overlapping appointments to avoid double bookings
**Story ID:** story-1

### Test Case: Validate real-time detection of overlapping appointments
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Scheduler role
- Scheduling database is accessible and populated with existing appointments
- At least one existing appointment is present in the system (e.g., Room A booked from 10:00 AM to 11:00 AM)
- Appointment creation page is accessible
- User has necessary permissions to create appointments

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the appointment creation page by clicking on 'Create Appointment' button or menu option | Appointment creation form is displayed with all required fields: date, time, duration, resource type, resource name, and description |
| 2 | Enter appointment details that overlap with an existing appointment: select date matching existing appointment, enter start time that overlaps (e.g., 10:30 AM if existing is 10:00-11:00 AM), select duration (e.g., 1 hour), and select the same resource (e.g., Room A) | Real-time alert is displayed immediately showing conflict message with details: 'Conflict Detected: This appointment overlaps with existing appointment in Room A from 10:00 AM to 11:00 AM' |
| 3 | Attempt to save the appointment by clicking 'Save' or 'Submit' button without resolving the conflict | System prevents the save operation and displays a confirmation prompt: 'This appointment conflicts with an existing booking. Do you want to override and create anyway?' with options to 'Cancel' or 'Override and Save' |

**Postconditions:**
- Conflicting appointment is not saved to the database unless override is confirmed
- Alert message remains visible until user takes action
- Existing appointment data remains unchanged
- User remains on the appointment creation page

---

### Test Case: Verify conflict detection latency under 1 second
- **ID:** tc-002
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- User is logged in with Scheduler role
- Scheduling database contains existing appointments
- Performance monitoring tool or browser developer tools are available to measure response time
- Network connection is stable
- System is under normal load conditions

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open browser developer tools and navigate to Network tab to monitor API calls and response times | Developer tools are open and ready to capture network activity with timestamp information |
| 2 | Input appointment details that trigger a conflict: enter date, time overlapping with existing appointment, and resource that matches existing booking, then note the exact timestamp when the last field is completed | Conflict detection API call (POST /appointments/check-conflict) is triggered and alert appears on screen within 1 second of completing the input |
| 3 | Measure and record the time difference between the API request initiation and alert display by reviewing the network timeline in developer tools | Measured latency from input completion to alert display is less than 1 second (< 1000ms), confirming system meets performance requirement |

**Postconditions:**
- Performance metrics are documented
- Alert was displayed within acceptable time frame
- System responsiveness meets the 1-second requirement
- No performance degradation observed

---

### Test Case: Ensure conflict detection supports multiple resource types
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role
- Scheduling database contains existing appointments for different resource types
- At least one existing appointment with personnel resource (e.g., Dr. Smith booked 2:00 PM - 3:00 PM)
- At least one existing appointment with room resource (e.g., Conference Room B booked 3:00 PM - 4:00 PM)
- Multiple resource types are configured in the system (personnel, rooms, equipment)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to appointment creation page and select 'Personnel' as resource type from dropdown | Resource type is set to 'Personnel' and personnel list is displayed in resource selection dropdown |
| 2 | Create an appointment with personnel resource conflict: select date, enter time overlapping with existing personnel appointment (e.g., 2:30 PM - 3:30 PM), and select the same personnel (e.g., Dr. Smith) | Conflict alert is displayed immediately with message: 'Conflict Detected: Dr. Smith is already scheduled from 2:00 PM to 3:00 PM' including personnel resource details |
| 3 | Clear the form or navigate back to appointment creation page, then select 'Room' as resource type from dropdown | Resource type is changed to 'Room' and room list is displayed in resource selection dropdown, previous conflict alert is cleared |
| 4 | Create an appointment with room resource conflict: select date, enter time overlapping with existing room appointment (e.g., 3:15 PM - 4:15 PM), and select the same room (e.g., Conference Room B) | Conflict alert is displayed immediately with message: 'Conflict Detected: Conference Room B is already booked from 3:00 PM to 4:00 PM' including room resource details |

**Postconditions:**
- Conflict detection functionality is confirmed for personnel resource type
- Conflict detection functionality is confirmed for room resource type
- No conflicting appointments are saved
- System demonstrates support for multiple resource types as required

---

## Story: As Scheduler, I want to receive alerts for double bookings to maintain schedule accuracy
**Story ID:** story-2

### Test Case: Validate detection of double bookings in real-time
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- User is logged in with Scheduler role
- Booking database is accessible and contains existing bookings
- At least one existing booking is present (e.g., Customer A booked for Service X at 1:00 PM on current date)
- Booking creation page is functional and accessible
- User has permissions to create bookings

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the booking creation page by selecting 'Create New Booking' from the main menu or dashboard | Booking creation form is displayed with all required fields visible: customer name, service type, date, time, duration, and booking category |
| 2 | Enter booking details that cause a double booking: select the same customer (Customer A), same service (Service X), same date, and overlapping time (e.g., 1:30 PM) with existing booking at 1:00 PM | Alert is displayed immediately upon entering the conflicting details with message: 'Double Booking Detected: Customer A already has a booking for Service X at 1:00 PM on this date' |
| 3 | Attempt to save the booking by clicking the 'Save Booking' or 'Submit' button without resolving the alert or modifying the booking details | System blocks the save operation and displays confirmation dialog: 'Warning: This creates a double booking. Are you sure you want to proceed?' with 'Cancel' and 'Confirm Override' buttons |

**Postconditions:**
- Double booking is not saved unless user explicitly confirms override
- Alert remains visible until user takes corrective action
- Existing booking data remains intact and unchanged
- User is kept on the booking creation page to make adjustments

---

### Test Case: Verify alert latency is under 1 second
- **ID:** tc-005
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- User is logged in with Scheduler role
- Booking database contains existing bookings to test against
- Browser developer tools or performance monitoring tool is available
- System is operating under normal load
- Network latency is within acceptable range

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open browser developer tools, navigate to Network tab, and prepare to monitor API response times for the double booking check endpoint (POST /bookings/check-double-booking) | Developer tools are active and network monitoring is enabled, showing timestamp information for all requests |
| 2 | Input conflicting booking details that will trigger double booking detection: enter customer name, service, date, and time that matches an existing booking, then record the timestamp when the final field loses focus or is completed | Alert appears on screen within 1 second of completing the input, displaying double booking warning message. Network tab shows API call completed with response time under 1000ms |

**Postconditions:**
- Alert latency is confirmed to be under 1 second
- Performance requirement is validated and documented
- System demonstrates acceptable responsiveness
- API response time metrics are recorded for future reference

---

### Test Case: Ensure detection supports all booking categories
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Scheduler role
- Booking database contains existing bookings across multiple categories
- Multiple booking categories are configured (e.g., Consultation, Treatment, Follow-up, Emergency)
- At least one existing booking exists for each category to test against
- Booking creation interface supports category selection

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to booking creation page and select first booking category 'Consultation' from the category dropdown menu | Category is set to 'Consultation' and form displays relevant fields for this booking type |
| 2 | Create a booking with details that conflict with an existing 'Consultation' booking: enter customer name, date, and time that overlaps with existing consultation booking | Alert is generated immediately displaying: 'Double Booking Detected: Consultation booking already exists for this customer at this time' with conflict details |
| 3 | Clear the form or create a new booking, then select second booking category 'Treatment' from the category dropdown | Category is changed to 'Treatment', form updates to show treatment-specific fields, and previous alert is cleared |
| 4 | Create a booking with details that conflict with an existing 'Treatment' booking: enter customer name, date, and time that overlaps with existing treatment booking | Alert is generated immediately displaying: 'Double Booking Detected: Treatment booking already exists for this customer at this time' with conflict details |
| 5 | Repeat the process for remaining booking categories (Follow-up, Emergency) by selecting each category and entering conflicting booking details | Alerts are generated for each booking category conflict, confirming that double booking detection works across all configured booking categories |

**Postconditions:**
- Double booking detection is confirmed functional for all booking categories
- No double bookings are saved to the system
- System demonstrates comprehensive category support
- All booking categories maintain data integrity

---

## Story: As Scheduler, I want the system to detect resource unavailability conflicts in real-time to prevent scheduling errors
**Story ID:** story-6

### Test Case: Validate detection of resource unavailability conflicts
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least one resource is marked as unavailable in the system
- Resource availability database is accessible
- Scheduling page is accessible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduling page | Scheduling form is displayed with all required fields including resource selection dropdown |
| 2 | Fill in appointment date and time fields | Date and time fields are populated successfully |
| 3 | Select a resource that is marked as unavailable from the resource dropdown | Real-time alert is displayed indicating the resource is unavailable with specific unavailability details (reason, duration) |
| 4 | Verify the alert message contains resource name, unavailability reason, and time period | Alert displays complete resource unavailability information including resource name, reason (maintenance/leave), and unavailability period |
| 5 | Attempt to save the appointment with the unavailable resource without override | System blocks the save operation and displays a validation message preventing appointment creation |
| 6 | Click on override option (if available) and confirm the override action | System prompts for override confirmation with warning message |
| 7 | Confirm the override and save the appointment | Appointment is saved successfully with override flag and confirmation message is displayed |

**Postconditions:**
- Alert for resource unavailability was displayed correctly
- System prevented save without override
- Appointment is saved only after override confirmation
- Audit log records the override action

---

### Test Case: Verify alert latency under 1 second
- **ID:** tc-002
- **Type:** boundary
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- User is logged in with Scheduler role
- At least one resource is marked as unavailable
- Scheduling page is loaded
- Timer or performance monitoring tool is available
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduling page and prepare to measure response time | Scheduling form is displayed and ready for input |
| 2 | Start timer and input appointment date and time | Date and time fields are populated |
| 3 | Select a resource marked as unavailable and stop timer when alert appears | Alert appears within 1 second of resource selection, displaying resource unavailability conflict message |
| 4 | Record the exact time taken for alert to appear | Measured latency is less than or equal to 1000 milliseconds |
| 5 | Repeat the test with different unavailable resources (minimum 3 iterations) | All iterations show alert latency under 1 second consistently |
| 6 | Verify alert content is complete and not truncated due to speed optimization | Alert contains all required information: resource name, unavailability reason, and time period |

**Postconditions:**
- Alert latency is verified to be under 1 second
- Performance metrics are documented
- System maintains data integrity while meeting performance requirements

---

### Test Case: Ensure detection supports all resource types
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- User is logged in with Scheduler role
- Multiple resource categories exist in the system (e.g., rooms, equipment, personnel, vehicles)
- At least one resource from each category is marked as unavailable
- Scheduling page is accessible
- Resource availability database contains all resource types

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduling page | Scheduling form is displayed with resource category selection options |
| 2 | Select 'Room' as resource category and choose a room marked as unavailable | Real-time alert is generated displaying room unavailability conflict with specific details |
| 3 | Clear the selection and select 'Equipment' as resource category, then choose equipment marked as unavailable | Real-time alert is generated displaying equipment unavailability conflict with maintenance or usage details |
| 4 | Clear the selection and select 'Personnel' as resource category, then choose personnel marked as unavailable | Real-time alert is generated displaying personnel unavailability conflict with leave or absence details |
| 5 | Clear the selection and select 'Vehicle' as resource category, then choose a vehicle marked as unavailable | Real-time alert is generated displaying vehicle unavailability conflict with maintenance or assignment details |
| 6 | Verify each alert contains category-specific unavailability information | All alerts display appropriate details relevant to their resource category (maintenance schedules, leave dates, etc.) |
| 7 | Attempt to save appointments with each unavailable resource type | System consistently blocks save operation for all resource categories unless override is confirmed |
| 8 | Test with available resources from each category | No alerts are generated and appointments can be saved successfully for available resources |

**Postconditions:**
- All resource categories show proper conflict detection
- Alerts are generated consistently across all resource types
- System prevents scheduling conflicts for all resource categories
- Available resources can be scheduled without restrictions

---

