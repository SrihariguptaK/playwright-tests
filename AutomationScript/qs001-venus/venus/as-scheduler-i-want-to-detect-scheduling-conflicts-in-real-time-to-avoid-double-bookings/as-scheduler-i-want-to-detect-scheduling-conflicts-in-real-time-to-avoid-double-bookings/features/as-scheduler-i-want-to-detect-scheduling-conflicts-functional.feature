@functional @smoke
Feature: As Scheduler, I want to detect scheduling conflicts in real-time to avoid double bookings - Functional Tests
  As a user
  I want to test functional tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-func-001
  Scenario: TC-FUNC-001 - Verify real-time conflict detection for overlapping time slots with existing schedule
    Given user is logged in with Scheduler role permissions
    And user is on the scheduling dashboard page
    And existing schedule exists: Resource 'Conference Room A' booked from 10:00 AM to 11:00 AM on current date
    And scheduling database is accessible and responsive
    When click 'Create New Schedule' button in the top-right corner of the dashboard
    Then scheduling form modal opens with empty fields for Resource, Start Time, End Time, and Description
    And select 'Conference Room A' from the Resource dropdown menu
    Then resource field displays 'Conference Room A' as selected
    And enter Start Time as '10:15 AM' and End Time as '11:15 AM' for current date
    Then time fields display entered values with proper formatting
    And click 'Check Availability' button or tab out of the End Time field to trigger real-time validation
    Then red alert banner appears below the form stating 'Conflict Detected: Conference Room A is already booked from 10:00 AM to 11:00 AM' with conflict details and existing booking information
    And navigate to 'Conflict Log' section from the left sidebar menu
    Then conflict log page displays the detected conflict with timestamp, resource name, conflicting time slots, and status 'Detected - Not Resolved'
    And scheduling request is not saved to the database
    And conflict is logged in the conflict_log table with status 'detected'
    And user remains on the scheduling form with conflict alert visible
    And existing schedule for Conference Room A remains unchanged

  @high @tc-func-002
  Scenario: TC-FUNC-002 - Verify successful schedule creation when no conflicts exist
    Given user is logged in with Scheduler role permissions
    And user is on the scheduling dashboard page
    And no existing schedules for 'Conference Room B' between 2:00 PM and 3:00 PM on current date
    And system response time is under 2 seconds for conflict detection
    When click 'Create New Schedule' button in the top-right corner
    Then scheduling form modal opens with all required fields visible
    And select 'Conference Room B' from Resource dropdown, enter Start Time '2:00 PM', End Time '3:00 PM', and Description 'Team Meeting'
    Then all fields display entered values correctly
    And click 'Check Availability' button to trigger real-time conflict detection
    Then green success message appears stating 'No conflicts detected. Resource is available.' within 2 seconds
    And click 'Save Schedule' button at the bottom of the form
    Then success notification 'Schedule created successfully' appears in green banner at top of page, modal closes automatically
    And verify the new schedule appears in the dashboard calendar view for Conference Room B at 2:00 PM - 3:00 PM
    Then schedule entry is visible with correct resource, time, and description details
    And new schedule is saved to scheduling database with status 'active'
    And no conflict log entry is created for this successful scheduling
    And user is returned to the scheduling dashboard with updated calendar view
    And conference Room B shows as booked for the specified time slot

  @high @tc-func-003
  Scenario: TC-FUNC-003 - Verify conflict resolution by modifying scheduling request after conflict detection
    Given user is logged in with Scheduler role permissions
    And existing schedule: 'Projector #1' booked from 1:00 PM to 2:00 PM on current date
    And user has already attempted to book 'Projector #1' from 1:30 PM to 2:30 PM and received conflict alert
    And scheduling form is still open with conflict alert displayed
    When review the conflict alert message displaying 'Conflict Detected: Projector #1 is already booked from 1:00 PM to 2:00 PM'
    Then conflict details are clearly visible with red alert styling and specific time overlap information
    And modify the Start Time field from '1:30 PM' to '2:15 PM' and End Time from '2:30 PM' to '3:15 PM'
    Then time fields update with new values
    And click 'Check Availability' button or tab out of End Time field to re-trigger conflict detection
    Then system re-evaluates the request within 2 seconds and displays green success message 'No conflicts detected. Resource is available.' The red conflict alert disappears
    And click 'Save Schedule' button to confirm the booking
    Then success notification 'Schedule created successfully' appears, modal closes, and new schedule is visible on dashboard
    And navigate to 'Conflict Log' and verify the original conflict entry
    Then conflict log shows the original conflict with status updated to 'Resolved - Time Modified' with timestamp of resolution
    And modified schedule is saved successfully for Projector #1 from 2:15 PM to 3:15 PM
    And original conflict log entry is updated with resolution status and method
    And no active conflicts exist for Projector #1
    And user is on the scheduling dashboard with updated calendar view

  @high @tc-func-004
  Scenario: TC-FUNC-004 - Verify conflict detection for exact time match with existing schedule
    Given user is logged in with Scheduler role permissions
    And existing schedule: 'Meeting Room 3' booked from 9:00 AM to 10:00 AM on current date
    And user is on the scheduling form page
    And conflict detection API endpoint POST /api/schedule/check is operational
    When select 'Meeting Room 3' from Resource dropdown
    Then resource field shows 'Meeting Room 3' as selected
    And enter Start Time as '9:00 AM' and End Time as '10:00 AM' (exact match with existing booking)
    Then time fields display the entered values
    And click 'Check Availability' button to trigger conflict detection
    Then red conflict alert appears stating 'Conflict Detected: Meeting Room 3 is already booked from 9:00 AM to 10:00 AM. This is an exact time match with existing booking.' Response time is under 2 seconds
    And click 'View Conflict Details' link in the alert message
    Then conflict details modal opens showing existing booking information including booker name, purpose, and contact information
    And scheduling request is blocked and not saved
    And conflict is logged with type 'exact_match' in conflict_log table
    And user remains on scheduling form with ability to modify request
    And existing schedule remains unchanged and active

  @medium @tc-func-005
  Scenario: TC-FUNC-005 - Verify conflict detection for partial overlap at the end of existing schedule
    Given user is logged in with Scheduler role permissions
    And existing schedule: 'Training Room A' booked from 3:00 PM to 5:00 PM on current date
    And user is on the scheduling dashboard
    And real-time conflict detection is enabled
    When click 'Create New Schedule' button and open the scheduling form
    Then scheduling form modal opens with empty fields
    And select 'Training Room A' from Resource dropdown, enter Start Time '4:30 PM' and End Time '6:00 PM'
    Then all fields display entered values correctly
    And click 'Check Availability' button to trigger real-time validation
    Then red conflict alert appears: 'Conflict Detected: Training Room A is already booked from 3:00 PM to 5:00 PM. Your requested time (4:30 PM - 6:00 PM) overlaps by 30 minutes.' Alert includes visual timeline showing the overlap
    And click 'Suggest Alternative Times' button in the conflict alert
    Then system displays 3 alternative time slots: '5:00 PM - 6:30 PM', '2:00 PM - 3:30 PM', and '6:00 PM - 7:30 PM' as available options
    And scheduling request is not saved due to detected conflict
    And conflict is logged with overlap details (30 minutes) in the system
    And user can select an alternative time or modify the original request
    And existing Training Room A schedule remains active and unchanged

  @medium @tc-func-006
  Scenario: TC-FUNC-006 - Verify conflict log displays complete history of all detected conflicts with filtering options
    Given user is logged in with Scheduler role permissions
    And at least 5 conflicts have been detected and logged in the system within the past 7 days
    And conflicts include various statuses: 'Detected - Not Resolved', 'Resolved - Time Modified', 'Resolved - Resource Changed'
    And user has access to the Conflict Log section
    When click 'Conflict Log' menu item in the left sidebar navigation
    Then conflict Log page loads displaying a table with columns: Conflict ID, Date/Time, Resource, Requested Time, Conflicting Time, Status, and Actions
    And verify all logged conflicts are displayed in reverse chronological order (newest first)
    Then all 5+ conflicts are visible with complete details including timestamps, resource names, time slots, and current status
    And click on the 'Status' filter dropdown and select 'Detected - Not Resolved'
    Then table updates to show only unresolved conflicts, other conflicts are hidden
    And click 'Export to CSV' button at the top-right of the conflict log table
    Then cSV file downloads containing all filtered conflict records with all column data
    And click on a specific conflict row to view detailed information
    Then conflict details panel expands showing full information: requester name, original request details, conflicting booking details, resolution history, and notes
    And conflict log data remains unchanged after viewing
    And filter selections are maintained during the session
    And cSV export file is saved to user's download folder
    And user remains on the Conflict Log page with ability to perform additional actions

