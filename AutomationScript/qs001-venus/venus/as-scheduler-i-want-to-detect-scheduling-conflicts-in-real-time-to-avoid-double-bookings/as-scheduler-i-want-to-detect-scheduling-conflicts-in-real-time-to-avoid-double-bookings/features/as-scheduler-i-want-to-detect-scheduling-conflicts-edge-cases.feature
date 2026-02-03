@edge-cases @boundary
Feature: As Scheduler, I want to detect scheduling conflicts in real-time to avoid double bookings - Edge Case Tests
  As a user
  I want to test edge case tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-edge-001
  Scenario: TC-EDGE-001 - Verify conflict detection for scheduling request spanning midnight (crosses day boundary)
    Given user is logged in with Scheduler role permissions
    And user is on the scheduling form page
    And no existing schedules for 'Server Room Access' between 11:00 PM today and 2:00 AM tomorrow
    And system supports multi-day scheduling
    When select 'Server Room Access' from Resource dropdown
    Then resource field displays 'Server Room Access'
    And enter Start Time as '11:00 PM' for current date and End Time as '2:00 AM' for next date
    Then system recognizes the time span crosses midnight and displays both dates: 'Start: [Today] 11:00 PM, End: [Tomorrow] 2:00 AM'
    And click 'Check Availability' button to trigger conflict detection
    Then system successfully checks for conflicts across both days and displays 'No conflicts detected. Resource is available for the entire duration (5 hours spanning two days).'
    And click 'Save Schedule' button
    Then schedule is created successfully with proper date/time handling. Success message appears: 'Schedule created for 5 hours from [Today] 11:00 PM to [Tomorrow] 2:00 AM'
    And verify the schedule appears correctly in the calendar view spanning both days
    Then calendar shows the booking starting on current day at 11:00 PM and continuing into the next day until 2:00 AM
    And schedule is saved with correct start and end timestamps across day boundary
    And calendar view correctly displays the multi-day booking
    And future conflict detection properly considers this cross-midnight booking
    And no duplicate entries are created for the two days

  @high @tc-edge-002
  Scenario: TC-EDGE-002 - Verify system handles multiple concurrent scheduling requests for the same resource simultaneously
    Given two or more users are logged in with Scheduler role permissions on different browser sessions
    And all users are attempting to book 'Presentation Equipment Set' for the same time slot
    And database supports transaction locking and race condition handling
    And system has concurrent request handling enabled
    When user A and User B simultaneously open scheduling forms and select 'Presentation Equipment Set' as resource
    Then both users see the resource selected in their respective forms
    And both users enter identical time slots: Start Time '1:00 PM', End Time '2:00 PM' for the same date
    Then both forms display the entered time values
    And both users click 'Check Availability' button within 1 second of each other
    Then both users initially receive 'No conflicts detected' message as the checks happen before either schedule is saved
    And both users click 'Save Schedule' button simultaneously (within milliseconds)
    Then first request to reach the database is processed successfully. Second request is rejected with message: 'Conflict Detected: This resource was just booked by another user. Please check availability again.'
    And user B (who received rejection) clicks 'Check Availability' again
    Then system now shows conflict alert: 'Conflict Detected: Presentation Equipment Set is already booked from 1:00 PM to 2:00 PM by [User A name]'
    And only one schedule is saved in the database for the resource at that time
    And both requests are logged in conflict log with details of the race condition
    And no data corruption or duplicate bookings occur
    And second user is prompted to select alternative time

  @medium @tc-edge-003
  Scenario: TC-EDGE-003 - Verify conflict detection with minimum time duration (1 minute) and maximum duration (24 hours)
    Given user is logged in with Scheduler role permissions
    And user is on the scheduling form page
    And system allows scheduling durations from 1 minute to 24 hours
    And resource 'Quick Access Terminal' is available
    When select 'Quick Access Terminal' from Resource dropdown, enter Start Time '10:00 AM' and End Time '10:01 AM' (1 minute duration)
    Then system accepts the 1-minute duration and displays 'Duration: 1 minute'
    And click 'Check Availability' button
    Then conflict detection processes successfully and returns result within 2 seconds. Message displays 'No conflicts detected' or shows any existing conflicts
    And click 'Save Schedule' button for the 1-minute booking
    Then schedule is saved successfully with message 'Schedule created for 1 minute duration'
    And create a new schedule for 'Data Center Access' with Start Time '12:00 AM' and End Time '11:59 PM' (24 hours minus 1 minute)
    Then system accepts the duration and displays 'Duration: 23 hours 59 minutes'
    And click 'Check Availability' for the 24-hour booking
    Then system successfully checks entire 24-hour period for conflicts and returns results within 2 seconds
    And both extreme duration schedules are saved correctly in the database
    And conflict detection works accurately for both minimum and maximum durations
    And calendar view displays both schedules with appropriate visual representation
    And future conflict checks properly consider these edge-duration bookings

  @high @tc-edge-004
  Scenario: TC-EDGE-004 - Verify conflict detection when scheduling request exactly touches but does not overlap existing schedule
    Given user is logged in with Scheduler role permissions
    And existing schedule: 'Workshop Space' booked from 9:00 AM to 11:00 AM on current date
    And user is on the scheduling form page
    And system defines conflict rules for adjacent time slots
    When select 'Workshop Space' from Resource dropdown
    Then resource field displays 'Workshop Space'
    And enter Start Time as '11:00 AM' (exactly when previous booking ends) and End Time as '1:00 PM'
    Then time fields display the entered values with 'Duration: 2 hours'
    And click 'Check Availability' button to trigger conflict detection
    Then system analyzes the adjacent time slots and displays 'No conflicts detected. Your booking starts immediately after the previous booking ends at 11:00 AM.' Green success message appears
    And click 'Save Schedule' button
    Then schedule is saved successfully with message 'Schedule created successfully. Note: This booking is back-to-back with another booking.'
    And verify calendar view shows both bookings as adjacent without gap or overlap
    Then calendar displays first booking (9:00 AM - 11:00 AM) and second booking (11:00 AM - 1:00 PM) as consecutive blocks with no visual overlap
    And both schedules exist in the database without conflict status
    And no conflict log entry is created for adjacent bookings
    And system correctly interprets that end time of one booking equals start time of next as non-conflicting
    And both bookings are active and valid

  @medium @tc-edge-005
  Scenario: TC-EDGE-005 - Verify conflict detection performance with large dataset of 10,000+ existing schedules
    Given user is logged in with Scheduler role permissions
    And database contains 10,000+ existing schedules across various resources and dates
    And user is on the scheduling form page
    And performance requirement: conflict detection must complete within 2 seconds
    When select any resource from dropdown that has 500+ existing bookings
    Then resource dropdown loads and displays selection within acceptable time
    And enter Start Time and End Time for a date that has 200+ other bookings for various resources
    Then time fields accept input without delay
    And click 'Check Availability' button and start timer to measure response time
    Then system queries the large dataset and returns conflict detection results within 2 seconds. Loading indicator shows progress
    And verify the accuracy of conflict detection result against the large dataset
    Then system correctly identifies any conflicts or confirms availability despite the large number of existing schedules. Result is accurate and complete
    And check system performance metrics and database query logs
    Then database queries are optimized with proper indexing. Query execution time is logged and within acceptable limits. No system slowdown or timeout occurs
    And system performance remains within 2-second requirement even with large dataset
    And database indexes are utilized effectively for quick lookups
    And no memory leaks or performance degradation occurs
    And user experience remains smooth without noticeable delays

  @medium @tc-edge-006
  Scenario: TC-EDGE-006 - Verify conflict detection when user session expires during scheduling process
    Given user is logged in with Scheduler role permissions
    And user is on the scheduling form with partially filled data
    And session timeout is set to expire during the test
    And authentication token expiration is configured
    When select 'Executive Boardroom' from Resource dropdown and enter Start Time '3:00 PM', End Time '5:00 PM'
    Then form fields display entered values correctly
    And wait for session to expire (simulate by clearing authentication token or waiting for timeout period)
    Then session expires but user remains on the form page
    And click 'Check Availability' button after session expiration
    Then system detects expired session and displays modal: 'Your session has expired. Please log in again to continue.' with 'Login' button
    And click 'Login' button in the modal
    Then user is redirected to login page. Form data is preserved in browser session storage with message 'Your unsaved scheduling request will be restored after login'
    And log in again with valid credentials
    Then after successful login, user is redirected back to scheduling form with all previously entered data restored (Resource, Start Time, End Time)
    And user is logged in with new valid session
    And previously entered form data is restored and available
    And user can continue with conflict check and save the schedule
    And no data loss occurs due to session expiration

