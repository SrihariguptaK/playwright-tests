Feature: Schedule Change Request Edge Cases
  As an employee
  I want the schedule change request system to handle edge cases correctly
  So that I can reliably submit requests under various boundary conditions

  Background:
    Given user is logged in as an authenticated employee
    And user is on the schedule change request page

  @edge @regression @priority-medium
  Scenario: System handles Reason field at maximum character limit boundary
    Given "Reason" field has maximum character limit of 500 characters
    And character counter is visible and functional
    When user enters "2024-08-01" in "Date" field
    And user enters "09:00 AM" in "Time" field
    And user enters exactly 500 characters in "Reason" field
    Then "Reason" field should accept all characters
    And character counter should display "500/500 characters" in neutral color
    When user attempts to type additional character beyond limit
    Then "Reason" field should prevent input of additional character
    And character counter should remain at "500/500"
    When user clicks "Submit Request" button
    Then success message "Schedule change request submitted successfully" should be displayed
    When user navigates to "My Requests" page
    And user views the submitted request details
    Then full 500 character reason should be displayed without truncation
    And database field should store all 500 characters without truncation

  @edge @regression @priority-medium
  Scenario: System handles special characters and Unicode in Reason field
    Given system supports UTF-8 character encoding
    And database is configured to store Unicode characters
    When user enters "2024-08-10" in "Date" field
    And user enters "02:00 PM" in "Time" field
    And user enters "Need time for café meeting & discussion about résumé. Cost: $50-$100. Email: test@example.com. Emoji: 😊 ✓ ★" in "Reason" field
    Then "Reason" field should accept all special characters and Unicode symbols
    And all characters should be displayed correctly in field
    When user clicks "Submit Request" button
    Then success message should be displayed
    When user navigates to "My Requests" page
    And user views the submitted request details
    Then reason should display "Need time for café meeting & discussion about résumé. Cost: $50-$100. Email: test@example.com. Emoji: 😊 ✓ ★"
    And database record should contain all special characters correctly encoded

  @edge @regression @priority-high
  Scenario: System prevents duplicate submissions from rapid consecutive clicks
    Given submit button click handler includes debounce mechanism
    And network latency is simulated to be 2 seconds
    When user enters "2024-08-20" in "Date" field
    And user enters "11:00 AM" in "Time" field
    And user enters "Conference attendance required" in "Reason" field
    And user rapidly clicks "Submit Request" button 5 times within 1 second
    Then "Submit Request" button should become disabled after first click
    And loading spinner with text "Submitting..." should be displayed
    And subsequent clicks should have no effect
    When user waits for API response to complete
    Then success message "Schedule change request submitted successfully. Request ID: SCR-12348" should be displayed
    And only one record should be created in database
    And server logs should show only one POST request to "/api/scheduleChangeRequests"

  @edge @regression @priority-low
  Scenario: System handles schedule change request submission at exactly midnight
    Given system time is set to "23:59:50"
    And time picker allows selection of midnight
    When user enters "2024-09-01" in "Date" field
    And user selects "12:00 AM" from "Time" picker
    And user enters "Night shift coverage needed" in "Reason" field
    And user waits until system clock reaches "00:00:00"
    And user clicks "Submit Request" button
    Then success message should be displayed
    When user navigates to "My Requests" page
    And user views the submitted request details
    Then request should be saved with correct date
    And time should display "12:00 AM"
    And submission timestamp should reflect correct date transition
    And database should contain accurate submission time

  @edge @regression @priority-medium
  Scenario: System handles browser back button after successful submission
    Given user has successfully submitted a schedule change request
    And user is on confirmation page showing "Schedule change request submitted successfully. Request ID: SCR-12349"
    And browser history contains the form page
    When user clicks browser back button
    Then user should be navigated to schedule change request form page
    And all form fields should be cleared
    And informational message "Your previous request (SCR-12349) was submitted successfully. You can submit a new request below." should be displayed
    When user enters "2024-08-25" in "Date" field
    And user enters "03:00 PM" in "Time" field
    And user enters "Additional schedule adjustment needed" in "Reason" field
    And user clicks "Submit Request" button
    Then success message with different request ID "SCR-12350" should be displayed
    When user navigates to "My Requests" page
    Then request "SCR-12349" should be listed with status "Pending Approval"
    And request "SCR-12350" should be listed with status "Pending Approval"
    And both requests should exist as separate entries