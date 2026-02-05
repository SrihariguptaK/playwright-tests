Feature: Schedule Review Cycles for Timely Performance Evaluations
  As a Performance Manager
  I want to schedule review cycles with clear feedback and error prevention
  So that I can maintain timely performance evaluations without scheduling conflicts

  Background:
    Given user is logged in as "Performance Manager"
    And user has permissions to schedule review cycles
    And review cycle management page is accessible

  @usability @functional @priority-critical @smoke
  Scenario: System provides clear feedback during review cycle scheduling process
    Given at least one team or department is available for scheduling
    When user navigates to "Review Cycle Management" page
    Then loading indicator should be displayed during page load
    And page should load within 2 seconds
    And clear indication should be displayed when page is ready
    When user selects "Quarterly" from "Review Cycle Frequency" dropdown
    And user fills in all required fields
    Then form fields should provide visual feedback as user interacts with them
    And validation icons should be displayed on form fields
    When user clicks "Save" button
    Then "Save" button should show loading state
    And "Saving..." text should be displayed during processing
    And "Save" button should be disabled during processing
    When save operation completes
    Then success message "Review cycle scheduled successfully" should be displayed
    And scheduled cycle frequency should be displayed in success message
    And scheduled cycle start date should be displayed in success message
    And scheduled cycle next review date should be displayed in success message
    And newly scheduled review cycle should appear immediately in calendar view
    And scheduled review cycle should have visual distinction in calendar view
    And scheduled review cycle should have color coding in calendar view

  @usability @negative @priority-critical @error-prevention
  Scenario: Past dates are disabled in date picker to prevent invalid scheduling
    Given at least one existing review cycle is already scheduled
    And system validation rules are active
    When user opens date picker for "Start Date" field
    Then past dates should be disabled in date picker
    And past dates should be grayed out in date picker

  @usability @negative @priority-critical @error-prevention
  Scenario: System prevents overlapping review cycles with inline warning
    Given at least one existing review cycle is already scheduled
    And system validation rules are active
    And existing review cycle is scheduled from "2024-01-01" to "2024-03-31" for "Engineering Team"
    When user selects "Engineering Team" from "Team" dropdown
    And user selects date range that overlaps with existing review cycle
    Then inline warning message "This period overlaps with existing review cycle (Jan 1 - Mar 31)" should be displayed immediately
    And conflicting dates should be highlighted in calendar view

  @usability @negative @priority-critical @error-prevention
  Scenario: Save button remains disabled until all required fields are completed
    Given at least one existing review cycle is already scheduled
    And system validation rules are active
    When user is on review cycle scheduling form
    And required fields are not filled
    Then "Save" button should be disabled
    And required fields should have asterisk indicators
    And required fields should have visual border indicators

  @usability @negative @priority-critical @error-prevention
  Scenario: End date picker prevents selection of dates before start date
    Given at least one existing review cycle is already scheduled
    And system validation rules are active
    When user selects "2024-06-01" in "Start Date" field
    And user opens "End Date" date picker
    Then end date picker should show only dates after "2024-06-01"

  @usability @negative @priority-critical @error-prevention
  Scenario: System warns when scheduling exceeds recommended concurrent review cycles
    Given at least one existing review cycle is already scheduled
    And system validation rules are active
    And "Engineering Team" already has 4 concurrent review cycles scheduled
    When user attempts to schedule 5th concurrent review cycle for "Engineering Team"
    Then warning message "Maximum 4 concurrent review cycles recommended. This may impact performance evaluation quality." should be displayed
    And "Proceed" button should be visible
    And "Cancel" button should be visible

  @usability @functional @priority-high @user-control
  Scenario: User can edit existing scheduled review cycle with pre-populated values
    Given at least two review cycles are already scheduled
    And user has edit and delete permissions
    When user clicks "Edit" button on existing scheduled review cycle
    Then edit form should open with current values pre-populated
    And "Cancel" button should be clearly visible
    And "Save Changes" button should be clearly visible
    When user modifies "Review Cycle Frequency" from "Quarterly" to "Monthly"
    And user clicks "Cancel" button
    Then system should return to previous view without saving changes

  @usability @functional @priority-high @user-control
  Scenario: User can undo changes immediately after saving review cycle
    Given at least two review cycles are already scheduled
    And user has edit and delete permissions
    When user clicks "Edit" button on existing scheduled review cycle
    And user modifies "Review Cycle Frequency" from "Quarterly" to "Monthly"
    And user clicks "Save Changes" button
    Then success message should be displayed
    And "Undo" link should be displayed in success message
    And "Undo" option should be available for 10 seconds

  @usability @functional @priority-high @user-control
  Scenario: System confirms deletion with clear dialog and undo option
    Given at least two review cycles are already scheduled
    And user has edit and delete permissions
    And scheduled review cycle "Quarterly Review - Engineering Team" exists
    When user clicks "Delete" button on scheduled review cycle
    Then confirmation dialog should appear
    And confirmation message "Are you sure you want to delete this review cycle? This action will remove [Quarterly Review - Engineering Team]. You can reschedule anytime." should be displayed
    And "Cancel" button should be displayed as default action
    And "Delete" button should be displayed
    When user clicks "Delete" button in confirmation dialog
    Then success message "Review cycle deleted. Undo" should be displayed
    And "Undo" option should be available for 10 seconds

  @usability @functional @priority-high @user-control
  Scenario: System prompts user when leaving page with unsaved changes
    Given at least two review cycles are already scheduled
    And user has edit and delete permissions
    When user is on review cycle scheduling form
    And user fills in "Review Cycle Frequency" field
    And user has unsaved changes
    And user presses browser back button
    Then prompt "You have unsaved changes. Leave page?" should be displayed
    And "Stay" button should be visible
    And "Leave" button should be visible