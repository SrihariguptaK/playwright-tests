@edge-cases @boundary
Feature: As Administrator, I want to perform shift template creation to achieve reusable scheduling. - Edge Case Tests
  As a user
  I want to test edge case tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @medium @tc-edge-001
  Scenario: TC-EDGE-001 - Create shift template with minimum valid time difference (1 minute between start and end)
    Given user is logged in as an Administrator
    And template creation form is open
    And system allows minimum 1-minute shift duration
    When click 'Create New Template' button
    Then template creation form opens
    And enter 'Minimal Shift' as Template Name
    Then template Name field shows 'Minimal Shift'
    And select '09:00 AM' as Start Time and '09:01 AM' as End Time
    Then both time fields populate with 1-minute difference
    And click 'Save Template' button
    Then either: (1) Success message appears and template is created, OR (2) Validation error appears if minimum duration is enforced
    And if saved successfully, verify template in the list
    Then template appears with Start '09:00 AM' and End '09:01 AM'
    And template is saved if system allows 1-minute shifts
    And validation behavior is consistent with business rules
    And template can be used in scheduling if created

  @medium @tc-edge-002
  Scenario: TC-EDGE-002 - Create shift template with maximum valid time span (23 hours 59 minutes)
    Given user is logged in as an Administrator
    And template creation form is open
    And system supports shifts up to 24 hours
    When click 'Create New Template' button
    Then template creation form opens
    And enter 'Maximum Shift' as Template Name
    Then template Name field populates
    And select '12:00 AM' as Start Time and '11:59 PM' as End Time
    Then time fields show nearly 24-hour span
    And add break from '12:00 PM' to '01:00 PM'
    Then break is added successfully
    And click 'Save Template' button
    Then success message appears: 'Template created successfully'
    And verify template in list
    Then 'Maximum Shift' appears with full time span displayed correctly
    And template with maximum duration is saved successfully
    And system handles extreme but valid time spans
    And template is available for scheduling

  @low @tc-edge-003
  Scenario: TC-EDGE-003 - Create shift template with template name at maximum character limit
    Given user is logged in as an Administrator
    And template creation form is open
    And template Name field has a maximum character limit (assume 255 characters)
    When click 'Create New Template' button
    Then template creation form opens
    And enter a 255-character string in Template Name field: 'A' repeated 255 times
    Then field accepts exactly 255 characters and prevents further input, or shows character counter '255/255'
    And enter valid Start Time '08:00 AM' and End Time '05:00 PM'
    Then time fields populate correctly
    And click 'Save Template' button
    Then success message appears and template is created
    And verify template in list
    Then template appears with full name visible or truncated with ellipsis, hovering shows full name in tooltip
    And template is saved with maximum-length name
    And database field accommodates the full name
    And uI handles display of long names appropriately

  @low @tc-edge-004
  Scenario: TC-EDGE-004 - Create shift template with Unicode characters, emojis, and special characters in name
    Given user is logged in as an Administrator
    And template creation form is open
    And system supports UTF-8 character encoding
    When click 'Create New Template' button
    Then template creation form opens
    And enter '早班 Shift 🌅 (Morning)' in Template Name field
    Then field accepts and displays Unicode characters, Chinese characters, and emoji correctly
    And enter Start Time '06:00 AM' and End Time '02:00 PM'
    Then time fields populate correctly
    And click 'Save Template' button
    Then success message appears and template is created
    And verify template in list
    Then template name displays correctly with all Unicode characters and emoji rendered properly
    And refresh the page and verify persistence
    Then template name still displays correctly after page reload
    And template is saved with Unicode characters intact
    And database stores UTF-8 characters correctly
    And uI renders special characters and emojis properly across browsers

  @medium @tc-edge-005
  Scenario: TC-EDGE-005 - Create shift template with break time exactly at shift boundaries
    Given user is logged in as an Administrator
    And template creation form is open
    And system validation allows breaks at shift boundaries
    When click 'Create New Template' button
    Then template creation form opens
    And enter 'Boundary Break Shift' as Template Name, '08:00 AM' as Start Time, '04:00 PM' as End Time
    Then all fields populate correctly
    And add break from '08:00 AM' to '08:15 AM' (starts exactly at shift start)
    Then break is added to the form
    And click 'Save Template' button
    Then either: (1) Success message appears if boundary breaks are allowed, OR (2) Validation error appears: 'Break cannot start at shift start time'
    And if error appears, modify break to '08:01 AM' to '08:15 AM' and save again
    Then template saves successfully with adjusted break time
    And system behavior at boundaries is consistent with business rules
    And validation provides clear guidance on break time constraints
    And template is saved with valid break configuration

  @medium @tc-edge-006
  Scenario: TC-EDGE-006 - Rapidly create multiple templates in quick succession to test concurrent operations
    Given user is logged in as an Administrator
    And user is on the shift template management page
    And system has fewer than 95 templates (room for 5 more)
    When open template creation form and create 'Rapid Test 1' with Start '08:00 AM', End '04:00 PM', click Save
    Then first template saves and success message appears
    And immediately click 'Create New Template' again and create 'Rapid Test 2' with Start '09:00 AM', End '05:00 PM', click Save
    Then second template saves successfully
    And repeat process rapidly for 'Rapid Test 3', 'Rapid Test 4', and 'Rapid Test 5'
    Then all templates are created without errors or race conditions
    And refresh the page and verify all 5 templates appear in the list
    Then all 5 'Rapid Test' templates are present with correct details
    And verify database contains all 5 templates with unique IDs
    Then database shows 5 distinct records with no duplicates or missing entries
    And all 5 templates are successfully created and persisted
    And no race conditions or duplicate entries occurred
    And system handled rapid successive operations correctly
    And database integrity is maintained

  @high @tc-edge-007
  Scenario: TC-EDGE-007 - Create shift template and verify behavior when database connection is temporarily lost during save
    Given user is logged in as an Administrator
    And template creation form is open with valid data entered
    And ability to simulate network/database interruption for testing
    When enter 'Network Test Shift' as Template Name, '10:00 AM' as Start Time, '06:00 PM' as End Time
    Then all fields populate correctly
    And simulate database connection loss or network interruption
    Then database connection is interrupted
    And click 'Save Template' button
    Then error message appears: 'Unable to save template. Please check your connection and try again.' or 'Network error occurred'
    And verify form data is retained
    Then form remains open with all entered data still present (not lost)
    And restore database connection
    Then connection is re-established
    And click 'Save Template' button again
    Then success message appears and template is saved successfully
    And template is saved after connection is restored
    And no duplicate entries were created
    And user data was preserved during the error
    And error handling provided clear feedback to user

