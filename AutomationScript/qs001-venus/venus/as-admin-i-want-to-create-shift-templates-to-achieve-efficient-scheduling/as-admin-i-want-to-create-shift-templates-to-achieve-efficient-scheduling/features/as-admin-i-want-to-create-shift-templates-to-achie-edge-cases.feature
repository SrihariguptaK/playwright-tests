@edge-cases @boundary
Feature: As Admin, I want to create shift templates to achieve efficient scheduling. - Edge Case Tests
  As a user
  I want to test edge case tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @medium @tc-edge-001
  Scenario: TC-EDGE-001 - Verify template creation with start and end times at midnight boundary (00:00)
    Given user is logged in with Admin-level authentication
    And user is on the Shift Template management page
    And template creation form is open
    And system supports 24-hour time format and midnight time values
    When click on 'Create New Template' button
    Then template creation form modal opens
    And enter 'Midnight Shift' in Template Name field
    Then template Name field accepts the input
    And enter '11:00 PM' (23:00) in Start Time field
    Then start Time field displays '11:00 PM' correctly
    And enter '12:00 AM' (00:00) in End Time field (next day midnight)
    Then end Time field displays '12:00 AM', system recognizes this as next day
    And select role 'Security Guard' and click 'Save Template' button
    Then success message appears, template is saved with correct time span crossing midnight
    And verify template displays correctly showing 1-hour duration from 11:00 PM to 12:00 AM
    Then template shows correct duration calculation, handles day boundary properly
    And template 'Midnight Shift' is saved with start time 23:00 and end time 00:00 (next day)
    And system correctly calculates shift duration as 1 hour spanning midnight
    And template can be assigned to employees and displays correctly on schedules
    And date/time handling properly manages day transitions

  @medium @tc-edge-002
  Scenario: TC-EDGE-002 - Verify template creation with maximum allowed character length in template name
    Given user is logged in with Admin-level authentication
    And user is on the Shift Template management page
    And template Name field has maximum character limit (assume 100 characters)
    And template creation form is open
    When click on 'Create New Template' button
    Then template creation form modal opens
    And enter exactly 100 characters in Template Name field: 'This is a very long template name designed to test the maximum character limit boundary for shift templates'
    Then field accepts exactly 100 characters, character counter shows '100/100' if present
    And enter valid Start Time '09:00 AM' and End Time '05:00 PM'
    Then time fields accept valid values without errors
    And select role 'Manager' and click 'Save Template' button
    Then success message appears, template is saved successfully
    And verify template appears in list with full name displayed or truncated with ellipsis
    Then template is visible in list, name is either fully displayed or truncated with tooltip showing full name on hover
    And attempt to enter 101 characters in a new template name
    Then field prevents input beyond 100 characters or displays validation error 'Maximum 100 characters allowed'
    And template with 100-character name is saved correctly in database
    And database field accommodates maximum length without truncation
    And uI handles long names gracefully with proper display formatting
    And character limit validation prevents exceeding maximum length

  @medium @tc-edge-003
  Scenario: TC-EDGE-003 - Verify system performance when creating 100 shift templates concurrently
    Given 100 admin users are logged in simultaneously (or simulation of concurrent requests)
    And system performance requirements specify handling 100 concurrent template creations
    And database connection pool is configured for high concurrency
    And load testing tools are available to simulate concurrent requests
    When set up load testing tool to simulate 100 concurrent POST requests to /api/shifts/templates
    Then load testing tool is configured with 100 virtual users ready to execute
    And each virtual user submits valid template data with unique names (Template_001 through Template_100)
    Then all 100 requests are sent simultaneously to the server
    And monitor server response times and success rates
    Then all 100 requests complete within acceptable time frame (e.g., under 5 seconds), no timeouts occur
    And verify all 100 templates are created successfully in the database
    Then database query shows exactly 100 new templates with unique names, no duplicates or missing records
    And check for any database deadlocks or connection pool exhaustion
    Then no database errors logged, connection pool handles concurrent writes efficiently
    And verify system remains responsive for other operations during concurrent load
    Then other admin users can still access and use the system without performance degradation
    And all 100 shift templates are successfully created in ShiftTemplates table
    And system performance meets specified requirements for concurrent operations
    And no data corruption or race conditions occurred during concurrent writes
    And system logs show successful handling of high concurrency load

  @medium @tc-edge-004
  Scenario: TC-EDGE-004 - Verify template creation with special characters and Unicode in template name
    Given user is logged in with Admin-level authentication
    And user is on the Shift Template management page
    And template creation form is open
    And system supports UTF-8 character encoding
    When click on 'Create New Template' button
    Then template creation form modal opens
    And enter template name with special characters and Unicode: 'Shift™ Café-Mañana 早班 🌅'
    Then field accepts all characters including trademark symbol, accented characters, Chinese characters, and emoji
    And enter valid Start Time '08:00 AM' and End Time '04:00 PM'
    Then time fields accept valid values
    And select role 'Barista' and click 'Save Template' button
    Then success message appears, template is saved without character encoding errors
    And verify template appears in list with all special characters and Unicode displayed correctly
    Then template name 'Shift™ Café-Mañana 早班 🌅' is displayed exactly as entered with proper character rendering
    And edit the template and verify special characters are preserved in edit form
    Then edit form shows template name with all special characters intact and editable
    And template is saved in database with UTF-8 encoding preserving all special characters
    And template name displays correctly across all UI components
    And special characters do not cause rendering issues or data corruption
    And template can be edited and deleted without character encoding problems

  @low @tc-edge-005
  Scenario: TC-EDGE-005 - Verify template creation with 1-minute shift duration (minimum valid duration)
    Given user is logged in with Admin-level authentication
    And user is on the Shift Template management page
    And template creation form is open
    And system allows minimum shift duration of 1 minute
    When click on 'Create New Template' button
    Then template creation form modal opens
    And enter 'Micro Shift' in Template Name field
    Then template Name field accepts the input
    And enter '09:00 AM' in Start Time field
    Then start Time field displays '09:00 AM'
    And enter '09:01 AM' in End Time field (1 minute duration)
    Then end Time field displays '09:01 AM', no validation error appears
    And select role 'Tester' and click 'Save Template' button
    Then success message appears, template is saved with 1-minute duration
    And verify template displays correctly showing 1-minute duration
    Then template shows duration as '1 minute' or '0.02 hours', system handles minimum duration correctly
    And template 'Micro Shift' is saved with 1-minute duration
    And system correctly calculates and displays minimum shift duration
    And template can be assigned to employees despite short duration
    And no validation errors occur for minimum valid duration

  @medium @tc-edge-006
  Scenario: TC-EDGE-006 - Verify template creation with 24-hour shift duration (maximum single-day duration)
    Given user is logged in with Admin-level authentication
    And user is on the Shift Template management page
    And template creation form is open
    And system supports shifts up to 24 hours in duration
    When click on 'Create New Template' button
    Then template creation form modal opens
    And enter 'Full Day Shift' in Template Name field
    Then template Name field accepts the input
    And enter '12:00 AM' (00:00) in Start Time field
    Then start Time field displays '12:00 AM'
    And enter '11:59 PM' (23:59) in End Time field
    Then end Time field displays '11:59 PM', system accepts 23 hour 59 minute duration
    And select role 'On-Call Manager' and click 'Save Template' button
    Then success message appears, template is saved with maximum single-day duration
    And verify template displays correctly showing approximately 24-hour duration
    Then template shows duration as '23 hours 59 minutes' or '23.98 hours', system handles maximum duration correctly
    And template 'Full Day Shift' is saved with 23:59 duration
    And system correctly handles maximum single-day shift duration
    And template can be assigned to employees for full-day coverage
    And duration calculations are accurate for extended shifts

