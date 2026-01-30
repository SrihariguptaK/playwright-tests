@edge-cases @boundary
Feature: As Administrator, I want to perform shift template creation to achieve reusable scheduling. - Edge Case Tests
  As a user
  I want to test edge case tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @medium @tc-edge-001
  Scenario: TC-EDGE-001 - Create shift template with minimum valid duration (1 minute)
    Given user is logged in as an Administrator
    And user is on the shift template management page
    And system allows minimum shift duration of 1 minute
    When click 'Create New Template' button
    Then template creation form opens
    And enter 'Minimum Duration Shift' as Template Name
    Then template Name field displays 'Minimum Duration Shift'
    And enter '09:00 AM' as Start Time and '09:01 AM' as End Time (1 minute duration)
    Then start Time shows '09:00 AM' and End Time shows '09:01 AM'
    And click 'Save Template' button
    Then template saves successfully with message 'Shift template created successfully' or validation error appears if minimum duration requirement exists
    And if saved, verify template appears in list with correct duration
    Then template displays with 1-minute duration calculated correctly
    And template is saved if system allows 1-minute shifts, or appropriate validation error is shown
    And system behavior is consistent with business rules for minimum shift duration

  @medium @tc-edge-002
  Scenario: TC-EDGE-002 - Create shift template with maximum valid duration (24 hours)
    Given user is logged in as an Administrator
    And user is on the shift template management page
    And system supports 24-hour shift templates
    When click 'Create New Template' button
    Then template creation form opens
    And enter '24 Hour Shift' as Template Name
    Then template Name field displays '24 Hour Shift'
    And enter '12:00 AM' as Start Time and '11:59 PM' as End Time (23 hours 59 minutes)
    Then start Time shows '12:00 AM' and End Time shows '11:59 PM'
    And add break from '12:00 PM' to '01:00 PM'
    Then break entry appears: '12:00 PM - 01:00 PM'
    And click 'Save Template' button
    Then template saves successfully with message 'Shift template created successfully'
    And verify template in list shows correct duration calculation
    Then template displays with duration of 23 hours 59 minutes or 'Full Day' indicator
    And template '24 Hour Shift' is saved with maximum duration
    And duration calculations are accurate
    And template is available for scheduling

  @medium @tc-edge-003
  Scenario: TC-EDGE-003 - Create shift template with template name containing special characters and Unicode
    Given user is logged in as an Administrator
    And user is on the shift template management page
    And system supports Unicode characters in template names
    When click 'Create New Template' button
    Then template creation form opens
    And enter 'Shift™ @#$% 早班 🌅 Café' in Template Name field (contains trademark symbol, special characters, Chinese characters, emoji, accented characters)
    Then template Name field displays 'Shift™ @#$% 早班 🌅 Café' correctly
    And enter '08:00 AM' as Start Time and '04:00 PM' as End Time
    Then time fields display entered values
    And click 'Save Template' button
    Then template saves successfully with message 'Shift template created successfully'
    And verify template appears in list with all special characters and Unicode displayed correctly
    Then template name 'Shift™ @#$% 早班 🌅 Café' displays correctly without character corruption or encoding issues
    And click to edit the template and verify name is preserved
    Then edit form shows template name exactly as entered with all special characters intact
    And template is saved with Unicode and special characters preserved
    And character encoding is handled correctly throughout the system
    And template name displays consistently across all views

  @medium @tc-edge-004
  Scenario: TC-EDGE-004 - Create shift template with template name at maximum character limit
    Given user is logged in as an Administrator
    And user is on the shift template management page
    And template name field has a maximum character limit (assume 255 characters)
    When click 'Create New Template' button
    Then template creation form opens
    And enter a 255-character string in Template Name field: 'A' repeated 255 times
    Then template Name field accepts exactly 255 characters and prevents entry of 256th character, or shows character counter '255/255'
    And enter '09:00 AM' as Start Time and '05:00 PM' as End Time
    Then time fields display entered values
    And click 'Save Template' button
    Then template saves successfully with message 'Shift template created successfully'
    And verify template appears in list with full name visible or truncated with ellipsis
    Then template appears in list, name is either fully visible with horizontal scroll, or truncated with tooltip showing full name on hover
    And template is saved with maximum length name
    And database stores full 255-character name without truncation
    And uI handles long names gracefully without breaking layout

  @high @tc-edge-005
  Scenario: TC-EDGE-005 - Verify system behavior when exactly 100 templates exist (performance boundary)
    Given user is logged in as an Administrator
    And exactly 100 shift templates exist in the system
    And user is on the shift template management page
    When measure page load time when accessing /admin/shift-templates
    Then page loads within 3 seconds with all 100 templates displayed or paginated
    And scroll through the entire list of templates
    Then scrolling is smooth without lag, all templates render correctly
    And use search/filter functionality if available to find a specific template
    Then search returns results within 1 second
    And click 'Create New Template' button
    Then form opens within 1 second, or system displays message 'Maximum template limit (100) reached. Please delete unused templates before creating new ones.'
    And if creation is blocked, attempt to delete one template and then create a new one
    Then after deletion, creation is allowed and new template saves successfully
    And system maintains performance with 100 templates
    And template limit enforcement is consistent
    And user receives clear feedback about system limits

  @medium @tc-edge-006
  Scenario: TC-EDGE-006 - Create shift template with break time exactly at shift boundaries
    Given user is logged in as an Administrator
    And user is on the shift template management page
    And system allows breaks at shift start or end times
    When click 'Create New Template' button
    Then template creation form opens
    And enter 'Boundary Break Shift' as Template Name, '09:00 AM' as Start Time, '05:00 PM' as End Time
    Then all fields display entered values
    And click 'Add Break' and enter break from '09:00 AM' to '09:15 AM' (starts exactly at shift start time)
    Then break entry appears: '09:00 AM - 09:15 AM'
    And click 'Add Break' and enter another break from '04:45 PM' to '05:00 PM' (ends exactly at shift end time)
    Then second break entry appears: '04:45 PM - 05:00 PM'
    And click 'Save Template' button
    Then template saves successfully, or validation error appears if breaks cannot be at exact boundaries
    And system behavior is consistent with business rules for break placement
    And if saved, breaks at boundaries are stored correctly
    And if rejected, clear validation message explains the constraint

  @medium @tc-edge-007
  Scenario: TC-EDGE-007 - Rapidly create multiple templates in quick succession to test race conditions
    Given user is logged in as an Administrator
    And user is on the shift template management page
    And browser developer tools are open to monitor network requests
    When click 'Create New Template' button and quickly fill in 'Rapid Test 1', Start: '08:00 AM', End: '04:00 PM'
    Then form is filled with values
    And click 'Save Template' button
    Then save request is initiated
    And immediately click 'Create New Template' again before first save completes and fill in 'Rapid Test 2', Start: '09:00 AM', End: '05:00 PM'
    Then second form opens and is filled
    And click 'Save Template' button for second template
    Then second save request is initiated
    And repeat steps 3-4 for 'Rapid Test 3'
    Then third save request is initiated
    And wait for all requests to complete and verify templates list
    Then all three templates ('Rapid Test 1', 'Rapid Test 2', 'Rapid Test 3') appear in the list with correct data, no duplicates, no data corruption
    And verify database contains exactly 3 new templates with unique IDs
    Then database shows 3 distinct templates with no duplicate entries or race condition issues
    And all templates are saved correctly without data loss
    And no race conditions caused duplicate or corrupted data
    And system handles concurrent requests appropriately

