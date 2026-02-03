@edge-cases @boundary
Feature: As Administrator, I want to perform shift template creation to achieve reusable scheduling. - Edge Case Tests
  As a user
  I want to test edge case tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @medium @tc-edge-001
  Scenario: TC-EDGE-001 - Verify shift template creation with maximum allowed duration (24 hours)
    Given user is logged in as Administrator
    And user is on the shift template creation page
    And system allows maximum shift duration of 24 hours
    And no template named '24 Hour Shift' exists
    When click 'Create New Template' button
    Then template creation form opens
    And enter '24 Hour Shift' as Template Name, '12:00 AM' as Start Time, and '11:59 PM' as End Time
    Then all fields accept the input without validation errors
    And add break time from '12:00 PM' to '01:00 PM'
    Then break is added successfully within the 24-hour shift
    And click 'Save Template' button
    Then success message appears and template is created with 23 hours 59 minutes duration
    And verify template appears in list with correct duration displayed
    Then template shows full day duration and is available for scheduling
    And template is saved with maximum duration in database
    And template can be assigned to schedules without errors
    And duration calculations are accurate for reporting

  @medium @tc-edge-002
  Scenario: TC-EDGE-002 - Verify shift template creation with special characters and Unicode in template name
    Given user is logged in as Administrator
    And user is on the shift template creation page
    And system supports UTF-8 character encoding
    And database can store Unicode characters
    When click 'Create New Template' button
    Then template creation form is displayed
    And enter 'Shift™ @#$% & 日本語 🌟' in Template Name field (includes trademark symbol, special chars, Japanese characters, and emoji)
    Then template Name field accepts all characters and displays them correctly
    And enter valid Start Time '09:00 AM' and End Time '05:00 PM'
    Then times are accepted without errors
    And click 'Save Template' button
    Then template is saved successfully with message 'Shift template created successfully'
    And verify template name displays correctly in the list with all special characters and Unicode intact
    Then template name 'Shift™ @#$% & 日本語 🌟' is displayed exactly as entered without corruption
    And template is stored in database with correct Unicode encoding
    And special characters and emoji render correctly across all views
    And template can be edited and deleted without character encoding issues

  @high @tc-edge-003
  Scenario: TC-EDGE-003 - Verify system behavior when creating the 100th shift template (performance limit)
    Given user is logged in as Administrator
    And exactly 99 shift templates already exist in the system
    And system performance requirement states handling up to 100 templates without degradation
    And user is on the shift template creation page
    When click 'Create New Template' button
    Then form loads within 2 seconds without performance issues
    And enter 'Template 100' as name, '08:00 AM' as Start Time, '04:00 PM' as End Time
    Then all fields accept input normally
    And click 'Save Template' button and measure response time
    Then template is created successfully within 3 seconds and success message appears
    And navigate to template list and verify all 100 templates load
    Then list loads within 5 seconds showing all 100 templates with pagination working correctly
    And attempt to create the 101st template
    Then either template is created (if limit is soft) or warning message appears: 'Maximum template limit reached. Consider archiving unused templates.'
    And system maintains performance with 100 templates loaded
    And all CRUD operations continue to function within acceptable time limits
    And database queries remain optimized

  @medium @tc-edge-004
  Scenario: TC-EDGE-004 - Verify shift template with break time exactly at shift boundaries (start or end)
    Given user is logged in as Administrator
    And user is on shift template creation page
    And template has Start Time '09:00 AM' and End Time '05:00 PM'
    And system validation rules for break boundaries are active
    When enter 'Boundary Break Shift' as Template Name
    Then name is accepted
    And add break time from '09:00 AM' to '09:15 AM' (starts exactly at shift start time)
    Then system either accepts the break or shows validation: 'Break cannot start at shift start time' depending on business rules
    And remove previous break and add break from '04:45 PM' to '05:00 PM' (ends exactly at shift end time)
    Then system either accepts the break or shows validation: 'Break cannot end at shift end time' depending on business rules
    And attempt to save the template
    Then template saves if breaks at boundaries are allowed, or error prevents saving with clear message about boundary rules
    And system behavior is consistent with documented business rules for break boundaries
    And if saved, template functions correctly in scheduling workflows
    And validation messages clearly communicate boundary rules to users

  @low @tc-edge-005
  Scenario: TC-EDGE-005 - Verify shift template creation with extremely long template name (boundary testing)
    Given user is logged in as Administrator
    And user is on shift template creation page
    And template Name field has a maximum character limit (e.g., 255 characters)
    And character counter is displayed on the form
    When click 'Create New Template' button
    Then form opens with empty Template Name field showing '0/255 characters'
    And enter a 255-character string in Template Name field: 'A' repeated 255 times
    Then field accepts exactly 255 characters and shows '255/255 characters', no validation error
    And attempt to enter the 256th character
    Then field prevents input beyond 255 characters or shows validation error: 'Template name cannot exceed 255 characters'
    And enter valid Start Time '09:00 AM' and End Time '05:00 PM', then click Save
    Then template is saved successfully with the 255-character name
    And verify template appears in list with name truncated or displayed with ellipsis if needed
    Then template name is displayed appropriately (truncated with '...' or in tooltip) without breaking UI layout
    And template is saved with full 255-character name in database
    And uI handles long names gracefully without layout issues
    And template can be edited and deleted normally

  @high @tc-edge-006
  Scenario: TC-EDGE-006 - Verify shift template creation across midnight (spanning two calendar days)
    Given user is logged in as Administrator
    And user is on shift template creation page
    And system supports overnight shifts that cross midnight
    And no template named 'Overnight Shift' exists
    When click 'Create New Template' button
    Then template creation form is displayed
    And enter 'Overnight Shift' as Template Name, '11:00 PM' as Start Time, and '07:00 AM' as End Time (next day)
    Then system accepts the times and calculates 8-hour duration correctly, or shows date picker to clarify next-day end time
    And add break time from '03:00 AM' to '03:30 AM' (during overnight hours)
    Then break is added successfully and validated as within shift hours
    And click 'Save Template' button
    Then template is saved with success message, duration calculated as 8 hours
    And verify template in list shows correct duration and time span
    Then template displays '11:00 PM - 07:00 AM (next day)' or similar notation indicating overnight shift
    And template correctly handles date transition in database
    And scheduling system can assign overnight shifts without errors
    And time calculations for payroll and reporting are accurate

