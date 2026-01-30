@edge-cases @boundary
Feature: As Administrator, I want to perform shift template creation to achieve reusable scheduling. - Edge Case Tests
  As a user
  I want to test edge case tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @medium @tc-edge-001
  Scenario: TC-EDGE-001 - Verify system handles template creation at exact boundary of 100 templates performance limit
    Given user is logged in as Administrator
    And exactly 99 shift templates already exist in the system
    And system performance requirement states handling up to 100 templates without degradation
    And user is on Shift Template Management page
    When verify current template count shows '99 templates' in the page header
    Then page displays 'Total Templates: 99' and all 99 templates load within acceptable time (under 3 seconds)
    And click 'Create New Template' button and create 100th template with Name '100th Template', Start Time '09:00 AM', End Time '05:00 PM'
    Then template creation form opens and accepts input without performance issues
    And click 'Save Template' button
    Then template saves successfully with message 'Shift template created successfully' and page updates to show 'Total Templates: 100'
    And measure page load time and verify all 100 templates display correctly
    Then page loads all 100 templates within 3 seconds with no performance degradation, all templates are visible and functional
    And attempt to create 101st template
    Then system either allows creation (no hard limit) or displays warning 'Maximum recommended templates (100) reached. Performance may be affected.'
    And system maintains performance with 100 templates as per requirements
    And all templates remain accessible and functional
    And user is warned if exceeding recommended limits

  @low @tc-edge-002
  Scenario: TC-EDGE-002 - Verify template creation with minimum valid time duration (1 minute shift)
    Given user is logged in as Administrator
    And user has opened Create New Template form
    And system allows minimum shift duration of 1 minute
    When enter 'Minimal Shift' as Template Name
    Then template Name field shows 'Minimal Shift'
    And select '09:00 AM' as Start Time
    Then start Time field displays '09:00 AM'
    And select '09:01 AM' as End Time (exactly 1 minute after start)
    Then end Time field displays '09:01 AM' with no validation errors
    And click 'Save Template' button
    Then template saves successfully with success message, or validation error appears if minimum duration requirement exists stating 'Shift duration must be at least X minutes'
    And if saved, verify template appears in list with correct 1-minute duration
    Then template 'Minimal Shift' shows Start: 09:00 AM, End: 09:01 AM, Duration: 1 minute
    And system behavior at minimum time boundary is clearly defined and consistent
    And template is saved if within system constraints
    And duration calculations handle edge case correctly

  @medium @tc-edge-003
  Scenario: TC-EDGE-003 - Verify template creation with maximum valid time duration (24-hour shift spanning midnight)
    Given user is logged in as Administrator
    And user has opened Create New Template form
    And system supports shifts spanning across midnight
    When enter '24-Hour Shift' as Template Name
    Then template Name field shows '24-Hour Shift'
    And select '12:00 AM' (midnight) as Start Time
    Then start Time field displays '12:00 AM'
    And select '11:59 PM' as End Time (23 hours 59 minutes later)
    Then end Time field displays '11:59 PM' with no validation errors
    And add break from '12:00 PM' to '01:00 PM'
    Then break is added successfully within the 24-hour shift boundary
    And click 'Save Template' button
    Then template saves successfully showing duration of 23 hours 59 minutes, or validation error if maximum duration limit exists
    And verify template displays correctly in list with proper time formatting
    Then template shows Start: 12:00 AM, End: 11:59 PM with correct duration calculation
    And system handles maximum duration edge case correctly
    And time calculations across midnight are accurate
    And template is usable in scheduling workflows

  @low @tc-edge-004
  Scenario: TC-EDGE-004 - Verify template creation with Unicode characters, emojis, and international characters in Template Name
    Given user is logged in as Administrator
    And user has opened Create New Template form
    And system database supports UTF-8 encoding
    When enter Template Name with Unicode characters: 'Shift 早班 🌅 Früh'
    Then template Name field displays all characters correctly including Chinese characters, emoji, and German umlaut
    And enter valid Start Time '08:00 AM' and End Time '04:00 PM'
    Then time fields are populated correctly
    And click 'Save Template' button
    Then template saves successfully with success message
    And verify template appears in list with all Unicode characters displayed correctly
    Then template name 'Shift 早班 🌅 Früh' displays correctly in the list without character corruption or encoding issues
    And edit the template and verify Unicode characters are preserved
    Then edit form shows Template Name with all Unicode characters intact and editable
    And template with Unicode characters is stored correctly in database
    And all international characters display properly across all views
    And system supports internationalization requirements

  @medium @tc-edge-005
  Scenario: TC-EDGE-005 - Verify system behavior when creating template with zero break times (no breaks)
    Given user is logged in as Administrator
    And user has opened Create New Template form
    And break times are optional (not required fields)
    When enter 'No Break Shift' as Template Name
    Then template Name field shows 'No Break Shift'
    And select '09:00 AM' as Start Time and '05:00 PM' as End Time
    Then time fields are populated correctly
    And do not add any breaks - leave breaks section empty
    Then breaks section shows 'No breaks added' or remains empty with 'Add Break' button available
    And click 'Save Template' button
    Then template saves successfully with message 'Shift template created successfully'
    And verify template in list shows no break times
    Then template 'No Break Shift' displays with Start: 09:00 AM, End: 05:00 PM, Breaks: None or 'No breaks'
    And template without breaks is saved and functional
    And system correctly handles null or empty break times
    And template can be used in scheduling without errors

  @medium @tc-edge-006
  Scenario: TC-EDGE-006 - Verify rapid consecutive template creation (stress test for race conditions)
    Given user is logged in as Administrator
    And user is on Shift Template Management page
    And system is monitored for race conditions and duplicate entries
    When open Create New Template form and fill with 'Rapid Test 1', Start: 09:00 AM, End: 05:00 PM
    Then form is populated with valid data
    And click 'Save Template' button rapidly 5 times in quick succession (within 1 second)
    Then system processes only one save request, button becomes disabled after first click, or loading state prevents multiple submissions
    And verify only one template 'Rapid Test 1' is created in the database
    Then templates list shows exactly one entry for 'Rapid Test 1', no duplicate entries exist
    And immediately create another template 'Rapid Test 2' and save
    Then second template saves successfully without conflicts or errors
    And verify both templates exist with unique IDs and no data corruption
    Then both 'Rapid Test 1' and 'Rapid Test 2' appear in list with unique identifiers and correct data
    And no duplicate templates are created from rapid clicking
    And system handles concurrent requests gracefully
    And data integrity is maintained under stress conditions

  @low @tc-edge-007
  Scenario: TC-EDGE-007 - Verify template list behavior when exactly zero templates exist (empty state)
    Given user is logged in as Administrator
    And all existing shift templates have been deleted from the system
    And shiftTemplates table is empty
    And user navigates to Shift Template Management page
    When observe the templates list area on page load
    Then empty state message displays: 'No shift templates found. Click Create New Template to get started.' with an illustration or icon
    And verify 'Create New Template' button is prominently displayed and enabled
    Then 'Create New Template' button is visible, enabled, and highlighted as primary action
    And verify page header shows 'Total Templates: 0'
    Then template count displays '0' correctly without errors
    And click 'Create New Template' button from empty state
    Then template creation form opens normally without errors
    And create first template with Name 'First Template', Start: 09:00 AM, End: 05:00 PM and save
    Then template saves successfully and empty state is replaced with template list showing the new template
    And empty state provides clear guidance to users
    And system handles zero templates gracefully without errors
    And user can successfully create first template from empty state

