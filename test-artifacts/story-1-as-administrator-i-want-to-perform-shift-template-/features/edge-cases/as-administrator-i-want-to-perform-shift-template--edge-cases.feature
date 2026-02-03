@edge-cases @boundary
Feature: As Administrator, I want to perform shift template creation to achieve reusable scheduling. - Edge Case Tests
  As a user
  I want to test edge case tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @medium @tc-edge-001
  Scenario: TC-EDGE-001 - Verify system handles creation of shift template with maximum allowed duration (24 hours)
    Given user is logged in as Administrator
    And user is on shift template creation page
    And system allows shift duration up to 24 hours
    When click 'Create New Template' button
    Then template creation form is displayed
    And enter '24 Hour Shift' as Template Name, '12:00 AM' as Start Time, and '11:59 PM' as End Time
    Then all fields accept input, system calculates duration as 23 hours 59 minutes
    And add break from '06:00 AM' to '06:30 AM'
    Then break is added successfully within the 24-hour shift
    And click 'Save Template' button
    Then template is saved successfully with confirmation message, no duration limit errors appear
    And verify template appears in list with correct 24-hour duration displayed
    Then template shows Start '12:00 AM', End '11:59 PM', and break time correctly
    And template with maximum duration is saved in database
    And template is usable for scheduling purposes
    And duration calculation is accurate and displayed correctly

  @medium @tc-edge-002
  Scenario: TC-EDGE-002 - Verify system handles creation of shift template with minimum duration (1 minute)
    Given user is logged in as Administrator
    And user is on shift template creation page
    And system allows very short shift durations
    When click 'Create New Template' and enter 'Minimal Shift' as Template Name
    Then template creation form opens with name populated
    And select '09:00 AM' as Start Time and '09:01 AM' as End Time (1 minute duration)
    Then times are accepted, system calculates 1-minute duration
    And attempt to add a break (if system allows breaks in very short shifts)
    Then system either prevents break addition with message 'Shift too short for breaks' or allows it based on business rules
    And click 'Save Template' button
    Then template is saved with confirmation message or validation error if minimum duration policy exists
    And template is saved if system allows 1-minute shifts, or appropriate validation error is shown
    And system behavior is consistent with business rules for minimum shift duration

  @high @tc-edge-003
  Scenario: TC-EDGE-003 - Verify system handles creation of 100th shift template (performance boundary)
    Given user is logged in as Administrator
    And exactly 99 shift templates already exist in the system
    And system performance requirement states handling up to 100 templates without degradation
    When navigate to shift template management page and verify current count shows 99 templates
    Then page loads within 2 seconds, displays '99 templates' count
    And click 'Create New Template' button
    Then form opens within 1 second without performance lag
    And enter '100th Template' as name, '08:00 AM' as Start Time, '05:00 PM' as End Time
    Then all fields accept input without delay
    And click 'Save Template' button and measure response time
    Then template is created within 3 seconds, success message appears, no performance degradation
    And verify templates list now shows 100 templates and page remains responsive
    Then list displays all 100 templates, scrolling is smooth, page load time remains under 3 seconds
    And attempt to create 101st template
    Then system either allows creation (if no hard limit) or shows message 'Maximum template limit reached (100)'
    And 100 templates exist in database
    And system performance remains acceptable per requirements
    And template list pagination or virtualization works correctly if implemented

  @medium @tc-edge-004
  Scenario: TC-EDGE-004 - Verify system handles template name with special characters and maximum length
    Given user is logged in as Administrator
    And user is on shift template creation page
    And template name field has character limit (assume 100 characters)
    When click 'Create New Template' button
    Then template creation form is displayed
    And enter template name with special characters: 'Shift #1 - Morning/Evening (Mon-Fri) @Location_A & B'
    Then template Name field accepts special characters without errors
    And enter valid Start Time '08:00 AM' and End Time '05:00 PM', then save
    Then template is created successfully, special characters are preserved in name
    And create another template with name at maximum length (100 characters): 'A' repeated 100 times
    Then field accepts exactly 100 characters, prevents input beyond limit, template saves successfully
    And verify both templates display correctly in the list with full names visible or truncated with tooltip
    Then template names are displayed correctly, long names are handled with ellipsis and hover tooltip showing full name
    And templates with special characters and maximum length are saved correctly in database
    And special characters do not cause SQL injection or XSS vulnerabilities
    And uI handles long names gracefully without breaking layout

  @medium @tc-edge-005
  Scenario: TC-EDGE-005 - Verify system handles rapid consecutive template creation attempts
    Given user is logged in as Administrator
    And user is on shift template creation page
    And system has rate limiting or duplicate submission prevention
    When enter valid template data: Name 'Rapid Test 1', Start '08:00 AM', End '05:00 PM'
    Then form accepts all valid input
    And click 'Save Template' button multiple times rapidly (5 clicks within 2 seconds)
    Then system prevents duplicate submissions, only one template is created, button is disabled after first click
    And verify only one 'Rapid Test 1' template appears in the list
    Then exactly one template is created, no duplicates exist
    And immediately create another template 'Rapid Test 2' right after first one completes
    Then second template is created successfully without interference from first submission
    And no duplicate templates are created in database
    And system handles rapid submissions gracefully with proper button state management
    And all created templates are valid and complete

  @low @tc-edge-006
  Scenario: TC-EDGE-006 - Verify system handles template creation with break duration equal to shift duration
    Given user is logged in as Administrator
    And user is on shift template creation page
    And system allows breaks to span entire shift duration
    When click 'Create New Template' and enter 'Full Break Shift' as name
    Then template creation form opens
    And enter '09:00 AM' as Start Time and '05:00 PM' as End Time (8-hour shift)
    Then valid shift times are accepted
    And add break from '09:00 AM' to '05:00 PM' (break equals entire shift duration)
    Then system either accepts this edge case or shows validation error 'Break cannot equal entire shift duration'
    And attempt to save the template
    Then system behavior is consistent with business rules - either saves with warning or prevents with clear error message
    And system handles edge case according to business rules
    And if saved, template is marked or flagged for review
    And if rejected, clear validation message explains the constraint

