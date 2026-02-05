@edge-cases @boundary
Feature: As Insurance Agent, I want to perform new quote initiation via agent portal to achieve efficient customer service - Edge Case Tests
  As a user
  I want to test edge case tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @medium @tc-edge-001
  Scenario: TC-EDGE-001 - Verify form handles maximum character limits in text fields
    Given agent is logged into Agent Portal
    And quote initiation form is displayed
    And character limits are defined for text fields (e.g., Customer Name: 100 chars)
    And field validation enforces character limits
    When generate and enter exactly 100 characters in Customer Name field (at maximum limit): 'A' repeated 100 times
    Then field accepts exactly 100 characters, character counter shows '100/100', no error message appears
    And attempt to enter 101st character by typing additional 'A'
    Then either: (1) 101st character is not accepted, field stops at 100 chars OR (2) Warning message appears: 'Maximum 100 characters allowed'
    And fill all other mandatory fields with valid data and submit quote with 100-character Customer Name
    Then quote submits successfully, full 100-character name is stored and displayed in confirmation
    And create new quote and enter exactly 1 character 'X' in Customer Name field (minimum valid input)
    Then field accepts single character, validation passes with green indicator
    And submit quote with single-character Customer Name and other valid data
    Then quote submits successfully, single character name is accepted and stored
    And both maximum and minimum length inputs are handled correctly
    And database stores full character data without truncation
    And character limits are enforced consistently
    And no data corruption occurs at boundaries

  @medium @tc-edge-002
  Scenario: TC-EDGE-002 - Verify form handles special characters and Unicode in text fields
    Given agent is logged into Agent Portal
    And quote initiation form is displayed
    And system supports UTF-8 character encoding
    And database can store Unicode characters
    When enter Customer Name with accented characters: 'José María Ñoño'
    Then field accepts accented characters, displays them correctly, validation passes
    And enter Customer Name with Unicode characters: '李明 (Chinese)', 'Владимир (Russian)', 'محمد (Arabic)'
    Then field accepts and displays Unicode characters correctly without corruption
    And enter Customer Name with emojis: 'John Smith 😀🏠'
    Then either: (1) Emojis are accepted and displayed OR (2) Validation message appears: 'Special symbols not allowed in name'
    And fill remaining mandatory fields with valid data and submit quote with special characters in Customer Name
    Then quote submits successfully, special characters are preserved in database and displayed correctly in confirmation
    And search for created quote using special characters from Customer Name
    Then search finds quote correctly, special characters match exactly as entered
    And special characters and Unicode are stored correctly in database
    And character encoding is preserved throughout system
    And search and retrieval work with special characters
    And no character corruption or data loss occurs

  @high @tc-edge-003
  Scenario: TC-EDGE-003 - Verify form handles boundary values for Coverage Amount field
    Given agent is logged into Agent Portal
    And quote initiation form is displayed
    And coverage Amount has defined min/max limits (e.g., $1 to $10,000,000)
    And numeric validation is active
    When enter minimum valid Coverage Amount: '$1' or '1'
    Then field accepts value, formats it as currency '$1.00', validation passes with green indicator
    And enter value below minimum: '$0' or '0'
    Then red error message appears: 'Coverage Amount must be at least $1', validation fails
    And enter maximum valid Coverage Amount: '$10000000' (10 million)
    Then field accepts value, formats it as '$10,000,000.00', validation passes
    And enter value above maximum: '$10000001' (10 million + 1)
    Then red error message appears: 'Coverage Amount cannot exceed $10,000,000', validation fails
    And enter value with many decimal places: '$50000.999999'
    Then value is auto-rounded to 2 decimal places: '$50,001.00' OR error message appears about decimal precision
    And fill other mandatory fields and submit quote with minimum Coverage Amount '$1'
    Then quote submits successfully, minimum amount is accepted and stored correctly
    And boundary values are enforced correctly
    And minimum and maximum limits prevent invalid data
    And currency formatting is consistent
    And decimal precision is handled appropriately

  @medium @tc-edge-004
  Scenario: TC-EDGE-004 - Verify system handles rapid successive quote submissions from same agent
    Given agent is logged into Agent Portal
    And quote initiation form is displayed
    And no rate limiting is expected for legitimate agent use
    And system can handle concurrent requests
    When fill quote form with valid data: Customer 'Rapid Test 1', Policy 'Auto', Coverage '$25000', Date 'tomorrow', Email 'rapid1@test.com', Phone '555-111-0001'
    Then form is filled and ready to submit
    And click 'Submit Quote' button rapidly 5 times in quick succession (double-click scenario)
    Then only ONE quote is created, submit button is disabled after first click, subsequent clicks are ignored, single confirmation message appears with one reference number
    And verify in database or quote list that only one quote was created
    Then exactly one quote record exists for 'Rapid Test 1', no duplicate quotes created
    And create 10 different quotes in rapid succession (one after another within 2 minutes) with different customer names: 'Rapid Test 2' through 'Rapid Test 11'
    Then all 10 quotes are created successfully, each receives unique reference number, system handles rapid legitimate submissions without errors
    And verify all 10 quotes exist in system with correct data
    Then all 10 quotes are retrievable, have unique reference numbers, contain correct customer data, no data corruption occurred
    And no duplicate quotes created from double-clicking
    And system handles legitimate rapid submissions correctly
    And all quotes have unique reference numbers
    And performance remains acceptable under rapid use

  @low @tc-edge-005
  Scenario: TC-EDGE-005 - Verify form behavior when browser auto-fill populates fields
    Given agent is logged into Agent Portal
    And browser has auto-fill enabled with saved form data
    And quote initiation form supports auto-fill attributes
    And previous quote data exists in browser auto-fill memory
    When navigate to quote initiation form and click into first field (Customer Name)
    Then browser auto-fill dropdown appears showing previously entered names
    And select an auto-fill suggestion from dropdown
    Then browser auto-fills multiple fields with saved data (name, email, phone), fields are populated instantly
    And verify that real-time validation triggers for auto-filled fields
    Then all auto-filled fields are validated automatically, green checkmarks appear for valid data, any invalid auto-filled data shows error messages
    And complete remaining mandatory fields not auto-filled (Policy Type, Coverage Amount, Effective Date) and submit
    Then quote submits successfully, auto-filled data is accepted and processed correctly
    And verify submitted quote contains correct data from auto-fill
    Then quote confirmation shows all data correctly, auto-filled information matches what was populated
    And auto-fill data is validated same as manually entered data
    And form works correctly with browser auto-fill feature
    And no validation is bypassed due to auto-fill
    And user experience is enhanced by auto-fill support

