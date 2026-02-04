@edge-cases @boundary
Feature: As Merchant Manager, I want to add a new merchant to the system to achieve accurate merchant representation - Edge Case Tests
  As a user
  I want to test edge case tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @medium @tc-edge-001
  Scenario: TC-EDGE-001 - Verify system handles merchant name at maximum character limit (100 characters)
    Given user is logged in as Merchant Manager
    And user is on the 'Add Merchant' page
    And maximum character limit for Merchant Name is 100 characters
    And character counter is visible
    When enter exactly 100 characters in Merchant Name field: 'A' repeated 100 times or 'This is a very long merchant name that contains exactly one hundred characters for testing purposes ok'
    Then all 100 characters are accepted, character counter shows '100/100', field border remains green
    And attempt to type one more character
    Then additional character is not entered, field prevents further input, character counter remains at '100/100'
    And fill other mandatory fields with valid data: Address='123 Edge St', Email='edge@test.com', Phone='+1-555-100-1000', Category='Retail'
    Then all fields are populated correctly
    And click 'Submit' button
    Then merchant is successfully created, confirmation message 'Merchant added successfully' appears, full 100-character name is saved
    And navigate to merchant list and verify the merchant name is displayed correctly
    Then full 100-character merchant name is displayed without truncation in the database, UI may show ellipsis with tooltip on hover
    And merchant with 100-character name is saved in database
    And full name is retrievable and displayed correctly
    And no data truncation occurred
    And character limit enforcement worked correctly

  @medium @tc-edge-002
  Scenario: TC-EDGE-002 - Verify system handles special characters and Unicode in merchant name and address fields
    Given user is logged in as Merchant Manager
    And user is on the 'Add Merchant' page
    And system supports UTF-8 character encoding
    And database collation supports Unicode characters
    When enter merchant name with special characters: 'Café & Restaurant Ñoño™ 北京商店 🏪' in Merchant Name field
    Then all special characters, accented letters, Chinese characters, and emoji are accepted and displayed correctly
    And enter address with Unicode: '123 Rue de la Paix, Montréal, Québec, 日本東京都' in Address field
    Then all international characters are accepted and displayed properly
    And fill remaining mandatory fields: Email='unicode@test.com', Phone='+1-555-200-2000', Category='Food & Beverage'
    Then fields are populated correctly
    And click 'Submit' button
    Then merchant is created successfully with confirmation message, all Unicode characters are preserved
    And retrieve merchant details from database or view in merchant list
    Then all special characters, accents, Chinese characters, and emoji are stored and displayed correctly without corruption
    And merchant with Unicode characters is saved correctly in database
    And character encoding is preserved throughout the system
    And all special characters display correctly in UI
    And search and filter functions work with Unicode characters

  @medium @tc-edge-003
  Scenario: TC-EDGE-003 - Verify system handles minimum valid data entry (only mandatory fields with shortest acceptable values)
    Given user is logged in as Merchant Manager
    And user is on the 'Add Merchant' page
    And minimum character requirements: Name=2 chars, Address=5 chars, Email=valid format, Phone=10 digits
    When enter 'AB' (2 characters) in Merchant Name field
    Then name is accepted as it meets minimum requirement
    And enter '12 St' (5 characters) in Address field
    Then address is accepted as it meets minimum requirement
    And enter 'a@b.c' (shortest valid email format) in Email field
    Then email is validated and accepted
    And enter '+1-555-0000' (minimum valid phone) in Phone Number field
    Then phone number is accepted
    And select 'Other' from Category dropdown
    Then category is selected
    And click 'Submit' button
    Then merchant is created successfully with confirmation message, all minimum values are saved
    And merchant with minimum valid data is saved in database
    And all fields contain the minimum acceptable values
    And no validation errors occurred
    And merchant is retrievable and functional in the system

  @high @tc-edge-004
  Scenario: TC-EDGE-004 - Verify system handles rapid consecutive form submissions (double-click prevention)
    Given user is logged in as Merchant Manager
    And user is on the 'Add Merchant' page
    And submit button debouncing or disabling mechanism is implemented
    And network latency is simulated at 1 second
    When fill all mandatory fields with valid data: Name='Rapid Submit Test', Address='123 Rapid St', Email='rapid@test.com', Phone='+1-555-300-3000', Category='Services'
    Then all fields are populated correctly
    And quickly double-click the 'Submit' button (two clicks within 200ms)
    Then submit button is disabled after first click, shows 'Submitting...' text, loading spinner appears
    And observe network requests in browser developer tools
    Then only ONE POST request to /api/merchants is sent, second click is ignored
    And wait for response
    Then single confirmation message 'Merchant added successfully' appears, button re-enables after response
    And check database for duplicate entries
    Then only ONE merchant record with name 'Rapid Submit Test' exists in database, no duplicates created
    And exactly one merchant record is created
    And no duplicate submissions occurred
    And submit button protection mechanism worked correctly
    And user experience is smooth without errors

  @medium @tc-edge-005
  Scenario: TC-EDGE-005 - Verify system handles file upload at maximum allowed size (5MB boundary)
    Given user is logged in as Merchant Manager
    And user is on the 'Add Merchant' page
    And test file 'large_document.pdf' of exactly 5MB (5,242,880 bytes) is available
    And maximum file size limit is set to 5MB
    When fill all mandatory merchant fields with valid data
    Then all fields are populated
    And click 'Upload Documents' button and select 'large_document.pdf' (exactly 5MB)
    Then file upload begins, progress bar shows upload progress from 0% to 100%
    And wait for upload completion
    Then upload completes successfully, green checkmark appears, message 'Document uploaded successfully (5.0 MB)' is displayed
    And attempt to upload another file 'oversized.pdf' of 5.1MB (5,349,376 bytes)
    Then upload is rejected immediately with error message 'File size exceeds maximum limit of 5MB. Please upload a smaller file.'
    And click 'Submit' button with the 5MB file attached
    Then merchant and document are saved successfully, confirmation message appears
    And merchant is saved with 5MB document attached
    And file size validation correctly enforces 5MB limit
    And oversized file (5.1MB) was rejected
    And document is accessible and downloadable at full 5MB size

  @high @tc-edge-006
  Scenario: TC-EDGE-006 - Verify system handles concurrent merchant additions by multiple users without data corruption
    Given two users (User A and User B) are logged in as Merchant Managers in different browser sessions
    And both users are on the 'Add Merchant' page simultaneously
    And database supports concurrent transactions with proper locking
    And system performance target is maintained under concurrent load
    When user A fills form with: Name='Concurrent Merchant A', Address='123 A Street', Email='userA@test.com', Phone='+1-555-400-4000', Category='Retail'
    Then user A's form is populated
    And user B fills form with: Name='Concurrent Merchant B', Address='456 B Avenue', Email='userB@test.com', Phone='+1-555-500-5000', Category='Technology'
    Then user B's form is populated
    And user A and User B click 'Submit' button simultaneously (within 100ms of each other)
    Then both submissions are processed, both users see loading indicators
    And wait for both responses (should be under 3 seconds each)
    Then user A sees 'Merchant added successfully' for Merchant A, User B sees 'Merchant added successfully' for Merchant B
    And verify database contains both merchants with correct data and no data mixing
    Then database contains two distinct merchant records: 'Concurrent Merchant A' with User A's data and 'Concurrent Merchant B' with User B's data, no data corruption or mixing occurred
    And two separate merchant records exist in database
    And each merchant has correct associated data with no cross-contamination
    And system performance remained under 3 seconds for both users
    And no database locking errors or transaction conflicts occurred

  @low @tc-edge-007
  Scenario: TC-EDGE-007 - Verify system handles phone number formats from different countries and international dialing codes
    Given user is logged in as Merchant Manager
    And user is on the 'Add Merchant' page
    And phone number validation supports international formats
    And system accepts various phone number formats and country codes
    When enter merchant with US format phone: Name='US Merchant', Phone='+1-555-123-4567', and other required fields
    Then phone number is accepted and formatted correctly
    And click Submit and verify success
    Then merchant is created successfully
    And add another merchant with UK format: Name='UK Merchant', Phone='+44 20 7123 4567', and other required fields
    Then uK phone format is accepted
    And add merchant with Japan format: Name='Japan Merchant', Phone='+81-3-1234-5678', and other required fields
    Then japan phone format is accepted
    And add merchant with no country code: Name='Local Merchant', Phone='555-1234', and other required fields
    Then either: (A) Phone is accepted if local format is allowed, OR (B) Validation error 'Please include country code (e.g., +1)' appears
    And verify all accepted phone numbers are stored correctly in database
    Then all international phone formats are stored and retrievable correctly
    And multiple merchants with different international phone formats are saved
    And phone number validation accommodates international formats
    And all phone numbers are stored in consistent format in database
    And phone numbers display correctly in merchant list

