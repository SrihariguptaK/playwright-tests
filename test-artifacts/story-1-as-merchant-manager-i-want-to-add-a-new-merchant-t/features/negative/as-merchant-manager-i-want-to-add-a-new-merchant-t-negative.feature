@negative @error-handling
Feature: As Merchant Manager, I want to add a new merchant to the system to achieve accurate merchant representation - Negative Tests
  As a user
  I want to test negative tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-nega-001
  Scenario: TC-NEGA-001 - Verify system prevents merchant addition when mandatory Merchant Name field is empty
    Given user is logged in as Merchant Manager
    And user is on the 'Add Merchant' page
    And form validation is enabled for mandatory fields
    When leave the 'Merchant Name' field empty
    Then field remains empty with no content
    And fill other mandatory fields: Address='123 Test St', Email='test@test.com', Phone='+1-555-000-0000', Category='Retail'
    Then other fields are populated correctly
    And click the 'Submit' button
    Then form submission is blocked, red error message 'Merchant Name is required' appears below the Merchant Name field, field border turns red, and focus moves to the empty field
    And verify no API call is made to POST /api/merchants
    Then network tab shows no POST request was sent, form remains on the same page
    And no merchant record is created in the database
    And user remains on the 'Add Merchant' page with error message displayed
    And form data in other fields is preserved
    And submit button remains enabled for retry

  @high @tc-nega-002
  Scenario: TC-NEGA-002 - Verify system rejects invalid email format and displays appropriate error message
    Given user is logged in as Merchant Manager
    And user is on the 'Add Merchant' page
    And email validation regex is configured to standard RFC 5322 format
    When enter 'Valid Merchant Name' in Merchant Name field
    Then name is accepted
    And enter 'notanemail' (missing @ and domain) in Email field
    Then text is entered in the field
    And fill remaining mandatory fields: Address='456 Test Ave', Phone='+1-555-111-1111', Category='Services'
    Then fields are populated
    And click 'Submit' button
    Then form submission is prevented, red error message 'Please enter a valid email address (e.g., user@example.com)' appears below Email field, field border turns red
    And change email to 'test@' (missing domain)
    Then same error message persists
    And change email to '@domain.com' (missing local part)
    Then same error message persists
    And no merchant is added to the database
    And error message remains visible until valid email is entered
    And form remains in editable state
    And all other field data is preserved

  @high @tc-nega-003
  Scenario: TC-NEGA-003 - Verify system handles file upload failure gracefully when unsupported file type is uploaded
    Given user is logged in as Merchant Manager
    And user is on the 'Add Merchant' page
    And test file 'malicious_script.exe' (executable file) is available on local system
    And allowed file types are: PDF, JPG, PNG, DOCX (max 5MB)
    When fill all mandatory merchant fields with valid data
    Then all fields are populated correctly
    And click 'Upload Documents' button
    Then file browser dialog opens
    And select 'malicious_script.exe' file and click 'Open'
    Then upload is rejected immediately, red error message 'File type not supported. Please upload PDF, JPG, PNG, or DOCX files only' appears below upload button
    And verify file is not uploaded to server
    Then no file appears in the uploaded documents list, no upload progress bar is shown
    And click 'Submit' button to save merchant without document
    Then merchant is saved successfully without the rejected document, confirmation message appears
    And merchant is saved without any document attachment
    And no executable file is stored on the server
    And error message is cleared after successful submission
    And system security is maintained by rejecting potentially harmful files

  @high @tc-nega-004
  Scenario: TC-NEGA-004 - Verify system prevents duplicate merchant addition when merchant with same name already exists
    Given user is logged in as Merchant Manager
    And merchant named 'Existing Merchant Corp' already exists in the database
    And user is on the 'Add Merchant' page
    And duplicate detection is enabled based on merchant name (case-insensitive)
    When enter 'Existing Merchant Corp' in Merchant Name field (exact match)
    Then text is entered in the field
    And fill other mandatory fields: Address='789 New Address', Email='different@email.com', Phone='+1-555-999-9999', Category='Technology'
    Then all fields are populated
    And click 'Submit' button
    Then form submission is blocked, error message 'A merchant with this name already exists. Please use a different name or update the existing merchant.' appears in red banner at top of form
    And change name to 'EXISTING MERCHANT CORP' (different case)
    Then text is entered
    And click 'Submit' button again
    Then same duplicate error message appears, confirming case-insensitive duplicate detection
    And no duplicate merchant record is created
    And original merchant 'Existing Merchant Corp' remains unchanged in database
    And user is prompted to modify the merchant name
    And form data is preserved for correction

  @medium @tc-nega-005
  Scenario: TC-NEGA-005 - Verify system handles network timeout gracefully when API response exceeds 3 seconds
    Given user is logged in as Merchant Manager
    And user is on the 'Add Merchant' page
    And network simulation tool is configured to delay API response by 5 seconds
    And timeout threshold is set to 3 seconds
    When fill all mandatory fields with valid data: Name='Timeout Test Merchant', Address='123 Timeout St', Email='timeout@test.com', Phone='+1-555-888-8888', Category='Retail'
    Then all fields are populated correctly
    And click 'Submit' button
    Then loading spinner appears, submit button is disabled and shows 'Submitting...'
    And wait for 3 seconds (timeout threshold)
    Then after 3 seconds, loading spinner disappears, error message 'Request timed out. Please check your connection and try again.' appears in red banner at top
    And verify submit button is re-enabled
    Then submit button returns to enabled state with text 'Submit', allowing user to retry
    And no merchant record is created due to timeout
    And form data is preserved for retry
    And user can attempt resubmission
    And error message provides clear guidance for next steps

  @high @tc-nega-006
  Scenario: TC-NEGA-006 - Verify system prevents unauthorized access when user session expires during form completion
    Given user is logged in as Merchant Manager
    And user is on the 'Add Merchant' page
    And session timeout is set to 30 minutes
    And user session is manually expired or 30 minutes have passed
    When fill all mandatory fields with valid data
    Then all fields are populated
    And wait for session to expire or manually clear session token from browser storage
    Then session expires in background
    And click 'Submit' button
    Then aPI returns 401 Unauthorized error, error message 'Your session has expired. Please log in again.' appears in red banner
    And verify automatic redirect to login page after 3 seconds
    Then user is redirected to login page with message 'Session expired. Please log in to continue.'
    And no merchant is added to the database
    And user is logged out and redirected to login page
    And form data is lost (security measure)
    And user must re-authenticate to access the system

  @high @tc-nega-007
  Scenario: TC-NEGA-007 - Verify system rejects SQL injection attempts in merchant name field
    Given user is logged in as Merchant Manager
    And user is on the 'Add Merchant' page
    And input sanitization and parameterized queries are implemented
    And sQL injection protection is active
    When enter SQL injection string "'; DROP TABLE merchants; --" in Merchant Name field
    Then text is entered in the field
    And fill other mandatory fields: Address='123 Test St', Email='test@sql.com', Phone='+1-555-777-7777', Category='Technology'
    Then fields are populated
    And click 'Submit' button
    Then either: (A) Input is sanitized and merchant is created with escaped string as literal name, OR (B) Validation error 'Invalid characters detected in Merchant Name' appears
    And verify merchants table still exists and is not dropped
    Then database merchants table remains intact, no SQL injection was executed, all existing merchants are still present
    And database integrity is maintained
    And no SQL commands from user input are executed
    And either merchant is created with sanitized name or creation is blocked
    And security logs record the attempted injection for audit

