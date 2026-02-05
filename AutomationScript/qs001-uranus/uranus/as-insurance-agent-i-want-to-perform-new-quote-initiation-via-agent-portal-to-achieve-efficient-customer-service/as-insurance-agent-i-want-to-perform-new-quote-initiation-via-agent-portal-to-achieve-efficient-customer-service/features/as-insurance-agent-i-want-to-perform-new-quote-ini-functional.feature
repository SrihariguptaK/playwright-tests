@functional @smoke
Feature: As Insurance Agent, I want to perform new quote initiation via agent portal to achieve efficient customer service - Functional Tests
  As a user
  I want to test functional tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-func-001
  Scenario: TC-FUNC-001 - Verify successful quote initiation with all mandatory fields completed
    Given agent has valid credentials with 'Agent' role assigned in the system
    And agent Portal application is accessible and running
    And database is available and quote tables are accessible
    And browser supports OAuth2 authentication flow
    When navigate to Agent Portal login page at '/login' and enter valid username 'agent@insurance.com' and password 'ValidPass123!'
    Then oAuth2 authentication succeeds and agent dashboard is displayed with 'Welcome Agent' message in header
    And click 'New Quote' button in the main navigation menu
    Then quote initiation form loads within 2 seconds displaying all mandatory fields marked with red asterisk (*)
    And enter valid data: Customer Name 'John Smith', Policy Type 'Auto Insurance', Coverage Amount '$50000', Effective Date 'tomorrow's date', Contact Email 'john.smith@email.com', Phone '555-123-4567'
    Then all fields accept input without validation errors, green checkmarks appear next to validated fields
    And click 'Submit Quote' button at bottom right of form
    Then form submits within 3 seconds, success message 'Quote successfully created' appears in green banner at top, unique quote reference number in format 'QT-YYYYMMDD-XXXX' is displayed prominently
    And verify quote reference number is displayed and copy it to clipboard
    Then reference number is selectable, copyable, and remains visible on confirmation page
    And new quote record is created in database with status 'Submitted' and timestamp
    And quote reference number is unique and retrievable via search
    And agent remains logged in and can initiate another quote
    And audit log entry created with agent ID, timestamp, and quote reference

  @high @tc-func-002
  Scenario: TC-FUNC-002 - Verify save as draft functionality preserves partial quote data
    Given agent is logged into Agent Portal with valid session
    And agent is on the quote initiation form page
    And no existing draft quotes for this agent session
    And database supports draft status for quotes
    When fill in partial quote data: Customer Name 'Jane Doe', Policy Type 'Home Insurance', leave Coverage Amount and other fields empty
    Then form accepts partial data, no validation errors shown for incomplete fields
    And click 'Save as Draft' button in bottom left of form
    Then blue notification banner appears with message 'Draft saved successfully' and draft reference number 'DRAFT-YYYYMMDD-XXXX' is displayed
    And click 'Logout' in top right corner and confirm logout
    Then agent is logged out and redirected to login page, session is terminated
    And log back in with same agent credentials 'agent@insurance.com'
    Then agent dashboard displays with 'Drafts' section showing 1 draft quote with reference number and timestamp
    And click on the draft quote reference number to resume editing
    Then quote form loads with previously entered data intact: Customer Name 'Jane Doe' and Policy Type 'Home Insurance' are populated, empty fields remain empty
    And complete remaining mandatory fields: Coverage Amount '$100000', Effective Date 'next week', Contact Email 'jane.doe@email.com', Phone '555-987-6543', then click 'Submit Quote'
    Then quote submits successfully, draft status changes to 'Submitted', new quote reference number generated, confirmation message displayed
    And draft quote is removed from drafts list after successful submission
    And final quote record exists with all data from draft plus newly added fields
    And draft history is maintained in audit log
    And agent can create new quotes or drafts without interference

  @high @tc-func-003
  Scenario: TC-FUNC-003 - Verify real-time field validation provides immediate feedback
    Given agent is logged into Agent Portal
    And quote initiation form is displayed and fully loaded
    And javaScript validation is enabled in browser
    And network connection is stable for real-time validation
    When click into 'Contact Email' field and enter invalid email 'notanemail' then tab out of field
    Then red error message 'Please enter a valid email address' appears below field immediately, field border turns red
    And correct the email to 'valid@email.com' and tab out
    Then error message disappears, field border turns green, green checkmark icon appears next to field
    And click into 'Phone' field and enter '123' then tab out
    Then red error message 'Phone number must be in format XXX-XXX-XXXX' appears below field
    And enter valid phone '555-123-4567'
    Then error clears, field validates with green indicator
    And select 'Effective Date' and choose a date in the past
    Then red error message 'Effective date must be today or in the future' appears, date field is highlighted in red
    And change date to tomorrow's date
    Then validation passes, green checkmark appears, error message disappears
    And all validation states are cleared when form is reset
    And validation messages are accessible and readable
    And form maintains validation state if user navigates away and returns
    And no validation errors persist after correction

  @high @tc-func-004
  Scenario: TC-FUNC-004 - Verify quote reference number generation is unique and follows correct format
    Given agent is logged into Agent Portal
    And multiple quotes can be created in sequence
    And database sequence generator is functioning
    And system date and time are correctly configured
    When create and submit first quote with valid data: Customer 'Test User 1', Policy 'Auto', Coverage '$25000', Date 'tomorrow', Email 'test1@email.com', Phone '555-111-1111'
    Then quote submits successfully, reference number displayed in format 'QT-YYYYMMDD-0001' where YYYYMMDD is current date
    And note the reference number and click 'Create Another Quote' button
    Then new blank quote form is displayed, previous reference number is no longer shown
    And create and submit second quote with different valid data: Customer 'Test User 2', Policy 'Home', Coverage '$75000', Date 'next week', Email 'test2@email.com', Phone '555-222-2222'
    Then quote submits successfully, new reference number displayed in format 'QT-YYYYMMDD-0002' with incremented sequence number
    And compare both reference numbers for uniqueness
    Then both reference numbers are unique, follow same format pattern, have same date prefix but different sequence numbers
    And navigate to 'Search Quotes' and search for both reference numbers individually
    Then each reference number returns exactly one quote with correct customer details matching submission data
    And both quotes exist in database with unique reference numbers
    And reference numbers are searchable and retrievable
    And sequence counter increments correctly for subsequent quotes
    And no duplicate reference numbers exist in system

  @medium @tc-func-005
  Scenario: TC-FUNC-005 - Verify agent can navigate away from form and return without losing unsaved data warning
    Given agent is logged into Agent Portal
    And quote initiation form is displayed
    And browser supports beforeunload event handling
    And no draft has been saved yet
    When enter data in quote form: Customer Name 'Test Customer', Policy Type 'Life Insurance'
    Then form accepts data, fields are populated
    And click browser back button or attempt to navigate to dashboard without saving
    Then browser warning dialog appears with message 'You have unsaved changes. Are you sure you want to leave this page?' with 'Stay' and 'Leave' options
    And click 'Stay' button in warning dialog
    Then dialog closes, user remains on quote form, all entered data is still present in fields
    And click 'Save as Draft' button
    Then draft is saved successfully with confirmation message
    And now click browser back button or navigate away
    Then no warning dialog appears since changes are saved, navigation proceeds normally
    And unsaved data warning only appears when there are unsaved changes
    And draft data is preserved in database after save
    And navigation works normally after saving
    And user experience is protected from accidental data loss

