@functional @smoke
Feature: As Merchant Manager, I want to add a new merchant to the system to achieve accurate merchant representation - Functional Tests
  As a user
  I want to test functional tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-func-001
  Scenario: TC-FUNC-001 - Successfully add a new merchant with all mandatory fields filled correctly
    Given user is logged in as Merchant Manager with valid credentials
    And user is on the 'Add Merchant' page (/merchants/add)
    And database connection is active and merchants table is accessible
    And no merchant with the same name exists in the system
    When enter 'ABC Electronics Store' in the 'Merchant Name' field
    Then text appears in the field without errors
    And enter '123 Main Street, Suite 100, New York, NY 10001' in the 'Address' field
    Then address is displayed correctly in the field
    And enter 'contact@abcelectronics.com' in the 'Email' field
    Then email format is accepted and displayed
    And enter '+1-555-123-4567' in the 'Phone Number' field
    Then phone number is formatted and displayed correctly
    And select 'Electronics' from the 'Category' dropdown menu
    Then category 'Electronics' is selected and displayed in the dropdown
    And click the 'Submit' button at the bottom of the form
    Then form is submitted, loading indicator appears briefly, and green confirmation message 'Merchant added successfully' appears at the top of the page within 3 seconds
    And new merchant 'ABC Electronics Store' is saved in the merchants database table
    And user remains on the 'Add Merchant' page with the form cleared for next entry
    And success confirmation message is visible for 5 seconds before auto-dismissing
    And merchant appears in the merchant list when navigating to 'View Merchants' page

  @high @tc-func-002
  Scenario: TC-FUNC-002 - Successfully add a new merchant with optional supporting documents uploaded
    Given user is logged in as Merchant Manager
    And user is on the 'Add Merchant' page
    And test document file 'merchant_license.pdf' (2MB, valid PDF format) is available on local system
    And file upload functionality is enabled in the system
    When fill all mandatory fields: Name='Tech Solutions Inc', Address='456 Tech Blvd', Email='info@techsolutions.com', Phone='+1-555-987-6543', Category='Technology'
    Then all fields are populated correctly without validation errors
    And click the 'Upload Documents' button in the supporting documents section
    Then file browser dialog opens
    And select 'merchant_license.pdf' from the file browser and click 'Open'
    Then file upload progress bar appears and shows upload progress
    And wait for upload completion
    Then green checkmark icon appears next to filename 'merchant_license.pdf' with message 'Document uploaded successfully'
    And click the 'Submit' button to save the merchant
    Then form submits successfully with confirmation message 'Merchant and documents added successfully' displayed in green banner
    And merchant 'Tech Solutions Inc' is saved in database with document reference
    And document 'merchant_license.pdf' is stored in the file storage system with correct merchant association
    And document metadata (filename, size, upload date) is recorded in the database
    And user can view the uploaded document when editing the merchant record

  @medium @tc-func-003
  Scenario: TC-FUNC-003 - Verify inline validation provides real-time feedback for email format
    Given user is logged in as Merchant Manager
    And user is on the 'Add Merchant' page with empty form
    And client-side validation is enabled
    When click into the 'Email' field
    Then field receives focus with blue border highlight
    And type 'invalidemail' (without @ symbol) in the Email field
    Then no immediate error appears while typing
    And click outside the Email field (blur event)
    Then red error message 'Please enter a valid email address' appears below the Email field, and field border turns red
    And clear the field and enter 'valid@email.com'
    Then error message disappears, field border turns green, and green checkmark icon appears
    And email field shows valid state with green indicator
    And form can be submitted with valid email
    And no error messages are displayed

  @medium @tc-func-004
  Scenario: TC-FUNC-004 - Verify form submission with all fields including optional fields populated
    Given user is logged in as Merchant Manager
    And user is on the 'Add Merchant' page
    And all form fields are visible and enabled
    When enter 'Global Retail Partners' in Merchant Name field
    Then name is displayed in the field
    And enter '789 Commerce Ave, Floor 5, Los Angeles, CA 90001' in Address field
    Then full address is displayed
    And enter 'partners@globalretail.com' in Email field
    Then email is validated and accepted
    And enter '+1-555-246-8135' in Phone Number field
    Then phone number is formatted correctly
    And select 'Retail' from Category dropdown
    Then category is selected
    And enter 'Primary retail partner for West Coast operations' in optional Notes/Description field
    Then notes text is displayed in the field
    And click 'Submit' button
    Then success message 'Merchant added successfully' appears, response time is under 3 seconds
    And merchant is saved with all fields including optional notes
    And all data is retrievable when viewing merchant details
    And form is reset to empty state for next entry

  @low @tc-func-005
  Scenario: TC-FUNC-005 - Verify user can navigate away from form and return without data loss using browser back button
    Given user is logged in as Merchant Manager
    And user is on the 'Add Merchant' page
    And browser session storage or form state management is enabled
    When enter 'Test Merchant Name' in the Merchant Name field
    Then text is entered and displayed
    And enter 'test@merchant.com' in the Email field
    Then email is entered and displayed
    And click browser back button or navigate to 'Dashboard' page
    Then warning dialog appears: 'You have unsaved changes. Are you sure you want to leave?' with 'Stay' and 'Leave' buttons
    And click 'Stay' button in the warning dialog
    Then dialog closes and user remains on 'Add Merchant' page with all entered data intact
    And all previously entered form data is preserved
    And user remains on the Add Merchant page
    And form is still in editable state

  @medium @tc-func-006
  Scenario: TC-FUNC-006 - Verify successful merchant addition updates the merchant count in the system dashboard
    Given user is logged in as Merchant Manager
    And current merchant count is visible on dashboard (e.g., 50 merchants)
    And user navigates to 'Add Merchant' page
    And system dashboard displays real-time merchant statistics
    When note the current merchant count displayed on dashboard before adding
    Then dashboard shows current count (e.g., '50 Total Merchants')
    And fill all mandatory fields: Name='New Merchant Co', Address='100 New St', Email='new@merchant.com', Phone='+1-555-111-2222', Category='Services'
    Then all fields are filled correctly
    And click 'Submit' button
    Then success message 'Merchant added successfully' appears
    And navigate to Dashboard page
    Then dashboard loads and merchant count is updated to 51 Total Merchants
    And merchant count on dashboard reflects the new addition
    And new merchant is included in the total count
    And dashboard statistics are synchronized with database

  @low @tc-func-007
  Scenario: TC-FUNC-007 - Verify form field character counters display remaining characters for fields with limits
    Given user is logged in as Merchant Manager
    And user is on the 'Add Merchant' page
    And character limit is set to 100 characters for Merchant Name field
    And character counter is visible below the field
    When click into the 'Merchant Name' field
    Then field receives focus and character counter shows '0/100 characters'
    And type 'ABC Corporation' (16 characters)
    Then character counter updates in real-time to show '16/100 characters'
    And continue typing until 95 characters are entered
    Then character counter shows '95/100 characters' in orange/warning color
    And type 5 more characters to reach exactly 100 characters
    Then character counter shows '100/100 characters' in red color, and further typing is prevented
    And field contains exactly 100 characters
    And no additional characters can be entered
    And character counter accurately reflects the limit

