Feature: Review Cycle Management

  Background:
    Given the application is accessible
    And the user is on the appropriate page

  # Functional Test Scenarios
  Scenario: Validate successful setup of review cycles
    Given User is logged in as Performance Manager
    Given User has valid authentication credentials
    Given Review cycle management feature is enabled
    Given Database is accessible and operational
    When Navigate to the review cycle management page
    Then Review cycle management interface is displayed with options to configure review cycles including frequency selection dropdown, save button, and any existing review cycles listed
    And Select a frequency for review cycles from the dropdown (daily, weekly, or monthly)
    Then Selected frequency is displayed in the frequency field and highlighted as the current selection
    And Click on the save button
    Then Review cycle is saved successfully, confirmation message is displayed, and the new review cycle appears in the list of configured cycles

  Scenario: Ensure reminders are sent for upcoming review cycles
    Given User is logged in as Performance Manager
    Given User has valid authentication credentials
    Given Review cycle management feature is enabled
    Given Notification system is operational
    Given User has notification permissions enabled
    When Set up a review cycle with a defined frequency (e.g., daily or weekly)
    Then Review cycle is saved successfully and confirmation message is displayed
    And Wait for the reminder time based on the configured frequency
    Then Reminder notification is sent to the user at the appropriate time before the scheduled review cycle
    And Check notification for review cycle in the notification center or inbox
    Then Notification contains correct review cycle details including frequency, scheduled date/time, and relevant performance metrics to be reviewed

  # Negative Test Scenarios
  Scenario: Verify error handling for incomplete review cycle setup
    Given User is logged in as Performance Manager
    Given User has valid authentication credentials
    Given Review cycle management feature is enabled
    Given Database is accessible and operational
    When Navigate to the review cycle management page
    Then Review cycle management interface is displayed with frequency selection dropdown and save button visible
    And Attempt to save a review cycle without selecting frequency by clicking the save button with frequency field empty
    Then Error message is displayed for missing frequency, indicating that frequency selection is required. The review cycle is not saved and the frequency field is highlighted or marked as required
    And Select frequency from the dropdown (daily, weekly, or monthly) and click save button
    Then Review cycle is saved successfully, confirmation message is displayed, error message is cleared, and the new review cycle appears in the configured cycles list

  # Accessibility Test Scenarios
  Scenario: Keyboard Navigation
    When the user navigates using keyboard only
    Then all interactive elements should be accessible via keyboard
    And focus indicators should be clearly visible

  Scenario: Screen Reader Compatibility
    When the user accesses the page with a screen reader
    Then all content should be properly announced
    And ARIA labels should be present for all interactive elements

  Scenario: Color Contrast
    Then all text should meet WCAG AA color contrast standards
    And important information should not rely solely on color

