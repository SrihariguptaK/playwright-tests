Feature: Real-Time Alert System

  Background:
    Given the application is accessible
    And the user is on the appropriate page

  # Functional Test Scenarios
  Scenario: Validate alert notification for detected conflict
    Given User account is active and logged into the system
    Given User has valid notification preferences configured
    Given Notification service is operational and accessible
    Given At least one scheduling conflict exists or can be triggered in the system
    Given User has permissions to receive scheduling alerts
    When Trigger or simulate a scheduling conflict in the system (e.g., double-booking a resource or overlapping appointments)
    Then System detects the scheduling conflict and generates an alert notification within 5 seconds
    And Navigate to user profile settings and check notification preferences section
    Then Notification settings page displays correctly showing user's configured preferences (in-app, email, or SMS) are properly set and active
    And Check the chosen notification method (in-app notification center, email inbox, or SMS messages) for the alert
    Then Alert is received via the user's chosen notification method and contains accurate conflict details including: conflict type, affected resources, time/date of conflict, and conflicting parties involved

  Scenario: Ensure alerts are customizable
    Given User is logged into the system with valid credentials
    Given User has access to alert settings configuration
    Given System has default alert preferences set for the user
    Given Notification service supports multiple delivery methods (in-app, email, SMS)
    Given User has valid email address and/or phone number registered in the system
    When Navigate to user settings menu and select 'Alert Settings' or 'Notification Preferences' option
    Then Alert settings page is displayed showing all available notification options including in-app notifications, email alerts, and SMS alerts with current preference selections visible
    And Modify alert preferences by selecting or deselecting notification methods (e.g., enable SMS alerts, disable email alerts, keep in-app enabled) and click 'Save' or 'Update Preferences' button
    Then System displays a success message confirming preferences are saved successfully, and the updated preferences are reflected in the settings page
    And Trigger or simulate a scheduling conflict in the system after preference changes have been saved
    Then System detects the conflict and sends alert notification according to the newly configured preferences (only through the selected notification methods), and alert is not sent through disabled notification channels

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

