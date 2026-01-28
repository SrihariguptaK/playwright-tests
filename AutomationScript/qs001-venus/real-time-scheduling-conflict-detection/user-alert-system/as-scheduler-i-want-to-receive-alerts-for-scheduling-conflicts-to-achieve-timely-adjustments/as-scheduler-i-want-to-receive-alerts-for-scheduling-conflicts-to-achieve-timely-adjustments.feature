Feature: User Alert System

  Background:
    Given the application is accessible
    And the user is on the appropriate page

  # Functional Test Scenarios
  Scenario: Validate alert delivery for detected conflicts
    Given User is authenticated and logged into the system
    Given Notification service is running and operational
    Given User has valid contact information (email/phone) configured
    Given User has alert notifications enabled in preferences
    Given At least two scheduling items exist that can create a conflict
    When Create or modify a schedule entry that conflicts with an existing schedule (e.g., overlapping time slots for the same resource)
    Then System detects the scheduling conflict and triggers the conflict detection mechanism
    And System processes the detected conflict and prepares an alert notification
    Then Alert notification is prepared with conflict details including affected schedules, time slots, and resources
    And System sends the alert to the user via configured notification channels (email, SMS, or in-app)
    Then Alert is dispatched successfully through the notification service within 5 seconds of conflict detection
    And User checks their notification channels (email inbox, SMS messages, or in-app notification center)
    Then User receives the alert notification containing the scheduling conflict information
    And User opens and reviews the alert notification
    Then Alert displays complete conflict details including: conflicting schedule names, affected time periods, resources involved, and conflict severity
    And Verify the timestamp of alert delivery against the conflict detection time
    Then Alert delivery timestamp is within 5 seconds of the conflict detection timestamp

  Scenario: Ensure alerts contain actionable insights
    Given User is authenticated and logged into the system
    Given Notification service is operational
    Given A scheduling conflict exists in the system
    Given User has permissions to modify schedules
    Given Alert notification feature is enabled for the user
    When System detects a scheduling conflict and triggers the alert generation process
    Then System initiates alert preparation with conflict analysis
    And System sends an alert notification for the scheduling conflict via the user's preferred notification channel
    Then Alert is dispatched successfully to the user with complete payload
    And User receives and opens the alert notification
    Then Alert notification is displayed to the user
    And User reviews the alert content for conflict details
    Then Alert includes detailed information: conflict description, affected schedules, conflicting time slots, resources involved, and conflict type
    And User examines the actionable insights section of the alert
    Then Alert contains suggested actions such as: reschedule options, alternative time slots, resource reassignment suggestions, or conflict resolution recommendations
    And User selects one of the suggested actions from the alert (e.g., clicks on a reschedule link or navigates to the scheduling interface)
    Then User is directed to the appropriate interface to implement the suggested action
    And User implements the suggested action to resolve the conflict (e.g., modifies schedule time, reassigns resource, or cancels conflicting entry)
    Then Schedule modification is saved successfully
    And System validates that the conflict has been resolved
    Then Conflict is removed from active conflicts list and user receives confirmation that the conflict has been successfully resolved

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

