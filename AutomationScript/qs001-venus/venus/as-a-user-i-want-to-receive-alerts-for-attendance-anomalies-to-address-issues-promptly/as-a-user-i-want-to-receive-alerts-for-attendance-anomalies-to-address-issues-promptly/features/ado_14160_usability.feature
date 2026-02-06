Feature: Attendance Anomaly Alert System
  As a User
  I want to receive alerts for attendance anomalies
  So that I can address issues promptly and maintain compliance

  Background:
    Given user is logged into the attendance system
    And attendance data is being actively monitored

  @undefined @usability @priority-critical @smoke
  Scenario: Real-time visibility of alert delivery status and anomaly detection progress
    Given test anomaly data is prepared for "late arrival" scenario
    And user has appropriate permissions to view alerts
    When user triggers an attendance anomaly with "30" minutes late arrival
    Then system should display visual indicator showing "anomaly detection is in progress"
    And processing icon or status message should be visible
    When user observes the interface during the alert generation window
    Then progress indicator should show "Analyzing attendance data" with timestamp
    Or status message should show "Alert being generated" with timestamp
    When user waits for alert to be dispatched
    Then system should display confirmation message "Alert sent to [User Name] and [Manager Name]" with timestamp
    And delivery status should be visible
    When user checks alert notification center
    Then alert should appear with status indicators "New/Read/Acknowledged"
    And timestamp of alert generation should be displayed
    When user navigates away from alerts page
    And user returns to the alerts page
    Then system should maintain and display current status of all alerts
    And page refresh should not be required

  @undefined @usability @priority-high @functional
  Scenario Outline: Alert language uses familiar terminology and clear anomaly descriptions
    Given multiple types of attendance anomalies are configured
    And user has no prior training on system terminology
    And alert notification system is active
    When user triggers "<anomaly_type>" anomaly
    Then alert message should use "<expected_language>" instead of technical terms
    And alert should include contextual information with date and time
    And alert should include location if applicable
    And anomaly type should be labeled as "<friendly_label>"
    And action items should use clear imperative language
    And visual icons should be displayed alongside text

    Examples:
      | anomaly_type          | expected_language                                                                      | friendly_label      |
      | late arrival          | You arrived 30 minutes late today at 9:30 AM (scheduled: 9:00 AM)                     | Late Arrival        |
      | unauthorized absence  | You were marked absent on [date] without prior approval                                | Missed Shift        |
      | early departure       | You left 45 minutes early today at 4:15 PM (scheduled: 5:00 PM)                       | Early Departure     |
      | extended break        | Your break exceeded the allowed time by 20 minutes                                     | Extended Break      |

  @undefined @usability @priority-high @functional
  Scenario: Alert information is visible without requiring recall of previous screens
    Given user has received multiple attendance alerts over time
    And historical alert records are accessible
    When user opens a single alert notification without viewing other screens
    Then alert should display complete information including anomaly type
    And alert should display date and scheduled time
    And alert should display actual time and deviation amount
    And alert should display affected shift and location
    When user checks alert for policy reference
    Then alert should show relevant policy snippet
    And policy snippet should display "Policy allows 15-minute grace period"
    When user reviews available actions from the alert
    Then alert should display "Acknowledge" button
    And alert should display "Explain Reason" button
    And alert should display "View Full Attendance Record" link
    And alert should display "Contact Manager" link
    When user accesses historical alerts list
    Then each historical alert should show summary information in list view
    And summary should include date, type, and status
    And user should not need to open each alert to recall details
    When user checks for manager information in alert
    Then alert should display manager name and contact method
    And manager email should be visible

  @undefined @usability @priority-critical @negative
  Scenario: Alert delivery failure provides clear recovery guidance
    Given test environment can simulate alert delivery failures
    When alert delivery fails due to email service down
    Then system should display message "Alert could not be delivered via email. You can view it here in your notification center. We will retry delivery in 10 minutes."
    And generic error messages like "Error 500" should not be displayed
    And "Retry" button should be available

  @undefined @usability @priority-critical @negative
  Scenario: Attempting to acknowledge already resolved alert shows clear message
    Given alert has been resolved by manager
    When user attempts to acknowledge the resolved alert
    Then error message should state "This alert was already resolved by your manager on [date]. No action needed from you."
    And "View Resolution Details" option should be available

  @undefined @usability @priority-critical @negative
  Scenario: API unavailability provides helpful error message with retry option
    Given API endpoint is unavailable
    When user tries to access alert details
    Then message should display "We cannot load alert details right now. Your alert summary: [brief text]. Try refreshing in a moment or contact support at [contact]."
    And "Retry" button should be visible

  @undefined @usability @priority-high @negative
  Scenario Outline: Form validation provides specific guidance for missing information
    Given user is submitting an explanation for an anomaly
    When user submits explanation with missing "<missing_field>"
    Then validation message should highlight specific missing fields
    And message should state "<validation_message>"
    And inline field highlighting should be displayed

    Examples:
      | missing_field              | validation_message                                                                                    |
      | reason for late arrival    | Please provide: 1) Reason for late arrival, 2) Supporting documentation (if applicable)              |
      | supporting documentation   | Please provide: 1) Reason for late arrival, 2) Supporting documentation (if applicable)              |
      | both required fields       | Please provide: 1) Reason for late arrival, 2) Supporting documentation (if applicable)              |

  @undefined @usability @priority-medium @negative
  Scenario: Permission denied error provides clear contact information
    Given user lacks permission to view manager-only notes
    When user attempts to access restricted alert details
    Then message should explain "You do not have permission to view manager-only notes. Contact your manager or HR for access."
    And clear contact information should be displayed
    And "Request Access" button should be available

  @undefined @functional @priority-critical @performance
  Scenario: Attendance anomaly detection and alert dispatch within performance threshold
    Given attendance data is being monitored in real-time
    When system detects attendance anomaly for "late arrival"
    Then anomaly should be detected within "5" minutes
    And alert should be generated within "5" minutes of detection
    And alert should be dispatched to user and manager
    And alert timestamp should be recorded

  @undefined @functional @priority-high @regression
  Scenario: Historical record of attendance alerts is maintained
    Given user has received attendance alerts over time
    When user navigates to "Attendance Alerts History" page
    Then historical record of all attendance alerts should be displayed
    And each alert should show anomaly type and date
    And each alert should show status and resolution details
    And alerts should be sortable by date
    And alerts should be filterable by type and status