Feature: Attendance Anomaly Alert System Edge Cases
  As a User
  I want the attendance alert system to handle edge cases reliably
  So that I receive accurate and timely notifications for attendance anomalies under all conditions

  Background:
    Given user is logged into the system with valid credentials
    And attendance monitoring system is active and running

  @edge @regression @priority-high
  Scenario: Multiple simultaneous anomalies for same user generate separate alerts
    Given test user has multiple attendance anomalies configured to occur simultaneously
    And manager account is configured to receive alerts for the test user
    When system triggers "late arrival" anomaly at "9:15 AM"
    And system triggers "missing clock-in" anomaly at "9:15 AM"
    And system triggers "unauthorized break extension" anomaly at "9:15 AM"
    Then system should detect all 3 anomalies within 5 minutes
    When user navigates to "Alerts Dashboard" page
    Then user should see 3 separate alerts displayed
    And each alert should have distinct anomaly description
    And each alert should have unique timestamp
    When manager checks alert inbox
    Then manager should receive 3 separate alert notifications
    And each alert should contain specific anomaly details
    And each alert should contain suggested actions
    When user verifies alert delivery timestamps
    Then all alerts should be delivered within 5 minutes of detection
    And each alert should have unique alert ID
    When user acknowledges each alert individually
    Then each alert should be acknowledged separately
    And acknowledgment status should be tracked independently for each anomaly
    And all 3 anomalies should be recorded in attendance alerts history
    And system performance should remain stable
    And alert counters should accurately reflect 3 separate anomalies

  @edge @regression @priority-high
  Scenario: Alert generated at exact 5-minute detection threshold boundary
    Given system clock is synchronized with attendance tracking system
    And attendance anomaly detection service is running
    And test environment allows precise timestamp manipulation
    When user creates "late arrival" anomaly at timestamp "T"
    Then anomaly should be recorded in attendance database with timestamp "T"
    When system monitors alert generation at timestamp "T+4:59"
    Then alert should be generated within 5 minute SLA
    And alert should be dispatched to user and manager
    When user verifies alert timestamp in alerts log
    Then alert should show detection time within 5 minutes
    And exact timestamps should be logged for anomaly occurrence
    And exact timestamps should be logged for alert dispatch
    When user checks alert content
    Then alert should contain correct anomaly type
    And alert should contain correct timestamp
    And alert should contain correct user details
    And alert should contain suggested actions
    And alert timestamp data should be accurately recorded in system logs
    And alert acknowledgment functionality should be available

  @edge @regression @priority-high
  Scenario: Alert delivery when user has no assigned manager
    Given test user account has no manager assigned in organizational hierarchy
    And attendance anomaly detection rules are configured
    When user verifies profile manager status
    Then user profile should display "No Manager Assigned" status
    When system triggers "late arrival" anomaly with "30" minutes delay
    Then system should detect anomaly within 5 minutes
    When user checks alert inbox
    Then user should receive alert with anomaly details
    And user should receive alert with suggested actions
    When user verifies system behavior for manager notification
    Then system logs should show alert attempted for manager
    And system should gracefully handle missing manager scenario
    And fallback notification should be sent to designated backup recipient
    When user checks error logs
    Then no critical errors should be logged
    And system should record missing manager scenario with warning level log entry
    And user should receive alert successfully despite missing manager
    And system should maintain alert history with missing manager notation
    And no system errors should occur due to missing manager reference

  @edge @regression @priority-high
  Scenario: Alert delivery when manager account is inactive
    Given test user has assigned manager with inactive account status
    And attendance monitoring system is active
    And attendance anomaly detection rules are configured
    When system triggers "late arrival" anomaly for user
    Then system should detect anomaly within 5 minutes
    When user checks alert inbox
    Then user should receive alert with anomaly details
    When user verifies manager notification handling
    Then system should detect inactive manager account
    And system should send fallback notification to HR admin
    And no critical errors should be logged
    And alert history should record inactive manager scenario

  @edge @regression @priority-medium
  Scenario: Alert system handles extremely large volume of simultaneous anomalies
    Given system has 500 active users configured in attendance system
    And load testing environment is available
    And database has sufficient capacity for high-volume alert storage
    When system triggers attendance anomalies for 500 users simultaneously
    Then system should begin processing all 500 anomalies without crashing
    When user monitors alert generation over next 5 minutes
    Then system should generate alerts for all 500 users
    And system should dispatch alerts for all 500 users
    And at least 95 percent of alerts should be delivered within 5 minute SLA
    When user checks system performance metrics
    Then CPU usage should remain below 80 percent
    And memory usage should remain below 85 percent
    And no connection pool exhaustion should occur
    When user verifies alert accuracy by sampling 50 random alerts
    Then all sampled alerts should contain correct user information
    And all sampled alerts should contain correct anomaly details
    And all sampled alerts should contain correct timestamps
    And no data corruption should be present
    When user tests alert dashboard during high load
    Then alert dashboard should remain responsive
    And page load times should be under 3 seconds
    And acknowledgment functionality should work correctly
    And all 500 alerts should be recorded in attendance alerts history
    And system performance should return to normal levels
    And no data loss should occur during high-volume processing

  @edge @regression @priority-medium
  Scenario Outline: Alert content displays special characters and Unicode correctly
    Given attendance system supports custom anomaly descriptions
    And alert display interface is accessible
    When user creates attendance anomaly with description "<description>"
    Then system should accept and store anomaly description
    And all special characters should remain intact
    When user navigates to "Alerts Dashboard" page
    Then alert should display correctly with proper character encoding
    And no layout breaks should occur
    When user acknowledges alert
    Then acknowledgment functionality should work correctly
    And confirmation message should display properly
    And alert description should be stored in database with correct encoding
    And alert history should maintain data integrity

    Examples:
      | description                                                                                                    |
      | Late arrival @9:45 AM - Traffic on I-95 & Route 128 (50% delay) #incident-2024                               |
      | Usuario llegó tarde - 遅刻 - تأخير - Задержка - 30 minutos                                                    |
      | Extended absence due to medical emergency requiring immediate attention and documentation submission within the next 24-48 hours as per company policy outlined in employee handbook section 4.2.3 regarding unplanned absences and proper notification procedures to be followed by all employees regardless of tenure or position level in the organizational hierarchy with appropriate manager approval and HR documentation |

  @edge @regression @priority-low
  Scenario: Alert acknowledgment prevents duplicate processing on rapid clicks
    Given user has active session
    And at least 1 unacknowledged attendance anomaly alert exists
    And alert acknowledgment API endpoint is accessible
    When user navigates to "Alerts Dashboard" page
    Then alert should be displayed with "Acknowledge" button enabled
    When user clicks "Acknowledge" button 10 times rapidly within 2 seconds
    Then system should process first acknowledgment only
    And system should prevent duplicate acknowledgments
    When user verifies alert status
    Then alert should show as acknowledged exactly once
    And alert should have single acknowledgment timestamp
    And no duplicate acknowledgment records should exist
    When user checks system logs and database
    Then only 1 acknowledgment record should exist in database
    And no error logs related to duplicate processing should exist
    When user verifies UI state
    Then "Acknowledge" button should be disabled
    And alert status should show "Acknowledged" with timestamp
    And alert status should show user who acknowledged
    And alert history should show single acknowledgment event
    And system should remain stable with no performance degradation

  @edge @regression @priority-medium
  Scenario: Alert timestamps handle timezone differences correctly
    Given system is configured to handle timezone-aware timestamps
    And test environment allows simulation of timezone changes
    And attendance anomaly detection service is running
    When user configures test user in "Pacific" timezone
    And user configures manager in "Eastern" timezone
    Then user profile should show "PST" timezone setting
    And manager profile should show "EST" timezone setting
    When user creates attendance anomaly at "9:00 AM PST"
    Then anomaly should be recorded with UTC timestamp
    And anomaly should be recorded with timezone information
    When user checks alert as affected user
    Then user should see alert showing "9:00 AM PST" for anomaly time
    When manager checks alert
    Then manager should see alert showing "12:00 PM EST" for same anomaly
    When user checks alert history
    Then all timestamps should be stored in UTC in database
    And timestamps should display correctly in user local timezone
    And no time calculation errors should occur

  @edge @regression @priority-medium
  Scenario: Alert system handles daylight saving time transitions correctly
    Given system is configured to handle timezone-aware timestamps
    And test environment allows simulation of timezone changes
    And attendance anomaly detection service is running
    When user simulates daylight saving time transition
    And user creates attendance anomaly during DST transition
    Then system should correctly adjust timestamps for DST
    And alerts should show accurate local times with DST notation
    When user checks alert history
    Then alert history should correctly handle DST transitions
    And no duplicate time periods should exist
    And no missing time periods should exist
    And 5 minute SLA should be calculated correctly regardless of timezone differences