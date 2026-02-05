Feature: Schedule Change Notification System Performance and Resilience
  As a system administrator
  I want the notification system to handle high load and maintain stability
  So that users reliably receive schedule change notifications even during peak usage

  Background:
    Given notification service is deployed and operational
    And monitoring tools are configured to capture performance metrics
    And email service and in-app notification channels are operational

  @performance @load @priority-critical @regression
  Scenario: Validate notification delivery performance under peak concurrent schedule changes
    Given "10000" test user accounts with valid notification preferences are configured
    And schedule database is populated with baseline schedules
    And load testing tool is configured to simulate "10000" concurrent users
    When load test triggers "10000" schedule change events simultaneously via "/api/notifications/send" endpoint
    Then all "10000" schedule change events should be accepted with HTTP "200" or "202" responses
    And P95 detection latency should be less than or equal to "15" seconds
    And P99 detection latency should be less than or equal to "30" seconds
    And "95" percent of notifications should be delivered within "60" seconds
    And P50 delivery time should be less than or equal to "20" seconds
    And P95 delivery time should be less than or equal to "50" seconds
    And P99 delivery time should be less than or equal to "60" seconds
    And CPU utilization should be less than or equal to "75" percent
    And memory utilization should be less than or equal to "80" percent
    And no memory leaks should be detected
    And error rate should be less than "0.1" percent
    And system should maintain minimum "200" transactions per second for notification dispatch
    And "100" percent of sampled notifications should contain correct schedule change details
    And all test notifications should be logged and retrievable
    And system should return to baseline resource utilization within "5" minutes
    And no database connection pool exhaustion should occur

  @performance @spike @priority-critical @regression
  Scenario: Validate notification system resilience during sudden traffic spike from mass schedule changes
    Given notification service with auto-scaling is configured
    And message queue system is operational with sufficient capacity
    And "25000" test user accounts are configured
    And circuit breaker and rate limiting mechanisms are configured
    And monitoring dashboards are active for real-time observation
    And baseline load with "100" concurrent users is established
    When system operates with baseline load of "100" concurrent users
    Then P95 response time should be less than or equal to "5" seconds
    And error rate should be "0" percent
    When load increases from "100" to "25000" concurrent schedule changes within "30" seconds
    Then system should accept all incoming requests without immediate failures
    And auto-scaling should trigger within "60" seconds
    And additional instances should be provisioned within "2" to "3" minutes
    And "95" percent of notifications should be delivered within "5" minutes
    And no notifications should be lost
    And error rate should be less than "1" percent
    And queue depth should remain less than "100000" messages
    And processing rate should increase proportionally with scaling
    When load reduces back to baseline "100" users within "30" seconds
    Then system should process queued notifications
    And system should auto-scale down gracefully within "10" minutes
    And "100" percent notification delivery should be achieved within "10" minutes of spike end
    And no data loss should occur
    And all queued notifications should be processed and delivered
    And system should scale back to baseline capacity
    And no orphaned processes or zombie instances should exist
    And circuit breakers should reset to normal state
    And audit logs should capture all notification events

  @performance @soak @endurance @priority-high @regression
  Scenario: Validate notification system stability and resource management over 24-hour continuous operation
    Given notification service is deployed with production-equivalent configuration
    And "2000" test user accounts with realistic schedule patterns are configured
    And database connection pool is configured with production settings
    And monitoring and alerting are configured for "24" hour observation
    And baseline performance metrics are captured
    When endurance test with "2000" concurrent users generates schedule changes at "50" changes per minute
    Then test should execute continuously for "24" hours
    And P95 response time should remain less than or equal to "60" seconds throughout duration
    And memory utilization should remain stable with variance within "5" percent
    And no continuous upward trend indicating memory leaks should be detected
    And heap size should remain stable
    And no connection pool exhaustion should occur
    And active connections should remain within configured limits
    And no connection timeout errors should occur
    And CPU utilization should remain stable in "60" to "75" percent range
    And no thread leaks should be detected
    And thread pool size should remain within normal bounds
    And delivery success rate should remain greater than or equal to "99.5" percent throughout test
    And P95 latency variance should be less than "10" percent between measurements at hours "1", "6", "12", "18", and "24"
    And error rate should remain less than "0.1" percent
    And no critical errors should occur
    And no cascading failures should occur
    And log file rotation should work properly
    And disk space utilization should remain stable
    And log rotation should prevent disk exhaustion
    And no I/O bottlenecks should occur
    And system should remain operational after "24" hour test
    And all notifications should be delivered successfully
    And performance metrics should be documented for trend analysis