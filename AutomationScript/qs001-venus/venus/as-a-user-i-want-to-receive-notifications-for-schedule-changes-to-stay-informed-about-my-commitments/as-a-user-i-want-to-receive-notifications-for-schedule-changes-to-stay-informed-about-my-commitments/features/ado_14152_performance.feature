Feature: Schedule Change Notification Performance and Reliability
  As a system administrator
  I want the notification system to handle high load and maintain performance
  So that users receive timely notifications even during peak usage periods

  Background:
    Given notification service is deployed and operational
    And performance monitoring tools are configured
    And monitoring and alerting systems are active

  @performance @load @priority-critical @regression
  Scenario: Validate notification delivery performance under peak concurrent schedule changes
    Given 10000 test user accounts are provisioned with active schedules
    And email and in-app notification channels are configured
    And baseline metrics are established for normal load
    When load testing tool is configured to simulate 10000 concurrent schedule changes via "/api/schedules/update" endpoint
    And load test is executed with ramp-up period of 5 minutes to reach 10000 concurrent users
    And load is sustained for 30 minutes
    Then all 10000 schedule changes should be processed successfully without errors
    And P95 notification delivery time should be less than or equal to 60 seconds
    And P99 notification delivery time should be less than or equal to 90 seconds
    And P50 notification delivery time should be less than or equal to 30 seconds
    And "/api/notifications/send" endpoint throughput should be greater than or equal to 500 TPS
    And API response time P95 should be less than or equal to 200 milliseconds
    And error rate should be less than 0.1 percent
    And CPU utilization should be less than 70 percent
    And memory utilization should be less than 80 percent
    And database connection pool should be less than 85 percent capacity
    And message queue lag should be less than 10 seconds
    And at least 95 percent of notifications should be delivered within 60 seconds
    And all test notifications should be delivered successfully
    And system should return to normal resource utilization within 5 minutes
    And no memory leaks or resource exhaustion should be detected

  @performance @spike @priority-critical @regression
  Scenario: Validate notification system resilience during sudden traffic spike from mass schedule update
    Given auto-scaling policies are configured for notification service
    And message queue system is configured with appropriate capacity
    And 15000 test user accounts are ready
    And circuit breaker patterns are implemented
    And baseline load with 100 concurrent users making schedule changes is established
    And system operates normally with P95 notification delivery less than 30 seconds
    When sudden spike to 15000 concurrent schedule changes is triggered within 30 seconds
    Then all 15000 schedule change requests should be accepted by the system
    And HTTP responses should be 200 or 202 status codes
    And auto-scaling should trigger within 60 seconds
    And additional instances should be provisioned to handle load
    And target instance count should be reached within 3 minutes
    And message queue depth should increase but remain less than 50000 messages
    And no message loss should occur
    And processing rate should increase proportionally with scaling
    And P95 notification delivery time during spike should be less than or equal to 5 minutes
    And P99 notification delivery time during spike should be less than or equal to 8 minutes
    When load is reduced back to 100 users after 10 minutes
    Then P95 notification delivery time should return to less than or equal to 60 seconds
    And error rate should be less than 1 percent
    And system should scale down gracefully within 10 minutes
    And all queued notifications should be processed
    And no notifications should be lost
    And all 15000 notifications should be eventually delivered
    And system should successfully scale back to baseline capacity
    And no service crashes or unhandled exceptions should occur
    And message queue should be cleared within 15 minutes of spike end

  @performance @soak @endurance @priority-high @regression
  Scenario: Validate notification system stability and resource management over 24-hour continuous operation
    Given 5000 test user accounts are provisioned
    And sufficient infrastructure resources are allocated for 24 hour test
    And monitoring dashboards are configured for long-term metric collection
    And database maintenance windows are not scheduled during test period
    When endurance test is configured with 5000 concurrent users
    And each user experiences 2 to 3 schedule changes per hour randomly distributed over 24 hours
    And endurance test is started
    Then test configuration should generate approximately 240000 to 360000 total schedule changes over 24 hours
    And initial baseline P95 delivery time should be less than or equal to 60 seconds
    And throughput should be stable at approximately 350 TPS
    And error rate should be less than 0.1 percent
    When notification delivery performance metrics are monitored every hour
    Then memory utilization should remain stable at less than 80 percent
    And no continuous upward trend indicating memory leaks should be detected
    And garbage collection frequency should remain consistent
    And database connections should remain within pool limits
    And no connection leaks should occur
    And query response times should remain consistent with variance less than 15 percent from baseline
    And message processing rate should remain consistent
    And dead letter queue accumulation should be less than 0.5 percent of total messages
    And no queue overflow events should occur
    When performance metrics are compared at hour 1, 8, 16, and 24
    Then P95 notification delivery time degradation should be less than 10 percent from baseline
    And throughput variance should be less than 5 percent
    And no service restarts should be required
    And 95 percent SLA should be maintained throughout 24 hour period
    When logs are analyzed for errors, exceptions, and warning patterns
    Then no critical errors should be found
    And exception rate should remain stable
    And no cascading failures or timeout patterns should emerge
    And system should remain operational after 24 hour test
    And all notifications should be successfully delivered
    And no manual intervention should be required during test period
    And performance metrics should return to baseline after test completion