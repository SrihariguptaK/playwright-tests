Feature: Task Comment System Performance and Scalability
  As a system administrator
  I want the task commenting system to handle high load and traffic spikes efficiently
  So that employees can reliably communicate even during peak usage periods

  Background:
    Given performance monitoring tools are configured and active
    And test environment is configured with production-like infrastructure

  @performance @load-testing @priority-critical @regression
  Scenario: Concurrent comment submission under peak load with response time validation
    Given database is populated with 10000 existing tasks
    And 500 authenticated employee test accounts are created
    And baseline performance metrics are captured for comparison
    When load testing tool is configured to simulate 500 concurrent users with ramp-up time of 60 seconds
    And POST requests to "/api/tasks/{id}/comments" endpoint are executed with comment payloads between 100 and 400 characters for 10 minutes sustained load
    Then all 500 concurrent users should successfully send comment requests continuously
    And P50 response time should be less than or equal to 1.0 seconds
    And P95 response time should be less than or equal to 1.8 seconds
    And P99 response time should be less than or equal to 2.0 seconds
    And throughput should be greater than or equal to 400 transactions per second
    And error rate should be less than 1 percent
    And all comments should be successfully saved to database
    And CPU utilization should be less than 70 percent
    And memory usage should be less than 80 percent
    And database connection pool usage should be less than 85 percent capacity
    And no resource exhaustion should occur
    And comment retrieval and display should complete within 2 seconds for tasks with up to 100 comments
    And all submitted comments should be persisted correctly in database
    And no data corruption or loss should be detected
    And system should return to normal state after load test completion

  @performance @stress-testing @priority-high @regression
  Scenario: Comment system breaking point and graceful degradation validation
    Given test environment is isolated from production
    And system health monitoring dashboards are active
    And database is pre-loaded with 5000 tasks
    And auto-scaling is disabled to identify true breaking point
    And alerting mechanisms are configured for critical thresholds
    When load starts with 500 concurrent users
    And load is incrementally increased by 200 users every 3 minutes until system failure
    Then metrics should be captured at each load level showing progressive degradation patterns
    And breaking point should be identified where error rate exceeds 5 percent or response time exceeds 10 seconds
    And breaking point should be within expected range of 1100 to 1500 concurrent users
    And system should exhibit clear performance degradation at breaking point
    And system should return proper HTTP error codes "503" or "429" instead of crashes
    And no application crashes or unhandled exceptions should occur
    And error messages should be user-friendly
    When load generation is stopped
    Then system should automatically recover within 5 minutes
    And response times should return to baseline
    And no manual intervention should be required
    And no data corruption should be detected
    And all successfully acknowledged comments should be persisted correctly
    And no duplicate entries should exist
    And system should be fully recovered to operational state

  @performance @spike-testing @priority-critical @regression
  Scenario: Sudden traffic surge handling during comment notification burst
    Given auto-scaling policies are configured and enabled
    And notification queue system is operational
    And baseline load of 50 concurrent users is established
    And cloud infrastructure with scaling capabilities is available
    And monitoring alerts are configured for spike detection
    When baseline load with 50 concurrent users submitting comments at rate of 5 comments per minute per user is established
    Then system should operate normally with P95 response time less than 1.5 seconds
    And CPU utilization should be less than 40 percent
    And performance should be stable
    When sudden spike increases load from 50 to 800 concurrent users within 30 seconds
    Then load spike should be executed successfully
    And 800 concurrent users should be actively submitting comments
    And error rate should remain less than 3 percent during first 2 minutes of spike
    And response times may temporarily increase to 3 to 5 seconds but no timeouts should occur
    And notification queue depth should increase but process without blocking
    And auto-scaling should be activated within 3 to 5 minutes
    And additional application instances should be launched
    And load balancer should distribute traffic
    And system should stabilize
    When spike load is maintained for 10 minutes
    Then P95 response time should return to less than 2.5 seconds after scaling
    And error rate should be less than 1 percent
    And throughput should be sustained at 600 or more transactions per second
    And all notifications should be queued successfully
    When load rapidly decreases from 800 to 50 users within 30 seconds
    Then system should handle rapid decrease gracefully
    And auto-scaling should scale down within 10 minutes
    And no errors should occur during scale-down
    And resources should be deallocated properly
    And 100 percent of successfully acknowledged comments should be saved to database
    And notification delivery rate should be greater than 95 percent within 5 minutes of comment submission
    And system should return to baseline performance levels
    And no orphaned resources or memory leaks should be detected