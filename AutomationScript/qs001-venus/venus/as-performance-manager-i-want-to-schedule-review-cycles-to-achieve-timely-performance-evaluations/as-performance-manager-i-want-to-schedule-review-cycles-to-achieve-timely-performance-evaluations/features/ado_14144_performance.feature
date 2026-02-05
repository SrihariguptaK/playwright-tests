Feature: Performance testing for review cycle scheduling system
  As a Performance Manager
  I want the review cycle scheduling system to handle high load efficiently
  So that performance evaluations can be scheduled reliably even during peak usage periods

  Background:
    Given performance testing environment is configured with production-like specifications
    And monitoring tools are active for system metrics
    And test user accounts with Performance Manager role are provisioned

  @performance @load @priority-critical @regression
  Scenario: Validate review cycle scheduling performance under peak concurrent user load
    Given review cycles database is populated with 1000 existing review cycles
    And load testing tool is configured and ready
    And 500 test user accounts are provisioned
    When load test is configured to simulate 500 concurrent Performance Managers with 30 second ramp-up time
    And each user navigates to review cycle management page
    And each user selects review frequency from available options
    And each user saves schedule via POST "/api/review-cycles/schedule" endpoint
    And load test executes for 15 minutes sustained duration
    Then all 500 users should complete workflow without errors
    And page load P50 response time should be less than or equal to 1.2 seconds
    And page load P95 response time should be less than or equal to 1.8 seconds
    And page load P99 response time should be less than or equal to 2.0 seconds
    And API POST P50 response time should be less than or equal to 800 milliseconds
    And API POST P95 response time should be less than or equal to 1.5 seconds
    And API POST P99 response time should be less than or equal to 2.0 seconds
    And throughput should be greater than or equal to 30 transactions per second
    And error rate should be less than 0.1 percent
    And HTTP 200 success rate should be greater than 99.5 percent
    And CPU utilization should be less than 75 percent
    And memory utilization should be less than 80 percent
    And database connection pool should be less than 85 percent capacity
    And no connection timeouts should occur
    And zero overlapping review cycles should be detected in database
    And all validation rules should be enforced
    And 100 percent data consistency should be maintained
    And all scheduled review cycles should be persisted correctly in database
    And no orphaned or corrupted records should exist
    And system should return to idle state with normal resource utilization
    And application logs should contain no errors or warnings related to performance

  @performance @stress @priority-high @regression
  Scenario: Identify system breaking point and validate graceful degradation when scheduling review cycles beyond capacity
    Given system is in stable state with normal resource utilization
    And database has 5000 existing review cycles for realistic load
    And auto-scaling is disabled to identify true breaking point
    And circuit breakers and rate limiters are configured
    And alerting and monitoring systems are active
    And backup and rollback procedures are documented and ready
    When stress test starts with 200 concurrent users
    And user load increases by 200 users every 5 minutes incrementally
    And response times, error rates, and system resources are monitored at each load increment
    Then load generator should successfully ramp up users in incremental steps
    And metrics should be captured at each increment showing progressive degradation pattern
    And breaking point should be identified where response time exceeds 5 seconds or error rate exceeds 5 percent
    And breaking point should be within expected range of 800 to 1200 concurrent users
    And system should exhibit predictable degradation pattern
    And rate limiter should activate with HTTP 429 responses
    And queue depth should increase but not overflow
    And users should receive "System busy, please retry" messages instead of crashes
    When load generation is stopped
    Then system should recover to normal state within 5 minutes
    And all queued requests should be processed
    And no data loss or corruption should occur
    And resource utilization should return to baseline
    And no deadlocks should be detected
    And all transactions should be completed or rolled back properly
    And database consistency checks should pass
    And system should be fully operational and responsive
    And all scheduled review cycles during test should be either completed or properly failed with rollback
    And no memory leaks or resource exhaustion should be detected
    And breaking point threshold should be documented for capacity planning

  @performance @spike @priority-critical @regression
  Scenario: Validate system handling of sudden traffic spike during review cycle scheduling with auto-scaling response
    Given auto-scaling policies are configured and enabled
    And scale up threshold is set at 70 percent CPU utilization
    And scale down threshold is set at 30 percent CPU utilization
    And cloud infrastructure has capacity for horizontal scaling up to 10 instances
    And load balancer is configured and health checks are active
    And database connection pooling is optimized for burst traffic
    And caching layer is operational
    When baseline load with 50 concurrent users is established for 5 minutes
    Then system should operate normally with P95 response time less than 1.5 seconds
    And CPU utilization should be approximately 40 percent
    And 2 application instances should be running
    When sudden spike to 500 concurrent users occurs within 30 seconds
    Then load generator should successfully create spike from 50 to 500 users in 30 seconds
    And initial response time spike to 3 to 4 seconds should be acceptable
    And error rate should remain less than 2 percent
    And no HTTP 500 errors should occur
    And auto-scaling should trigger within 60 seconds
    And additional instances should provision within 90 seconds
    And system should scale to 6 to 8 instances
    And response times should stabilize to P95 less than 2.5 seconds within 3 minutes
    And throughput should increase to greater than 80 transactions per second
    When spike load is maintained for 10 minutes
    Then response times should remain stable with P95 less than 2.5 seconds
    And P99 response time should be less than 3.5 seconds
    And error rate should be less than 0.5 percent
    And CPU per instance should be less than 75 percent
    And no database connection exhaustion should occur
    When load rapidly decreases back to 50 users within 30 seconds
    Then system should handle rapid decrease gracefully
    And auto-scaling should initiate scale-down after 5 minute cooldown
    And instances should reduce to 2 to 3
    And no in-flight requests should be dropped
    And zero duplicate review cycles should be created
    And all validation rules should be enforced during spike
    And no overlapping cycles should exist
    And 100 percent data consistency should be maintained across all scheduled reviews
    And system should return to baseline performance with 2 instances
    And all review cycles scheduled during spike should be valid and persisted
    And no orphaned resources or zombie instances should remain
    And auto-scaling metrics and logs should be captured for analysis
    And cache hit ratio and effectiveness during spike should be documented