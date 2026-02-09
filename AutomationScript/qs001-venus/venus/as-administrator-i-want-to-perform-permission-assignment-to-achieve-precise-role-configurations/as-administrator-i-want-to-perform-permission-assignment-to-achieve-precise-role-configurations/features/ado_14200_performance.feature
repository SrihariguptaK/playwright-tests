Feature: Administrator Permission Assignment Performance and Stability
  As an Administrator
  I want the permission assignment system to handle high load and stress conditions reliably
  So that role configurations remain secure and performant under all operational scenarios

  Background:
    Given production-like test environment is configured
    And monitoring tools are active for system metrics
    And database contains "1000" roles and "500" permissions

  @performance @load @priority-critical @regression
  Scenario: Concurrent permission assignment under peak load maintains performance targets
    Given load testing tool is configured with "50" concurrent admin sessions
    And all admin users are authenticated
    And CPU, memory, and database connection monitoring is enabled
    When "50" concurrent administrators access permission configuration section
    And load test executes POST requests to "/api/roles/{id}/permissions" endpoint with "5" to "10" permissions per assignment
    And system ramps up to peak load over "2" minutes
    And peak load is maintained for "15" minutes with "3" to "5" assignments per user per minute
    Then P50 response time should be less than or equal to "1" second
    And P95 response time should be less than or equal to "1.8" seconds
    And P99 response time should be less than or equal to "2" seconds
    And throughput should be greater than or equal to "150" transactions per second
    And error rate should be less than "0.1" percent
    And CPU utilization should be less than "75" percent
    And memory usage should remain stable with no leaks
    And database connections should be less than "80" percent of pool
    And query execution times should be less than "500" milliseconds
    And "100" random role-permission assignments should be validated in database
    And all permission assignments should be correctly persisted with no duplicates or conflicts
    And audit logs should contain all transactions
    And system should return to idle state within "30" seconds
    And no orphaned database connections should exist

  @performance @stress @priority-high @regression
  Scenario: Permission assignment system handles progressive load increase and recovers gracefully
    Given stress testing tool is configured with progressive load profile
    And baseline performance metrics are established with "50" concurrent users
    And circuit breaker and rate limiting mechanisms are enabled
    And database connection pool is configured with maximum limits
    And alerting systems are active
    When load increases progressively from "50" users by "25" users every "3" minutes
    And system processes requests at each load increment
    Then response times, error rates, and resource utilization should show clear degradation pattern
    And breaking point should be identified when error rate exceeds "5" percent or P99 response time exceeds "10" seconds
    And system should return HTTP status code "429" or "503" instead of crashing
    And users should receive clear error messages
    And existing permission assignments should remain intact
    And no database deadlocks or corruption should occur
    When load is reduced to "50" percent of breaking point
    Then system should recover within "2" minutes
    And response times should return to less than "2" seconds
    And error rate should drop below "0.1" percent
    And system resources should stabilize
    And "200" random permission assignments made during stress period should be validated
    And all successful assignments should be persisted correctly
    And failed requests should be properly rolled back with no partial updates

  @performance @soak @priority-high @regression
  Scenario: Extended duration permission assignment maintains stability without memory leaks
    Given isolated test environment with production-equivalent configuration
    And baseline metrics are captured for memory, CPU, database connections, and response times
    And "30" concurrent admin users are configured for sustained load
    And memory profiling tools are enabled
    And database connection monitoring is active
    And sufficient test data exists for "4" hour continuous operation
    When baseline metrics are recorded showing memory "2" GB, CPU "30" percent, database connections "20", and P95 response time "1.5" seconds
    And sustained load of "30" concurrent administrators perform permission assignments continuously for "4" hours
    And each administrator performs "2" to "3" assignments per minute
    And metrics are recorded every "15" minutes for heap memory, garbage collection, response times, error rates, and database connection pool
    Then total assignments should be between "14400" and "21600" over "4" hours
    And memory growth should be less than "10" percent per hour
    And garbage collection frequency should remain consistent
    And response times should remain within "10" percent of baseline
    And error rate should be less than "0.1" percent
    And no connection pool exhaustion should occur
    And memory heap dumps at "1" hour intervals should show no memory leaks
    And object counts should remain stable
    And no unbounded collection growth should be detected
    And memory should be released after garbage collection cycles
    And database query times should be less than "500" milliseconds
    And no orphaned database connections should exist
    And no lock escalations should occur
    And transaction log should remain within normal bounds
    And "500" permission assignments sampled from different time periods should be validated
    And all sampled assignments should be correctly persisted with accurate timestamps and audit logs
    And no data corruption or inconsistencies should be found
    And system performance should return to baseline within "5" minutes after test completion

  @performance @spike @priority-critical @regression
  Scenario: Sudden traffic surge is handled gracefully with auto-scaling and rate limiting
    Given auto-scaling is configured with appropriate thresholds
    And rate limiting and throttling mechanisms are enabled
    And message queue or request buffer is configured
    And baseline load of "10" concurrent users is established
    And monitoring dashboards are active for real-time observation
    When baseline load with "10" concurrent administrators perform "2" assignments per minute
    Then baseline should be stable with P95 response time "1.2" seconds, throughput "20" TPS, CPU "25" percent, and error rate "0" percent
    When sudden spike increases load from "10" to "100" concurrent users within "30" seconds
    And each user attempts "5" permission assignments immediately
    Then "500" permission assignment requests should be submitted within "30" second window
    And rate limiting should activate returning HTTP status code "429" for excess requests
    And accepted requests should be queued
    And P99 response time should be less than "5" seconds for accepted requests
    And system should not crash
    And auto-scaling should trigger within "60" to "90" seconds if configured
    And additional capacity should be provisioned or queue should process requests within acceptable timeframe
    And queued requests should be processed within "3" to "5" minutes
    And error rate for accepted requests should be less than "1" percent
    And no request data loss should occur
    And all rate-limited requests should receive proper error responses
    When load drops from "100" to "10" concurrent users within "30" seconds
    Then system should scale down gracefully within "5" to "10" minutes
    And response times should return to baseline
    And resources should be deallocated
    And no lingering performance issues should exist
    And all successfully processed permission assignments during spike should be validated
    And all accepted assignments should be correctly persisted
    And no duplicate assignments should exist
    And audit logs should be complete
    And rejected requests should be properly logged with reason codes
    And all queues should be cleared