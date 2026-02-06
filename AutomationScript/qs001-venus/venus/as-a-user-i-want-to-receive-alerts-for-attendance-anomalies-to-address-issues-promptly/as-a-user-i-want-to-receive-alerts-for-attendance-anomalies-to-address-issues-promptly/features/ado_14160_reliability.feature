Feature: Attendance Anomaly Alert System Resilience and Reliability
  As a system administrator
  I want the attendance alert system to remain resilient during failures
  So that all attendance anomalies are reliably detected and reported without data loss

  @reliability @critical @priority-critical @database-failure @resilience
  Scenario: Alert service maintains resilience during database connection failure
    Given attendance anomaly detection service is running
    And database connection is healthy
    And message queue buffer system is configured
    And monitoring tools are active to track MTTR
    And baseline is established by generating 10 test attendance anomalies
    And all 10 alerts are delivered successfully within 5 minutes
    When database connection is terminated
    Then database connection failure should be detected
    And service should log error but remain operational
    When 15 attendance anomalies are generated during database outage
    Then alerts should be queued in message buffer
    And no alerts should be lost
    And circuit breaker should open to prevent cascading failures
    When system behavior is monitored for 10 minutes during outage
    Then service should remain responsive
    And health check endpoint should return degraded status
    And no memory leaks or resource exhaustion should be observed
    When database connection is restored
    Then service should automatically detect restored connection
    And circuit breaker should transition to half-open state
    And circuit breaker should transition to closed state within 2 minutes
    And all 15 queued alerts should be delivered within 5 minutes of recovery
    And no data loss should occur
    And total system availability should be at least 99.5 percent

  @reliability @critical @priority-critical @network-chaos @latency
  Scenario: Alert dispatch maintains resilience under network partition and latency injection
    Given alert notification service is operational
    And multiple notification channels are configured with "email" and "SMS" and "in-app"
    And network chaos tools are configured
    And baseline alert delivery rate is established at 100 percent
    And hypothesis is defined as "Alert system will maintain 95% delivery rate within 10 minutes despite 30% network packet loss and 2000ms latency injection"
    And blast radius is limited to notification service only
    When 20 test alerts are sent to establish steady state
    Then baseline metrics should show 100 percent delivery rate
    And average delivery time should be less than 5 minutes
    And MTBF baseline should be established
    When 30 percent packet loss is applied to network path
    And 2000 millisecond latency is injected to network path for 15 minutes
    Then network degradation should be applied successfully
    And service should detect increased latency and packet loss
    When 25 attendance anomaly alerts are generated during chaos period
    Then retry mechanism should activate with exponential backoff
    And alerts should queue for retry
    And at least 20 alerts out of 25 should be delivered within chaos window
    And circuit breaker should open for failed channels
    And system should automatically failover to alternative notification channels
    When network chaos is removed
    Then all remaining queued alerts should be delivered within 5 minutes
    And final delivery rate should be at least 95 percent
    And MTTR should be less than or equal to 5 minutes
    And system should return to steady state
    And no duplicate alert notifications should be sent

  @reliability @high @priority-high @circuit-breaker @failover
  Scenario: External notification API failure triggers circuit breaker and automatic failover
    Given multiple notification providers are configured with primary and fallback
    And circuit breaker is configured with 50 percent error rate threshold
    And circuit breaker is configured with 10 request minimum threshold
    And fallback notification mechanism is available
    And API mock service is ready to simulate failures
    When primary email API is configured to return "503" status code for all requests
    Then email API mock should be configured to simulate complete outage
    When 15 attendance anomaly alerts requiring email notifications are generated
    Then system should attempt to send via primary email API
    And system should receive "503" errors
    And circuit breaker should track failure rate
    And circuit breaker should open after 5 consecutive failures
    And circuit breaker should open within 30 seconds
    And system should stop calling failed email API
    And logs should indicate circuit breaker state change to "OPEN"
    And automatic failover to secondary notification channel should occur
    And all 15 alerts should be successfully delivered via fallback channel within 7 minutes
    And no user-facing errors should occur
    And availability should be maintained at least 99 percent
    When primary email API is restored to healthy state
    And system waits for circuit breaker half-open period of 5 minutes
    Then circuit breaker should transition to "HALF-OPEN" state
    And system should send test request to primary API
    When 5 new alerts are generated
    Then primary email API should successfully deliver alerts
    And circuit breaker should close after 3 consecutive successes
    And system should return to normal operation

  @reliability @critical @priority-critical @data-integrity @crash-recovery
  Scenario: Alert data integrity is maintained during service crash and recovery
    Given alert service is running with transaction logging enabled
    And database with ACID compliance is configured
    And alert processing queue with persistence is enabled
    And backup and recovery mechanisms are configured
    When processing of 30 attendance anomaly alerts is initiated in batches of 10
    Then first batch of 10 alerts should begin processing
    And alerts should be written to persistent queue with transaction IDs
    When alert service process is forcefully terminated during processing of second batch
    Then service should crash immediately
    And in-flight transactions should be interrupted
    And service should become unavailable
    And first batch of 10 alerts should be successfully committed to database
    And all 10 alerts from first batch should be persisted with "DELIVERED" status
    And no partial or corrupted records should be found
    And second batch alerts should be rolled back or marked as "PENDING"
    And no alerts should be marked as delivered when they were not
    And data integrity should be maintained
    When alert service is restarted
    Then service should restart automatically within 2 minutes
    And service should perform recovery routine checking for incomplete transactions
    And automatic reprocessing of 20 pending alerts should occur without duplicates
    And all 20 remaining alerts should be processed successfully within 5 minutes
    And no duplicate alerts should be sent
    And total data loss should be 0
    And alert audit log should show complete history
    When end-to-end alert count and delivery status is validated in database
    Then exactly 30 alerts should exist in database with unique IDs
    And all alerts should be marked as "DELIVERED"
    And no orphaned or duplicate records should exist
    And transaction log should show proper rollback and replay