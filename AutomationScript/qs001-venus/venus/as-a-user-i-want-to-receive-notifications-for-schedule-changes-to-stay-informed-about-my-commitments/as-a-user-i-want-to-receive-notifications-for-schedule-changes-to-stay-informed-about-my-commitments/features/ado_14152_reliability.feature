Feature: Schedule Change Notification System Resilience and Reliability
  As a system administrator
  I want the notification system to remain resilient during infrastructure failures
  So that users continue to receive schedule change notifications even under adverse conditions

  Background:
    Given notification service is operational
    And monitoring and alerting systems are active
    And audit logging is enabled

  @reliability @chaos-engineering @priority-critical @circuit-breaker
  Scenario: Notification service maintains availability during database connection failure with circuit breaker protection
    Given circuit breaker is configured with threshold of 5 failures in 10 seconds
    And schedule database is accessible and healthy
    And message queue is operational
    And 5 active users have scheduled appointments
    And baseline notification delivery time is less than 60 seconds
    And MTBF is greater than 720 hours
    When database connections are terminated using chaos engineering tool
    Then database becomes unavailable
    And connection attempts fail with timeout errors
    When 10 schedule change events are triggered across different user accounts
    Then circuit breaker transitions to "OPEN" state after 5 failed attempts
    And 10 notifications are queued in message queue
    And error logs are generated with appropriate severity
    And notifications are not dropped
    When system health endpoints are checked
    Then service remains operational without crashes
    And circuit breaker status is "OPEN"
    And notification queue depth is 10
    And no memory leaks are detected
    And CPU usage remains below 80 percent
    When database connectivity is restored after 5 minutes
    Then database connection is restored successfully
    And circuit breaker transitions to "HALF-OPEN" state
    When automatic recovery is observed
    Then circuit breaker transitions from "HALF-OPEN" to "CLOSED" after 3 successful requests
    And all 10 queued notifications are processed within 2 minutes
    And MTTR is less than 7 minutes
    When notification delivery is validated for all users
    Then 100 percent notification delivery success is achieved
    And no duplicate notifications are sent
    And notification content is accurate
    And total system downtime for notification feature is 0
    When SLO compliance is verified
    Then availability is 100 percent in degraded mode
    And RTO is less than 7 minutes
    And RPO is 0 with no data loss
    And MTTR is less than 7 minutes meeting SLO target
    And all services are restored to normal operation
    And circuit breaker is in "CLOSED" state
    And notification queue is empty
    And no orphaned notifications exist in the system
    And incident is logged with root cause analysis

  @reliability @failover @priority-critical @retry-logic
  Scenario: Email service provider failure triggers automatic fallback with retry logic
    Given primary email service provider is configured and operational
    And secondary email service provider is configured as fallback
    And retry policy is configured with 3 attempts and exponential backoff of "1s, 2s, 4s"
    And in-app notification service is independent and operational
    And 10 users have valid email addresses and active sessions
    And monitoring alerts are configured for ESP failures
    When 5 schedule changes are triggered
    Then 100 percent delivery success is achieved on both channels
    And average delivery time is 15 seconds for email
    And average delivery time is 5 seconds for in-app notifications
    When primary ESP is configured to return HTTP 503 errors
    Then primary ESP returns 503 errors for all email send requests
    When 10 schedule change events are triggered during ESP outage
    Then system attempts to send emails via primary ESP
    And system receives 503 errors
    And retry logic initiates with exponential backoff at "T+1s, T+2s, T+4s"
    When retry behavior and fallback activation are monitored
    Then system switches to secondary ESP after 3 failed attempts
    And fallback mechanism activates within 10 seconds of initial failure
    And total retry duration is 7 seconds
    When email delivery through secondary ESP is verified
    Then all 10 emails are successfully sent via secondary ESP within 30 seconds
    And all 10 in-app notifications are delivered within 5 seconds
    And total email delivery time is less than 45 seconds
    When primary ESP is restored to healthy state
    And 5 new schedule changes are triggered
    Then system detects primary ESP recovery
    And new notifications route through primary ESP
    And delivery time returns to baseline of less than 15 seconds
    When notification audit trail is validated for all 15 notifications
    Then audit logs show 5 successful deliveries via primary ESP before failure
    And audit logs show 10 successful deliveries via secondary ESP during failure
    And audit logs show 5 successful deliveries via primary ESP after recovery
    And no duplicate emails are sent
    And delivery status accurately reflects channel used
    When resilience metrics are calculated
    Then email channel availability is 100 percent via fallback
    And in-app channel availability is 100 percent
    And MTTR for email channel is less than 45 seconds
    And user impact is 0 missed notifications
    And SLO compliance is 100 percent notification delivery maintained
    And primary ESP is restored and active
    And all notifications are delivered successfully
    And no pending retry queues exist
    And fallback mechanism is reset to monitor primary ESP
    And alert notifications are sent to operations team

  @reliability @load-testing @priority-critical @backpressure
  Scenario: Message queue handles saturation and resource exhaustion under high load with backpressure mechanism
    Given message queue is configured with capacity limit of 500 messages
    And notification service is configured with backpressure handling
    And dead letter queue is configured for failed messages
    And system monitoring tracks queue depth, memory usage, and CPU utilization
    And 1000 test user accounts have scheduled appointments
    And baseline CPU usage is below 40 percent
    And baseline memory usage is below 60 percent
    And baseline queue depth is below 50 messages
    When 100 schedule changes are processed
    Then queue processing rate is 50 messages per second
    And CPU usage is 35 percent
    And memory usage is 55 percent
    And queue depth peaks at 20 messages
    And all notifications are delivered within 60 seconds
    When 1000 simultaneous schedule changes are triggered within 60 seconds
    Then queue depth rapidly increases to 500 messages
    And new messages experience backpressure
    And system detects queue saturation condition
    When backpressure activation and system behavior are monitored
    Then backpressure mechanism activates producer rate limiting
    And queue remains at capacity of 500 messages
    And overflow messages are held in producer buffer
    And overflow messages are not dropped
    And CPU increases to range "75-85" percent
    And memory increases to range "80-85" percent
    And memory remains stable with no leaks
    When priority-based processing is observed
    Then message queue processes messages with priority headers
    And cancellation notifications are processed first
    And system maintains message ordering within priority levels
    And no messages are moved to DLQ due to capacity issues
    When queue drain rate and system recovery are monitored over 10 minutes
    Then queue depth decreases steadily at rate of 50 messages per second
    And queue depth returns to below 50 messages after 10 minutes
    And CPU returns to 40 percent
    And memory stabilizes at 60 percent
    And no service crashes or restarts occur
    When notification delivery completeness is validated
    Then 100 percent notification delivery success is achieved for 1000 notifications
    And no messages exist in DLQ
    And no duplicate notifications are sent
    And average delivery time during spike is 8 minutes
    And post-recovery delivery time returns to less than 60 seconds
    When data integrity is verified
    Then all 1000 schedule changes have corresponding notification records
    And notification content matches schedule change details
    And timestamps show processing order respected priority rules
    And no orphaned notification records exist
    And no corrupted notification records exist
    When resilience metrics are calculated
    Then RPO is 0 with no data loss
    And RTO is not applicable as system remained available
    And availability is 100 percent with degraded performance
    And MTBF is maintained
    And peak delivery latency is 10 minutes within acceptable degraded SLO
    And system successfully handled 20x normal load
    And message queue depth returned to normal below 50 messages
    And system resources returned to baseline levels
    And no messages remain in producer buffers
    And DLQ is empty with no failed messages
    And backpressure mechanism is deactivated
    And performance metrics are logged for capacity planning