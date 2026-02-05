Feature: Task Commenting System Reliability and Resilience
  As an Employee
  I want the task commenting system to remain reliable under failure conditions
  So that I can communicate with team members without data loss or service disruption

  Background:
    Given employee is authenticated
    And employee is on task details page
    And baseline system metrics are established

  @reliability @critical @priority-critical @chaos-engineering
  Scenario: Database connection failure during comment submission with recovery validation
    Given database monitoring tools are configured
    And circuit breaker is enabled with failure threshold of 5
    And chaos engineering tool is configured
    And baseline SLI metrics are captured with "99.5" percent availability and MTTR less than 30 seconds
    And employee submits 10 comments successfully with average response time less than 2 seconds
    When database connection failure is injected using chaos tool
    And database becomes unreachable with connection timeout after 3 seconds
    And employee enters "Critical update on task progress" in comment field
    And employee clicks "Save" button
    Then system should detect database failure
    And circuit breaker should open after retry attempts
    And error message "Unable to save comment. Please try again in a moment." should be displayed
    And comment should remain in UI without data loss
    When employee attempts 3 more comment submissions while database is down
    Then circuit breaker should remain open
    And fast-fail responses should be returned within 500 milliseconds
    And consistent error messaging should be displayed
    When database connection is restored
    And system waits for circuit breaker half-open state for 60 seconds
    And employee submits a new test comment
    Then comment should save successfully
    And circuit breaker should close
    And system should return to normal operation within MTTR target of 30 seconds
    And original comment data integrity should be verified
    And no orphaned transactions should exist
    And no partial data should exist in database
    And transaction should be properly rolled back
    When system is monitored for 5 minutes post-recovery
    Then system should achieve 100 percent success rate
    And response times should be less than 2 seconds
    And no cascading failures should occur
    And MTBF should be maintained
    And circuit breaker should be in closed state
    And system availability should return to "99.5" percent SLO

  @reliability @high @priority-high @chaos-engineering @graceful-degradation
  Scenario: Notification service failure with graceful degradation validation
    Given notification service is operational and monitored
    And message queue is configured for async notifications
    And retry policy is configured with exponential backoff and maximum 5 attempts
    And dead letter queue is configured for failed notifications
    And baseline metrics show "95" percent notification delivery rate within 10 seconds
    And chaos hypothesis is defined as "When notification service fails, comment submission success rate remains at 100% and notifications are queued for retry"
    And steady state is established with 5 comments submitted
    And all 5 notifications are delivered to team members within 10 seconds
    When notification service failure is injected with service returning 503 errors
    And notification service becomes unavailable
    And health check fails
    And service is marked as degraded in monitoring
    And employee submits comment "Testing resilience during notification outage" on task with 3 team members
    Then comment should save successfully within 2 seconds
    And comment should be displayed in UI immediately
    And user should receive success confirmation
    And notification attempts should fail and messages should be queued in message broker
    When employee submits 10 additional comments across different tasks while notification service remains down
    Then all 10 comments should save successfully with 100 percent success rate
    And core functionality should remain unaffected
    And notifications should accumulate in retry queue
    And no user-facing errors about notifications should be displayed
    And message queue should contain 11 notification jobs with retry metadata
    And exponential backoff timestamps should be present
    And no messages should exist in dead letter queue
    And retry attempts should be logged
    When notification service is restored to operational state
    And service health check passes
    And service is marked as available
    And retry processor begins consuming queued messages
    Then all 11 queued notifications should be delivered successfully within 5 minutes
    And eventual consistency should be achieved
    And no duplicate notifications should be sent
    And system should return to steady state
    And all comments should be persisted correctly in database
    And 100 percent of notifications should be eventually delivered
    And notification service should be operational

  @reliability @critical @priority-critical @performance @data-integrity
  Scenario: Concurrent comment submission under resource exhaustion with data integrity validation
    Given load testing tool is configured
    And resource monitoring is enabled for CPU, memory, and disk I/O
    And database transaction isolation level is set to "READ_COMMITTED"
    And rate limiting is configured with 100 requests per minute per user
    And baseline performance shows 50 concurrent users with 2 second response time
    And RTO target is 2 minutes
    And RPO target is zero data loss
    And baseline is established with 50 concurrent employees each submitting 1 comment
    And all 50 comments are saved successfully with average response time less than 2 seconds
    And CPU usage is less than 70 percent
    And memory usage is less than 80 percent
    When resource exhaustion is injected by limiting CPU to 50 percent and memory to 60 percent
    And system resources become constrained
    And CPU reaches 90 percent or higher
    And memory reaches 85 percent or higher
    And response times begin degrading
    And 200 concurrent employees submit comments simultaneously with varying comment lengths between 50 and 500 characters
    Then system should accept requests and process them through queue
    And rate limiting should activate for users exceeding 100 requests per minute
    And backpressure mechanisms should engage
    And no immediate failures should occur
    When system is monitored for 3 minutes under sustained load and resource constraint
    Then response times should degrade to 5 to 10 seconds
    And requests should not fail immediately
    And queue depth should increase
    And some requests may timeout after 30 seconds with proper error handling
    And no 500 errors should occur
    And circuit breakers may open for downstream services
    When resource constraints are removed
    And normal CPU and memory allocation is restored
    Then system should begin processing queued requests
    And CPU and memory utilization should normalize within RTO of 2 minutes
    And queue should drain progressively
    When system waits for all queued comments to process for up to 5 minutes
    Then all successfully submitted comments should be processed and saved
    And response times should return to less than 2 seconds baseline
    And system should achieve steady state
    When data integrity validation is executed
    And database is queried for total comment count
    And comments are checked for duplicates
    And comment content integrity is verified
    And timestamps are validated for sequential order
    Then exact count should match submitted comments accounting for rate-limited rejections
    And zero duplicate comments should exist
    And no data corruption should be present
    And all comments should have valid timestamps and user associations
    And transaction isolation should be maintained
    When RPO compliance is verified by comparing submission logs with database records
    Then zero data loss should be confirmed with RPO equals 0
    And all accepted requests should result in persisted comments
    And rejected requests should be properly logged with clear user feedback
    When application logs and error rates are reviewed during the experiment
    Then no database deadlocks should exist
    And no transaction rollback errors should exist beyond expected rate-limit rejections
    And proper error handling should be logged
    And MTBF should be maintained
    And availability should remain greater than 95 percent
    And all valid comments should be persisted in database with correct data
    And zero data corruption or duplicate entries should exist
    And system performance should return to baseline with less than 2 second response time
    And resource utilization should normalize with CPU less than 70 percent and memory less than 80 percent