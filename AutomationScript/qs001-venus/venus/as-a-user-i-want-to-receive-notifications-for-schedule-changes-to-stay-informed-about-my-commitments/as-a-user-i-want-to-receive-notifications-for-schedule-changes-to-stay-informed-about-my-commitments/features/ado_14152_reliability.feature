Feature: Notification Service Reliability and High Availability
  As a system administrator
  I want the notification service to maintain high availability and resilience during failures
  So that users receive schedule change notifications without interruption or data loss

  Background:
    Given notification service is running in production-like environment
    And monitoring tools are active to track metrics
    And test user accounts with scheduled appointments are configured

  @reliability @priority-critical @resilience @database-failure
  Scenario: Notification service recovers automatically from database connection failure without notification loss
    Given schedule database is operational with active connections
    And message queue system is configured for notification persistence
    And baseline is established with 5 schedule changes delivered within 1 minute
    When database connections are terminated
    And 10 schedule changes are created while database is down
    And system behavior is monitored for 5 minutes during outage
    Then notification service should detect database unavailability
    And notification events should be queued to message buffer
    And service should remain operational without crash
    And health check endpoints should return degraded status
    And circuit breaker should open to prevent cascading failures
    When database connectivity is restored
    Then service should detect database availability within 30 seconds
    And circuit breaker should transition to half-open then closed state
    And all 10 queued notifications should be delivered within 2 minutes
    And notification data integrity should be maintained
    When 3 new schedule changes are created post-recovery
    Then new notifications should be delivered within 1 minute
    And MTTR should be less than 2 minutes
    And notification delivery rate should be 100 percent with 13 total notifications
    And RTO compliance should be verified
    And no duplicate notifications should be sent to users

  @reliability @priority-critical @chaos-engineering @email-latency
  Scenario: System maintains notification delivery when email service experiences high latency
    Given notification service is configured with dual-channel delivery
    And email service provider API integration is active
    And circuit breaker is configured with 3 second timeout threshold
    And in-app notification service is operational as fallback mechanism
    And chaos engineering platform is configured with latency injection capability
    And baseline metrics show 95 percent notification delivery within 1 minute
    And chaos hypothesis is defined as "When email API latency exceeds 3 seconds, system will deliver in-app notifications within 1 minute while retrying email delivery with exponential backoff, maintaining 95% user notification rate"
    And blast radius is limited to 20 percent of user base
    When steady state is monitored for 10 schedule changes with normal latency
    Then 100 percent dual-channel delivery should occur within 1 minute
    And average email delivery time should be 800 milliseconds
    And in-app delivery time should be 300 milliseconds
    When network latency of 10 seconds is injected to email service provider API
    And 15 schedule changes are created affecting users in blast radius
    Then in-app notifications should be delivered within 1 minute for all 15 changes
    And email delivery attempts should timeout after 3 seconds
    And circuit breaker should open after 3 consecutive timeout failures
    And email service should be marked as degraded
    And retry queue should be activated
    And retry attempts should follow exponential backoff pattern with intervals "1s, 2s, 4s, 8s, 16s"
    And maximum 5 retry attempts per notification should occur
    And no system overload should occur
    When latency injection is removed after 10 minutes
    Then email API latency should return to less than 500 milliseconds
    And circuit breaker should transition to half-open state within 30 seconds
    And all 15 email notifications should be delivered within 3 minutes post-recovery
    And users should receive exactly 1 email and 1 in-app notification per change
    And chaos hypothesis should be confirmed
    And overall notification success rate should be 100 percent
    And MTTR should be 30 seconds

  @reliability @priority-critical @high-availability @failover
  Scenario: Notification service maintains zero notification loss during instance crash with automatic failover
    Given notification service is deployed with minimum 3 instances behind load balancer
    And load balancer is configured with health checks at 5 second interval
    And 2 consecutive health check failures trigger instance removal
    And shared message queue is accessible by all service instances
    And database connection pooling is configured across all instances
    And session persistence is disabled to allow stateless failover
    And monitoring is configured for instance health and notification processing metrics
    When baseline high availability is verified with 3 service instances running
    Then load balancer should distribute traffic evenly at 33 percent each
    And health checks should pass every 5 seconds for all instances
    When continuous load of 50 schedule changes is generated over 10 minute period
    Then notifications should process normally across all instances
    And delivery rate should be 100 percent within 1 minute SLA
    When primary instance handling majority of traffic is identified
    Then 5 to 10 notifications should be in active processing state
    When primary notification service instance is forcefully terminated
    Then primary instance should crash immediately
    And health check should fail for crashed instance
    And in-flight notifications should remain in message queue as unacknowledged
    And load balancer should detect failure within 10 seconds
    And failed instance should be removed from pool
    And traffic should be redistributed to 2 remaining instances
    And message queue should reassign unacknowledged notifications within 15 seconds
    And no notifications should be lost
    And notification delivery should continue with less than 5 second interruption
    And all 50 notifications should be delivered successfully
    And no duplicate notifications should be sent
    When replacement instance is brought up
    Then new instance should start within 60 seconds
    And new instance should pass health checks
    And new instance should be added to load balancer pool
    And traffic should be rebalanced to 3 instances
    And service availability should be 99.95 percent
    And MTTR should be 15 seconds
    And RPO should be 0 with zero notification loss
    And RTO should be 10 seconds for failover time
    And failover event should be logged with complete metrics