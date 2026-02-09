Feature: Administrator Permission Assignment Reliability and Data Integrity
  As an Administrator
  I want the permission assignment system to handle failures gracefully and maintain data integrity
  So that role configurations remain accurate and secure even under adverse conditions

  Background:
    Given administrator is authenticated with valid admin credentials
    And role exists in the system with current permissions

  @reliability @critical @priority-critical @chaos-engineering
  Scenario: Database connection failure during permission assignment with transaction rollback
    Given database connection monitoring tools are configured
    And transaction logging is enabled
    And chaos engineering tool is configured for database failure injection
    And administrator navigates to permission configuration section
    When administrator selects target role
    Then role details and current permissions should be displayed successfully
    When administrator selects 5 new permissions to assign to the role
    Then permissions should be selected and ready for submission
    When administrator clicks "Submit" button
    And database connection failure is injected using chaos tool immediately after submission
    Then database connection should terminate mid-transaction
    And system should detect database failure within 500 milliseconds
    And error message "Permission assignment failed due to system error. Please retry." should be displayed
    And no partial permissions should be committed
    When administrator queries permissions table directly
    Then no new permissions should be assigned to role
    And database state should be unchanged
    And transaction should be fully rolled back
    When database connection is restored
    And administrator retries permission assignment
    Then permission assignment should complete successfully within 2 seconds
    And all 5 permissions should be assigned
    And confirmation message should be displayed
    When administrator verifies audit log entries
    Then audit log should contain entry for failed attempt with error details
    And audit log should contain entry for successful retry with timestamp
    And system MTTR should be less than 30 seconds from failure detection to recovery readiness

  @reliability @critical @priority-critical @circuit-breaker @performance
  Scenario: API service degradation under high latency with circuit breaker validation
    Given baseline steady state shows permission assignment API responds within 2 seconds with 99.9 percent success rate
    And circuit breaker is configured with failure rate threshold 50 percent
    And circuit breaker is configured with timeout 5 seconds
    And circuit breaker is configured with half-open retry after 30 seconds
    And network latency injection tool is configured
    And monitoring dashboard is active for SLI SLO tracking
    And load generator is ready to simulate 100 concurrent admin users
    When administrator executes 100 permission assignments
    Then baseline metrics should show 100 percent success rate
    And average latency should be 1.5 seconds
    And p95 latency should be 1.8 seconds
    When network latency of 8 seconds is injected to "POST /api/roles/{id}/permissions" endpoint using chaos tool
    Then network latency should be increased to 8 seconds for all requests to permission API
    When 50 concurrent permission assignment requests are initiated from different admin users
    Then initial requests should timeout after 5 seconds
    And circuit breaker should detect failure threshold exceeded
    And circuit breaker should transition to "OPEN" state after 5 consecutive failures
    And subsequent requests should fail fast with error message "Service temporarily unavailable, please try again shortly"
    And response time should be less than 100 milliseconds for fast-fail
    When system is monitored for 30 seconds while circuit breaker remains open
    Then all permission assignment requests should fail fast
    And no cascading failures to other services should occur
    And system logs should show circuit breaker open state
    And dependent services should remain operational
    When network latency injection is removed after 30 seconds
    Then network latency should return to normal less than 2 seconds
    And circuit breaker should enter "HALF-OPEN" state
    When circuit breaker allows 3 test requests through in half-open state
    Then test requests should succeed within 2 seconds
    And circuit breaker should transition to "CLOSED" state
    And normal operation should be resumed
    When administrator executes 100 permission assignments to validate full recovery
    Then success rate should return to 99.9 percent
    And average latency should be 1.5 seconds
    And system should achieve steady state
    And MTTR should be 35 seconds from failure injection to full recovery

  @reliability @high @priority-high @graceful-degradation @session-management
  Scenario: Authentication service failure with graceful degradation and session validation
    Given administrator session token is established with TTL 30 minutes
    And authentication service is operational and responding
    And session cache is configured with Redis
    And fallback authentication mechanism is enabled
    And service mesh is configured for dependency management
    When administrator successfully logs in
    And administrator navigates to permission configuration section
    Then session should be established
    And authentication token should be cached
    And admin dashboard should be displayed
    When administrator selects role
    And administrator begins permission assignment workflow
    Then role details should be loaded
    And permission selection interface should be displayed
    When authentication service failure is simulated by stopping the service
    Then authentication service should become unavailable
    And health check should fail
    When administrator submits permission assignment form while authentication service is down
    Then system should validate session using cached authentication token
    And permission assignment should proceed successfully using cached admin credentials
    And permission assignment should complete within 2 seconds
    When administrator verifies permission assignment was logged
    Then audit log should show permission assignment with correct admin user ID from cached session
    And timestamp should be recorded
    When new user attempts to initiate new login session while authentication service is down
    Then new login should fail gracefully with message "Authentication service temporarily unavailable. If you have an active session, you may continue working."
    And existing sessions should remain valid
    When session token approaches expiration at 28 minutes while auth service still down
    Then system should display warning "Session expiring soon. Authentication service unavailable for renewal. Please save your work."
    When authentication service is restored
    Then authentication service should become available
    And health check should pass
    And session renewal capability should be restored
    And RTO should be 3 minutes from service restoration to full functionality
    When administrator performs another permission assignment to validate full recovery
    Then permission assignment should complete successfully with real-time authentication validation
    And audit log should be updated

  @reliability @high @priority-high @concurrency @data-integrity @optimistic-locking
  Scenario: Concurrent permission assignment conflict with data integrity validation and optimistic locking
    Given role exists with current permission set "PERM-A, PERM-B"
    And role has ID "ROLE-555"
    And two administrators "Admin1" and "Admin2" are authenticated simultaneously
    And optimistic locking is enabled with version control on roles table
    And database supports ACID transactions
    And conflict resolution policy is configured
    And audit logging is enabled for all permission changes
    When "Admin1" navigates to role "ROLE-555" permission configuration
    And "Admin2" navigates to role "ROLE-555" permission configuration simultaneously
    Then both administrators should see current permissions "PERM-A, PERM-B"
    And version number should be "v1"
    When "Admin1" adds permissions "PERM-C, PERM-D" and prepares to submit
    Then "Admin1" form should show pending changes "PERM-A, PERM-B, PERM-C, PERM-D"
    When "Admin2" adds permission "PERM-E"
    And "Admin2" removes permission "PERM-A"
    And "Admin2" submits form immediately
    Then "Admin2" submission should succeed
    And role should be updated to "PERM-B, PERM-E"
    And version should be incremented to "v2"
    And confirmation message should be displayed
    And audit log entry should be created with "Admin2" details
    When "Admin1" submits form 5 seconds after "Admin2" with original version "v1"
    Then system should detect version conflict with current version "v2" and submitted version "v1"
    And submission should be rejected with error message "Permission configuration has been modified by another administrator. Please review current state and resubmit."
    When "Admin1" refreshes role permission view
    Then "Admin1" should see updated permissions "PERM-B, PERM-E"
    And version should be "v2"
    And notification should be displayed "This role was recently modified by Admin2 at [timestamp]"
    When "Admin1" reviews changes and reapplies desired modifications by adding "PERM-C, PERM-D" to current state
    Then form should show "PERM-B, PERM-E, PERM-C, PERM-D"
    And version should be "v2"
    When "Admin1" submits updated form with correct version
    Then submission should succeed
    And role should be updated to "PERM-B, PERM-E, PERM-C, PERM-D"
    And version should be incremented to "v3"
    And confirmation message should be displayed
    When administrator verifies audit log contains complete history
    Then audit log should show "Admin2" added "PERM-E" and removed "PERM-A" at timestamp "T1"
    And audit log should show "Admin1" conflict rejection at timestamp "T2"
    And audit log should show "Admin1" added "PERM-C, PERM-D" at timestamp "T3"
    And complete change history should be preserved with zero data loss
    When administrator queries database directly to verify final permission state
    Then database should show role permissions "PERM-B, PERM-E, PERM-C, PERM-D"
    And version should be "v3"
    And no orphaned records should exist
    And referential integrity should be maintained
    And RPO should be 0 seconds
    And RTO should be immediate