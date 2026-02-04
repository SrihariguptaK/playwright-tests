@edge-cases @boundary
Feature: As Scheduler, I want to receive notifications for recurring conflicts to proactively manage scheduling - Edge Case Tests
  As a user
  I want to test edge case tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @medium @tc-edge-001
  Scenario: TC-EDGE-001 - Verify system handles maximum number of simultaneous recurring conflicts
    Given user is logged in as Scheduler
    And system is configured with maximum limit of 100 recurring conflict patterns per user
    And database currently contains 99 recurring conflict patterns for the test user
    And system performance monitoring is active
    When trigger the 100th unique recurring conflict pattern by creating a new schedule conflict that repeats
    Then system successfully identifies and stores the 100th recurring conflict, notification is generated within 5 seconds
    And attempt to trigger a 101st unique recurring conflict pattern
    Then system either accepts it with warning message 'You have reached the maximum number of tracked recurring conflicts (100). Oldest patterns may be archived.' or prevents creation with message 'Maximum recurring conflict limit reached'
    And open notification panel and scroll through all recurring conflict notifications
    Then notification panel implements pagination or virtual scrolling, displays 'Showing 1-20 of 100' with 'Load More' button, UI remains responsive without lag
    And send GET request to /api/conflicts/recurring with no pagination parameters
    Then aPI returns first page of results (default 20 items) with pagination metadata showing totalCount: 100, and includes links to next page
    And measure page load time and API response time
    Then page loads within 3 seconds, API responds within 5 seconds even with 100 recurring conflicts, no browser freeze or memory issues
    And system maintains performance with maximum number of recurring conflicts
    And all 100 recurring conflicts are accessible through pagination
    And database queries remain optimized with proper indexing
    And user can still interact with the application without performance degradation

  @low @tc-edge-002
  Scenario: TC-EDGE-002 - Verify system handles recurring conflict with extremely long resource names and descriptions
    Given user is logged in as Scheduler
    And system allows resource names up to 255 characters
    And test data includes resources with names at maximum character limit
    And notification UI has responsive design for various content lengths
    When create a recurring conflict involving a resource with 255-character name: 'Conference Room A with Extended Description Including Location Building 5 Floor 3 West Wing Near Elevator Bank With Video Conferencing Capabilities and Whiteboard and Projector and Seating Capacity of Twenty Five People and Windows Facing North and Access to Kitchen'
    Then system accepts the resource name and successfully creates the conflict record
    And trigger the recurring conflict pattern 3 times to generate recurring conflict notification
    Then system identifies recurring pattern and generates notification within 5 seconds
    And open notification panel and view the recurring conflict notification
    Then notification displays resource name with text truncation (e.g., 'Conference Room A with Extended Description Including Location Building 5 Floor 3 West Wing Near Elevator Bank With Video Conferencing Capabilities and Whiteboard and Projector and Seating Capacity of Twenty Five People and Windows Facing North and Access to Kitchen' shows as 'Conference Room A with Extended Description Including Location Building 5 Floor 3 West Wing Near Elevator Bank With Video Conferencing Capabilities and Whiteboard and Projector and Seating Capacity of Twenty Five People and Windows Facing North and Access to Kitchen' with ellipsis and 'Show More' link)
    And click 'Show More' link or hover over truncated text
    Then full resource name is displayed in tooltip or expanded view without breaking UI layout, text wraps properly within notification container
    And export or download recurring conflict report
    Then full resource name is included in export file without truncation, CSV or PDF format handles long text appropriately
    And uI remains functional and visually correct with long resource names
    And no text overflow or layout breaking occurs
    And full data is preserved in database and exports
    And notification remains readable and accessible

  @high @tc-edge-003
  Scenario: TC-EDGE-003 - Verify system handles recurring conflict detection across different time zones
    Given user is logged in as Scheduler with account timezone set to EST (UTC-5)
    And system supports multiple time zones for scheduling
    And historical conflicts exist for 'Monday 10:00 AM EST' occurring 3 times
    And user is about to create a schedule in PST (UTC-8) timezone
    When change user's timezone preference to PST (UTC-8) in account settings
    Then timezone preference is saved, confirmation message displays 'Timezone updated to Pacific Standard Time (PST)'
    And create a schedule conflict for 'Monday 1:00 PM PST' (which is equivalent to 'Monday 10:00 AM EST' in previous timezone)
    Then system converts time to UTC for comparison and recognizes this as the same recurring conflict pattern
    And check notification panel for recurring conflict alert
    Then recurring conflict notification is generated showing 'This conflict has occurred 4 times' with times displayed in user's current timezone (PST): 'Monday 1:00 PM PST'
    And click 'View Conflict History' to see all previous occurrences
    Then history shows all 4 occurrences with times converted to PST: 3 previous instances shown as 'Monday 1:00 PM PST' and current instance, with note '(Previously scheduled in EST)' for historical entries
    And verify API response from GET /api/conflicts/recurring includes timezone information
    Then aPI response includes timezone field for each occurrence, times are returned in ISO 8601 format with timezone offset (e.g., '2024-01-15T13:00:00-08:00')
    And recurring conflict detection works correctly across timezone changes
    And all times are displayed consistently in user's current timezone
    And historical data maintains original timezone information
    And no duplicate conflict patterns are created due to timezone differences

  @medium @tc-edge-004
  Scenario: TC-EDGE-004 - Verify system handles recurring conflicts when historical data is exactly at threshold boundary
    Given user is logged in as Scheduler
    And system is configured to classify conflicts as recurring when they occur exactly 3 times (minimum threshold)
    And historical database contains exactly 2 instances of a specific conflict pattern
    And system uses inclusive threshold logic (3 or more = recurring)
    When trigger the same conflict pattern for the 3rd time (exactly at threshold)
    Then system detects that occurrence count equals threshold (3) and classifies it as recurring conflict
    And check notification panel immediately after triggering 3rd occurrence
    Then recurring conflict notification appears within 5 seconds with message 'Recurring pattern detected: This conflict has occurred 3 times'
    And send GET request to /api/conflicts/recurring
    Then aPI response includes this conflict pattern in the array with occurrences: 3, classified as recurring: true
    And delete one of the historical conflict instances to bring count back to 2
    Then system recalculates pattern frequency, occurrence count drops to 2
    And refresh notification panel and send new GET request to /api/conflicts/recurring
    Then conflict pattern is removed from recurring conflicts list since it no longer meets threshold, notification is archived or marked as resolved
    And system correctly applies threshold boundary logic (inclusive of threshold value)
    And recurring classification is dynamic and updates when occurrence count changes
    And notifications accurately reflect current recurring status
    And historical data changes trigger recalculation of patterns

  @medium @tc-edge-005
  Scenario: TC-EDGE-005 - Verify system handles notification delivery when user has disabled all notification channels
    Given user is logged in as Scheduler
    And user has disabled all notification channels: in-app, email, and SMS are all unchecked in preferences
    And notification preferences are saved with all channels disabled
    And a recurring conflict pattern exists and is about to be triggered
    When verify notification preferences show all channels disabled
    Then notification Preferences page displays all checkboxes unchecked for 'In-App Notifications', 'Email Notifications', and 'SMS Notifications' under Recurring Conflicts section
    And trigger a recurring conflict by creating a schedule matching an existing pattern
    Then system detects recurring conflict and processes it normally, conflict is logged in database
    And check notification bell icon in the application
    Then notification bell shows no badge or indicator, clicking it shows empty state message 'You have disabled notifications for recurring conflicts. Update your preferences to receive alerts.'
    And check email inbox and phone for any notifications
    Then no email or SMS is received, notification channels respect user's disabled preferences
    And navigate to Conflict History or Dashboard to verify conflict was still detected
    Then recurring conflict is visible in Conflict History page with indicator showing 'Notification not sent (user preferences)', conflict data is complete and accessible
    And no notifications are sent through any channel
    And conflict detection and logging still functions normally
    And user preferences are respected and not overridden
    And conflict data remains accessible through direct navigation to conflict views

  @high @tc-edge-006
  Scenario: TC-EDGE-006 - Verify system performance when analyzing large historical dataset for recurring patterns
    Given user is logged in as Scheduler
    And historical conflict database contains 10,000+ conflict records spanning 2 years
    And system is configured to analyze last 90 days of data for recurring patterns
    And performance monitoring tools are active to measure response times
    When trigger a new conflict that requires system to analyze historical data for pattern matching
    Then system initiates pattern analysis query against historical database
    And measure time taken for system to identify if conflict is recurring
    Then pattern analysis completes within 5 seconds as per performance requirement, notification is generated within the SLA
    And monitor database query performance and resource utilization
    Then database query uses proper indexes, execution plan shows index seek (not table scan), CPU usage remains below 70%, memory usage is stable
    And trigger 5 different conflicts simultaneously (simulate multiple schedulers working concurrently)
    Then system handles concurrent pattern analysis requests, all 5 conflicts are analyzed within 5 seconds each, no query deadlocks or timeouts occur
    And verify notification delivery for all 5 concurrent conflicts
    Then all recurring conflict notifications are generated and delivered successfully, notification queue processes all items without backlog, no notifications are lost or delayed beyond 5-second SLA
    And system maintains performance SLA with large historical dataset
    And database queries are optimized with proper indexing
    And concurrent users do not experience degraded performance
    And all notifications are delivered within specified timeframe

