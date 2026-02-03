@edge-cases @boundary
Feature: As Administrator, I want to perform employee schedule management to achieve optimal staffing. - Edge Case Tests
  As a user
  I want to test edge case tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-edge-001
  Scenario: TC-EDGE-001 - Verify system performance with maximum employee assignments (500 employees)
    Given user is logged in as Administrator
    And system has exactly 500 active employees in the database (performance threshold)
    And all 500 employees are assigned to various shifts across a 4-week period
    And schedule management page is configured to display monthly view
    And performance monitoring tools are active to measure load times
    When navigate to schedule management page and select 'Monthly View' to display all 500 employee assignments
    Then page loads within 3 seconds (acceptable performance threshold), calendar renders with all 500 assignments visible, no browser freezing or lag
    And use search functionality to filter employees by typing 'Smith' in search bar
    Then search results filter in real-time (under 500ms response), matching employees are displayed, calendar updates to show only filtered assignments
    And attempt to add one more assignment (501st) by assigning an available employee to a new shift
    Then assignment is created successfully, system handles 501 assignments without performance degradation, save operation completes within 2 seconds
    And click 'Export Schedule' button to generate report of all 500+ assignments
    Then export process initiates with progress indicator, CSV/PDF file generates within 10 seconds containing all assignment data accurately
    And system maintains acceptable performance with 500+ assignments as per requirements
    And all 501 assignments are accurately stored in EmployeeSchedules table
    And administrator remains on schedule management page with full functionality available
    And performance metrics are logged showing load times within acceptable thresholds

  @medium @tc-edge-002
  Scenario: TC-EDGE-002 - Verify schedule management with employee names containing special characters and Unicode
    Given user is logged in as Administrator
    And system contains employees with special character names: 'O'Brien', 'José García', '李明', 'Müller-Schmidt', 'Владимир'
    And schedule management page supports UTF-8 encoding
    And database is configured to handle Unicode characters properly
    When navigate to schedule management page and locate employees with special characters in the available employees list
    Then all employee names display correctly with proper character rendering: O'Brien (apostrophe), José García (accented characters), 李明 (Chinese characters), Müller-Schmidt (umlaut and hyphen), Владимир (Cyrillic)
    And search for employee 'José García' using the search bar by typing the exact name with accent
    Then search successfully finds and highlights 'José García', accent is recognized correctly in search algorithm
    And assign '李明' to Monday Morning Shift by dragging from employee list to calendar slot
    Then assignment is created successfully, Chinese characters display correctly in calendar slot, no character encoding errors
    And save the schedule and verify the assignment persists by refreshing the page
    Then schedule saves successfully, after refresh '李明' still appears correctly in assigned slot with proper character encoding
    And export schedule to PDF and verify special characters render correctly in the exported document
    Then pDF export completes successfully, all special characters and Unicode names render correctly in the document without corruption or replacement characters
    And all employee assignments with special characters are stored correctly in EmployeeSchedules table with proper UTF-8 encoding
    And character encoding is maintained across all operations: display, search, save, export
    And administrator remains on schedule management page with all names displaying correctly
    And no data corruption or character replacement occurs in database or UI

  @medium @tc-edge-003
  Scenario: TC-EDGE-003 - Verify schedule management at midnight boundary and daylight saving time transitions
    Given user is logged in as Administrator
    And system date is set to the day before daylight saving time change (e.g., March 10, 2024 at 11:45 PM)
    And shift template 'Night Shift 11PM-7AM' spans across midnight and DST transition
    And system timezone is set to a region that observes daylight saving time (e.g., America/New_York)
    When navigate to schedule management page and select the week containing the DST transition date
    Then calendar displays the week correctly with DST transition date marked or indicated, time slots are displayed accurately
    And assign employee 'David Wilson' to Night Shift 11PM-7AM on the night of DST transition (March 10-11)
    Then assignment is created, system correctly calculates shift duration accounting for DST (either 7 hours or 9 hours depending on spring/fall), no time calculation errors
    And save the schedule and verify the shift times are stored correctly in the database
    Then schedule saves successfully, success message appears, shift times are stored with correct timezone offset in EmployeeSchedules table
    And view the assignment in calendar after DST transition has occurred (system time is now in DST)
    Then shift displays with correct adjusted times, employee portal shows accurate shift times in current timezone, no time discrepancies or off-by-one-hour errors
    And shift assignment correctly accounts for DST transition with accurate duration calculation
    And all timestamps in EmployeeSchedules table are stored in UTC or with proper timezone offset
    And employee sees correct shift times in their portal regardless of DST transition
    And no scheduling conflicts arise from DST time adjustments

  @low @tc-edge-004
  Scenario: TC-EDGE-004 - Verify schedule management with empty employee list and no available templates
    Given user is logged in as Administrator
    And system has zero active employees in the database (all employees terminated or no employees added yet)
    And system has zero shift templates created
    And schedule management page is accessible
    When navigate to schedule management page with no employees or templates in the system
    Then page loads successfully showing empty state message: 'No employees available. Please add employees to begin scheduling.' and 'No shift templates found. Please create templates first.'
    And verify that calendar view displays empty slots with no assignments
    Then calendar renders correctly with empty time slots, no errors or broken UI elements, helpful message displays 'Get started by creating shift templates and adding employees'
    And attempt to access 'Assign Employee' functionality
    Then assignment controls are disabled or show tooltip 'No employees available to assign', prevents user from attempting invalid operations
    And click on 'Create Template' link or button in the empty state message
    Then user is redirected to shift template creation page or modal opens to create first template, providing clear path forward
    And no errors or crashes occur when viewing schedule management with empty data
    And administrator is provided with clear guidance on next steps (create templates, add employees)
    And uI gracefully handles empty state with helpful messaging
    And system remains stable and functional despite lack of data

  @medium @tc-edge-005
  Scenario: TC-EDGE-005 - Verify rapid consecutive save operations and race condition handling
    Given user is logged in as Administrator
    And multiple employees are assigned to shifts with unsaved changes
    And network latency is normal (not throttled)
    And save button is enabled and functional
    When make 3 new employee assignments to different shifts in quick succession
    Then all 3 assignments appear in calendar with unsaved changes indicator, save button is enabled
    And rapidly click the 'Save Schedule' button 5 times in quick succession (within 1 second)
    Then system handles rapid clicks gracefully: save button becomes disabled after first click, loading indicator appears, subsequent clicks are ignored or queued
    And observe the save operation completion and check for duplicate API calls in browser network tab
    Then only one POST request is sent to /api/employee-schedules, no duplicate requests, success message appears once: 'Schedule saved successfully. 3 employees assigned.'
    And verify in database that assignments were created only once, not duplicated
    Then employeeSchedules table contains exactly 3 new records, no duplicate entries, all assignments have unique IDs and correct data
    And no duplicate assignments are created despite rapid save button clicks
    And system implements proper debouncing or request deduplication
    And data integrity is maintained with single save operation
    And administrator remains on schedule management page with saved schedule displayed correctly

  @medium @tc-edge-006
  Scenario: TC-EDGE-006 - Verify schedule display and functionality on minimum supported screen resolution (320px mobile)
    Given user is logged in as Administrator on mobile device or browser with viewport set to 320px width
    And schedule management page is responsive and supports mobile view
    And at least 10 employees are assigned to various shifts
    And mobile-optimized UI components are implemented
    When navigate to schedule management page on 320px viewport (iPhone SE size)
    Then page loads and adapts to mobile layout: calendar switches to list or day view, navigation is accessible via hamburger menu, no horizontal scrolling required
    And attempt to view weekly schedule on mobile view
    Then schedule displays in mobile-optimized format (vertical list or swipeable day cards), all employee assignments are readable, text is not truncated or overlapping
    And attempt to assign an employee to a shift using touch interface
    Then assignment interface is touch-friendly: buttons are at least 44px touch targets, dropdowns are accessible, drag-and-drop is replaced with tap-to-assign or modal selection
    And save the schedule using mobile interface
    Then save button is accessible and properly sized, save operation completes successfully, success message is visible and readable on small screen
    And schedule management functionality is fully accessible on 320px mobile viewport
    And all assignments are saved correctly regardless of screen size
    And administrator can perform all critical tasks on mobile device
    And uI remains usable and readable without layout breaking or content overflow

