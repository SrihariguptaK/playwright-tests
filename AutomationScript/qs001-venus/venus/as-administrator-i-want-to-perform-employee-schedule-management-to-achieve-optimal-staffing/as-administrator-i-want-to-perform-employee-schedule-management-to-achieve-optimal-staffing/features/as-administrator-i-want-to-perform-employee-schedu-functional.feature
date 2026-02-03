@functional @smoke
Feature: As Administrator, I want to perform employee schedule management to achieve optimal staffing. - Functional Tests
  As a user
  I want to test functional tests
  So that I can ensure quality and reliability

  Background:
    Given the system is ready for testing
    And the test environment is properly configured

  @high @tc-func-001
  Scenario: TC-FUNC-001 - Verify successful employee assignment to shift using template
    Given user is logged in with Administrator role and has schedule management permissions
    And at least one shift template exists in the system (e.g., 'Morning Shift 8AM-4PM')
    And at least 3 active employees are available in the system with no existing shift assignments
    And employee schedule management page is accessible at /admin/schedule-management
    And database EmployeeSchedules table is accessible and has no conflicting records
    When navigate to /admin/schedule-management page by clicking 'Schedule Management' in the admin navigation menu
    Then employee schedule management interface loads successfully showing calendar view, available templates dropdown, and employee list panel
    And click on the 'Select Template' dropdown and select 'Morning Shift 8AM-4PM' template from the list
    Then template is selected and highlighted, shift details (time, duration, requirements) are displayed in the template preview section
    And from the available employees list, drag and drop employee 'John Smith' onto the selected shift time slot in the calendar
    Then employee 'John Smith' appears in the shift slot with visual confirmation (employee name, avatar), no error messages displayed
    And click the 'Save Schedule' button located in the top-right corner of the page
    Then green success banner appears at top of page with message 'Schedule saved successfully. 1 employee assigned.' Calendar updates to show saved state with checkmark icon
    And verify the assignment by refreshing the page and checking the calendar view
    Then page reloads and employee 'John Smith' remains assigned to the Morning Shift slot, data persists correctly
    And employee 'John Smith' is successfully assigned to the Morning Shift in EmployeeSchedules table with status 'active'
    And administrator remains on the schedule management page with saved schedule displayed
    And employee 'John Smith' can view the assigned shift in their employee portal in real-time
    And audit log records the schedule assignment with timestamp and administrator details

  @high @tc-func-002
  Scenario: TC-FUNC-002 - Verify calendar format displays schedules correctly for multiple employees
    Given user is logged in as Administrator with schedule management permissions
    And at least 5 employees are assigned to various shifts across a 7-day period
    And calendar view is set to weekly display mode
    And browser viewport is at least 1024px width for proper calendar rendering
    When navigate to the employee schedule management page at /admin/schedule-management
    Then page loads with calendar view showing current week, days of week as column headers, time slots as rows, and assigned employees visible in respective slots
    And observe the calendar layout and verify all assigned employees are displayed with their names, shift times, and color-coded indicators
    Then calendar shows all 5 employees in their respective time slots, each with distinct color coding, employee name clearly visible, shift duration accurately represented
    And click on the 'Next Week' navigation arrow button to view the following week's schedule
    Then calendar transitions smoothly to next week view, date range updates in header, any assignments for next week are displayed correctly
    And click on an assigned employee card in the calendar to view detailed shift information
    Then modal or side panel opens showing detailed information: employee name, shift template used, start/end times, break times, and any notes
    And calendar view accurately reflects all schedule data from EmployeeSchedules table
    And administrator remains on schedule management page with calendar view active
    And no data is modified during view-only operations
    And calendar state (selected week) is maintained in session storage

  @high @tc-func-003
  Scenario: TC-FUNC-003 - Verify administrator can make adjustments to existing employee assignments
    Given user is logged in as Administrator with edit permissions
    And employee 'Jane Doe' is already assigned to 'Evening Shift 4PM-12AM' on Monday
    And employee 'Mike Johnson' is available and not assigned to any shift on Monday
    And schedule management page is loaded with current week view displayed
    When navigate to the schedule management page and locate 'Jane Doe' assigned to Monday Evening Shift
    Then calendar displays 'Jane Doe' in the Monday Evening Shift slot with edit controls visible on hover
    And click on 'Jane Doe' assignment card and select 'Remove Assignment' from the context menu
    Then confirmation dialog appears asking 'Are you sure you want to remove Jane Doe from this shift?', with 'Confirm' and 'Cancel' buttons
    And click 'Confirm' button in the confirmation dialog
    Then jane Doe is removed from the shift slot, slot shows as empty/available, visual indicator shows unsaved changes (orange border or asterisk)
    And drag and drop 'Mike Johnson' from the available employees list to the now-empty Monday Evening Shift slot
    Then 'Mike Johnson' appears in the shift slot, assignment is highlighted as new/modified with visual indicator
    And click 'Save Schedule' button to persist the changes
    Then green success message displays 'Schedule updated successfully. 1 assignment modified.' Changes are saved and visual indicators for unsaved changes disappear
    And employeeSchedules table is updated: Jane Doe's assignment is removed or marked inactive, Mike Johnson is assigned to Monday Evening Shift
    And both Jane Doe and Mike Johnson see updated schedules in their employee portals immediately
    And administrator remains on schedule management page with updated calendar view
    And change history is logged with details of the modification, timestamp, and administrator ID

  @high @tc-func-004
  Scenario: TC-FUNC-004 - Verify employees can view their assigned shifts in real-time after administrator saves schedule
    Given administrator is logged in and on schedule management page
    And employee 'Sarah Williams' is logged in on a separate browser/device viewing employee portal at /employee/my-schedule
    And sarah Williams has no current shift assignments
    And real-time update mechanism (WebSocket or polling) is active and functional
    When as Administrator, select 'Day Shift 9AM-5PM' template and assign 'Sarah Williams' to Wednesday Day Shift
    Then sarah Williams appears in the Wednesday Day Shift slot in administrator's calendar view
    And as Administrator, click 'Save Schedule' button to persist the assignment
    Then success message 'Schedule saved successfully' appears, assignment is saved to database
    And as Employee Sarah Williams, observe the employee portal schedule view without manually refreshing the page
    Then within 3-5 seconds, the Wednesday Day Shift 9AM-5PM appears in Sarah's schedule view with notification badge or toast message 'New shift assigned'
    And as Employee Sarah Williams, click on the newly assigned shift to view details
    Then shift details modal opens showing: Date (Wednesday), Time (9AM-5PM), Location, Supervisor name, and any special instructions
    And sarah Williams' schedule in employee portal accurately reflects the assignment made by administrator
    And assignment is stored in EmployeeSchedules table with correct employee ID and shift details
    And real-time notification was delivered to employee within acceptable latency (under 5 seconds)
    And both administrator and employee views show consistent schedule data

  @medium @tc-func-005
  Scenario: TC-FUNC-005 - Verify bulk assignment of multiple employees to multiple shifts using template
    Given user is logged in as Administrator with bulk assignment permissions
    And at least 10 employees are available and unassigned in the system
    And multiple shift templates exist: Morning, Afternoon, Evening, Night shifts
    And schedule management page supports multi-select functionality
    When navigate to schedule management page and click 'Bulk Assignment' button in the toolbar
    Then bulk assignment modal opens with options to select multiple employees, date range, and shift template
    And select 5 employees using checkboxes: John Smith, Jane Doe, Mike Johnson, Sarah Williams, Tom Brown
    Then all 5 employees are highlighted with checkmarks, selected count shows '5 employees selected' at bottom of modal
    And select date range 'Monday to Friday' using the date picker, and choose 'Morning Shift 8AM-4PM' template from dropdown
    Then date range displays 'Mon 01/15 - Fri 01/19', template shows 'Morning Shift 8AM-4PM' with shift details preview
    And click 'Apply Bulk Assignment' button at bottom of modal
    Then progress indicator shows assignment in progress, then success message 'Successfully assigned 5 employees to 5 shifts (25 total assignments)' appears
    And close modal and verify calendar view shows all 5 employees assigned to Morning Shift for Monday through Friday
    Then calendar displays all 25 assignments correctly, each employee appears in Morning Shift slot for each weekday, no overlaps or errors
    And employeeSchedules table contains 25 new records (5 employees × 5 days) with correct shift details
    And all 5 employees can view their full week schedule in employee portal
    And administrator remains on schedule management page with updated calendar showing all assignments
    And system performance remains acceptable (page load under 2 seconds) after bulk assignment

  @medium @tc-func-006
  Scenario: TC-FUNC-006 - Verify schedule filtering and search functionality for large employee base
    Given user is logged in as Administrator
    And system contains at least 100 employees with various shift assignments
    And schedule management page has search and filter controls visible
    And test data includes employees from different departments: Sales, Support, Operations
    When navigate to schedule management page and locate the search bar at top of employee list panel
    Then search bar is visible with placeholder text 'Search employees by name or ID', filter dropdown shows 'All Departments'
    And type 'John' in the search bar and observe real-time filtering
    Then employee list filters in real-time showing only employees with 'John' in their name (e.g., John Smith, Johnny Walker), count shows 'X results found'
    And clear search and click 'Filter by Department' dropdown, select 'Sales' department
    Then employee list updates to show only Sales department employees, calendar view updates to show only Sales employees' shifts
    And click 'Filter by Shift' dropdown and select 'Morning Shift' to further refine results
    Then view narrows to show only Sales employees assigned to Morning Shifts, calendar highlights matching shifts, filter tags appear showing active filters
    And click 'Clear All Filters' button to reset view
    Then all filters are removed, full employee list is restored, calendar shows all shifts for all employees, filter tags disappear
    And search and filter functionality works without modifying any schedule data
    And administrator remains on schedule management page with default view restored
    And filter state is cleared and not persisted in session
    And page performance remains acceptable with filtered results loading under 1 second

