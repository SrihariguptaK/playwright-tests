Feature: As Supervisor, I want to assign shift templates to employees to achieve accurate schedule creation

  Background:
    Given the application is accessible
    And the user is on the appropriate page

  # Functional Test Scenarios
  Scenario: Verify successful assignment of shift template to employee for specific dates
    Given User is logged in with Supervisor role
    Given At least one employee exists in the system
    Given At least one shift template is available in ShiftTemplates table
    Given Employee has no existing shifts for the selected date range
    Given Schedule creation page is accessible
    When Navigate to the schedule creation page
    Then Schedule creation page loads successfully with employee selection and calendar interface visible
    And Select an employee from the employee dropdown list
    Then Employee is selected and their current schedule information is displayed
    And Select a date range (start date and end date) for shift assignment
    Then Date range is highlighted on the calendar view and ready for template assignment
    And Choose a shift template from the available shift templates list
    Then Shift template is selected and preview of shift details (time, duration, break) is displayed
    And Click 'Assign Shift' button to assign the selected template to the employee for the chosen dates
    Then System processes the assignment and displays a success message confirming shift template assignment
    And Verify the assigned shifts appear in the calendar view
    Then Assigned shifts are visible in the calendar with correct dates, times, and employee name displayed

  Scenario: Verify supervisor can manually adjust assigned shifts with successful validation
    Given User is logged in with Supervisor role
    Given Employee has at least one assigned shift in the schedule
    Given Schedule creation page is accessible
    Given Validation rules are active in the system
    When Navigate to the schedule creation page
    Then Schedule creation page loads with existing employee schedules visible in calendar view
    And Select an employee with existing shift assignments
    Then Employee is selected and their assigned shifts are displayed in the calendar
    And Click on an existing assigned shift in the calendar to open edit mode
    Then Shift details panel opens showing current shift information (start time, end time, break duration, shift type)
    And Modify the shift start time to a valid new time that does not create conflicts
    Then New start time is entered and field accepts the input
    And Modify the shift end time to a valid new time
    Then New end time is entered and field accepts the input
    And Click 'Save Changes' or 'Update Shift' button
    Then System validates the manual adjustments against conflict rules and work hour limits
    And Verify validation success message is displayed
    Then Success message confirms shift has been updated with validation passed
    And Check the calendar view for updated shift details
    Then Calendar displays the modified shift with new start and end times correctly reflected

  Scenario: Verify employees receive notifications when schedule is created
    Given User is logged in with Supervisor role
    Given Employee account exists with valid notification settings (email/SMS enabled)
    Given Notification service is operational
    Given At least one shift template is available
    When Navigate to the schedule creation page
    Then Schedule creation page loads successfully
    And Select an employee from the employee list
    Then Employee is selected and ready for shift assignment
    And Select a date range for the new schedule
    Then Date range is selected and highlighted on calendar
    And Assign a shift template to the selected employee and dates
    Then Shift template is assigned successfully
    And Click 'Confirm' or 'Save Schedule' button to finalize the schedule creation
    Then System saves the schedule and triggers notification process
    And Verify notification confirmation message appears for the supervisor
    Then Message confirms that notification has been sent to the employee
    And Check employee's notification inbox/email (if accessible in test environment)
    Then Employee receives notification containing schedule details: date, shift time, location, and any relevant instructions

  Scenario: Verify employees receive notifications when schedule is modified
    Given User is logged in with Supervisor role
    Given Employee has an existing assigned shift
    Given Employee notification settings are enabled
    Given Notification service is operational
    When Navigate to the schedule creation page
    Then Schedule creation page loads with existing schedules visible
    And Select an employee with an existing shift assignment
    Then Employee is selected and current shifts are displayed
    And Click on an existing shift to edit it
    Then Shift edit panel opens with current shift details
    And Modify the shift details (change start time, end time, or date)
    Then Modified values are entered successfully
    And Click 'Save Changes' button to save the modification
    Then System validates and saves the modified shift successfully
    And Verify notification confirmation message is displayed
    Then Confirmation message indicates notification has been sent to employee about schedule modification
    And Check employee's notification inbox/email for modification notice
    Then Employee receives notification with updated schedule details highlighting what was changed (original vs. new times/dates)

  Scenario: Verify supervisor can view employee schedules in calendar view
    Given User is logged in with Supervisor role
    Given Multiple employees have assigned shifts in the system
    Given Schedule creation page is accessible
    Given Calendar view feature is enabled
    When Navigate to the schedule creation page
    Then Schedule creation page loads with calendar view interface visible
    And Verify calendar view displays current month/week by default
    Then Calendar shows current time period with date grid clearly visible
    And Select an employee from the employee filter/dropdown
    Then Calendar view updates to show only the selected employee's shifts
    And Verify assigned shifts are displayed on the calendar with shift details
    Then Each shift appears on correct date with visible information: shift time, duration, and shift type/template name
    And Navigate to next week/month using calendar navigation controls
    Then Calendar updates to show next time period with any scheduled shifts for that period
    And Navigate back to previous week/month using calendar navigation controls
    Then Calendar updates to show previous time period with historical shift data
    And Switch calendar view mode (if available: day view, week view, month view)
    Then Calendar adjusts display format while maintaining all shift information visibility
    And Click on a shift in the calendar to view detailed information
    Then Shift details panel opens showing complete information: employee name, date, start time, end time, break duration, location, and status

  Scenario: Verify calendar view displays multiple employees' schedules simultaneously
    Given User is logged in with Supervisor role
    Given At least 3 different employees have assigned shifts
    Given Schedule creation page with calendar view is accessible
    When Navigate to the schedule creation page
    Then Schedule creation page loads with calendar view
    And Select 'All Employees' or multiple employees from the filter options
    Then Calendar view updates to show shifts for all selected employees
    And Verify shifts from different employees are visually distinguishable
    Then Each employee's shifts are displayed with different colors or clear labels showing employee names
    And Check that overlapping shifts (different employees, same time) are both visible
    Then Calendar displays both shifts clearly without one hiding the other, possibly stacked or side-by-side
    And Verify calendar legend or key is present
    Then Legend shows color coding or symbols used to differentiate between employees

  # Negative Test Scenarios
  Scenario: Verify system detects and alerts supervisor for overlapping shift assignments
    Given User is logged in with Supervisor role
    Given Employee already has an assigned shift on a specific date and time
    Given Schedule creation page is accessible
    Given Conflict detection rules are configured in backend
    When Navigate to the schedule creation page
    Then Schedule creation page loads with current employee schedules visible
    And Select the employee who already has an existing shift assignment
    Then Employee is selected and existing shifts are displayed in the calendar view
    And Select a date that overlaps with an existing shift for this employee
    Then Date is selected and available for template assignment
    And Choose a shift template that has overlapping time with the existing shift
    Then Shift template is selected and ready for assignment
    And Click 'Assign Shift' button to attempt assignment
    Then System validates the assignment and detects the overlapping shift conflict
    And Review the conflict alert message displayed by the system
    Then Clear alert message is displayed indicating overlapping shift conflict with details of conflicting shifts (date, time, existing shift details)
    And Verify that the conflicting shift was not saved to the schedule
    Then New shift is not added to EmployeeSchedules table and calendar view shows only the original shift

  Scenario: Verify system detects and alerts supervisor when work hour limits are exceeded
    Given User is logged in with Supervisor role
    Given Employee has existing shifts that approach maximum work hour limits
    Given Work hour limit rules are configured in the system
    Given Schedule creation page is accessible
    When Navigate to the schedule creation page
    Then Schedule creation page loads successfully
    And Select an employee who is near their work hour limit for the week/period
    Then Employee is selected and current total work hours are visible
    And Select a date within the current work period
    Then Date is selected on the calendar
    And Choose a shift template that would cause total hours to exceed the maximum allowed work hour limit
    Then Shift template is selected showing shift duration
    And Click 'Assign Shift' button to attempt assignment
    Then System validates total work hours and detects the limit violation
    And Review the alert message displayed by the system
    Then Alert message clearly indicates work hour limit exceeded with details: current hours, proposed hours, maximum allowed hours, and period affected
    And Verify the shift was not assigned to the employee
    Then Shift is not saved to EmployeeSchedules table and employee's total hours remain within limits

  Scenario: Verify system prevents manual adjustment of shifts that would create conflicts
    Given User is logged in with Supervisor role
    Given Employee has multiple assigned shifts
    Given At least two shifts exist with potential for overlap if modified
    Given Validation rules are configured and active
    When Navigate to the schedule creation page
    Then Schedule creation page loads with employee schedules visible
    And Select an employee with multiple existing shifts
    Then Employee is selected and all assigned shifts are displayed in calendar view
    And Click on a shift to open it for editing
    Then Shift edit panel opens with current shift details editable
    And Modify the shift time to overlap with another existing shift for the same employee
    Then Modified time values are entered in the fields
    And Click 'Save Changes' button to attempt saving the conflicting modification
    Then System runs validation and detects the scheduling conflict
    And Review the validation error message displayed
    Then Error message clearly states the conflict with details of overlapping shifts and specific times that conflict
    And Verify the shift modification was not saved
    Then Original shift times remain unchanged in the calendar and EmployeeSchedules table

  Scenario: Verify role-based access control prevents non-supervisor users from assigning shifts
    Given User account with non-supervisor role exists (e.g., Employee, Viewer)
    Given Role-based access control is configured and active
    Given Schedule creation functionality requires supervisor privileges
    When Log in to the system with a non-supervisor user account
    Then User successfully logs in with limited role permissions
    And Attempt to navigate to the schedule creation page via direct URL or menu
    Then System denies access and displays authorization error message or redirects to unauthorized page
    And Verify schedule creation menu option is not visible or is disabled
    Then Schedule creation option is either hidden from navigation menu or displayed as disabled/grayed out
    And Attempt to access POST /api/schedules endpoint directly (if testing API access)
    Then API returns 403 Forbidden or 401 Unauthorized status code with appropriate error message
    And Verify user can only view their own schedule (if applicable to role)
    Then User can access read-only view of their personal schedule but cannot modify or create schedules for others

  # Edge Case Test Scenarios
  Scenario: Verify system handles concurrent schedule edits by multiple supervisors
    Given Two supervisor accounts are logged in on different sessions/browsers
    Given Same employee schedule is accessible to both supervisors
    Given System supports concurrent editing with conflict resolution
    When Supervisor 1: Navigate to schedule creation page and select an employee
    Then Supervisor 1 sees employee schedule and can edit
    And Supervisor 2: Navigate to schedule creation page and select the same employee
    Then Supervisor 2 sees the same employee schedule and can edit
    And Supervisor 1: Begin editing a shift (change start time)
    Then Shift enters edit mode for Supervisor 1
    And Supervisor 2: Simultaneously edit the same shift (change end time)
    Then Shift enters edit mode for Supervisor 2
    And Supervisor 1: Save the changes first
    Then Changes are saved successfully and database is updated with Supervisor 1's modifications
    And Supervisor 2: Attempt to save changes after Supervisor 1
    Then System detects concurrent edit conflict and displays appropriate message (e.g., 'This shift has been modified by another user. Please refresh and try again.')
    And Supervisor 2: Refresh the schedule view
    Then Updated schedule reflects Supervisor 1's changes, Supervisor 2's unsaved changes are discarded or highlighted for review

  Scenario: Verify system performance with maximum concurrent schedule edits
    Given Test environment supports performance testing
    Given 100 supervisor accounts are available or can be simulated
    Given Sufficient employee and shift data exists in the system
    Given Performance monitoring tools are configured
    When Prepare 100 concurrent supervisor sessions accessing the schedule creation page
    Then All 100 sessions successfully load the schedule creation interface
    And Initiate simultaneous schedule edit operations from all 100 sessions
    Then System accepts all edit requests without crashing or timing out
    And Monitor system response time for each edit operation
    Then Response time remains within acceptable limits (e.g., under 3 seconds per operation)
    And Execute save operations from all 100 sessions simultaneously
    Then All save operations are processed successfully without data loss or corruption
    And Verify database integrity after concurrent operations
    Then All schedule changes are correctly saved in EmployeeSchedules table with no duplicate or missing entries
    And Check system logs for errors or warnings during concurrent operations
    Then No critical errors are logged; system handles load gracefully
    And Verify API endpoint performance metrics
    Then POST /api/schedules and PUT /api/schedules/{id} endpoints maintain acceptable performance under load

  # Accessibility Test Scenarios
  Scenario: Keyboard Navigation
    When the user navigates using keyboard only
    Then all interactive elements should be accessible via keyboard
    And focus indicators should be clearly visible

  Scenario: Screen Reader Compatibility
    When the user accesses the page with a screen reader
    Then all content should be properly announced
    And ARIA labels should be present for all interactive elements

  Scenario: Color Contrast
    Then all text should meet WCAG AA color contrast standards
    And important information should not rely solely on color

