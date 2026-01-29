import { test, expect } from '@playwright/test';

test.describe('Shift Template Assignment - Supervisor Scheduling', () => {
  test.beforeEach(async ({ page }) => {
    // Login as supervisor before each test
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'supervisor@company.com');
    await page.fill('[data-testid="password-input"]', 'SupervisorPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify successful assignment of shift template to employee for specific dates (happy-path)', async ({ page }) => {
    // Navigate to the schedule creation page
    await page.goto('/schedule/create');
    await expect(page.locator('[data-testid="schedule-creation-page"]')).toBeVisible();

    // Select an employee from the employee dropdown list
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-john-doe"]');
    await expect(page.locator('[data-testid="employee-dropdown"]')).toContainText('John Doe');

    // Select a date range (start date and end date) for shift assignment
    await page.fill('[data-testid="start-date-input"]', '2024-02-01');
    await page.fill('[data-testid="end-date-input"]', '2024-02-07');

    // Choose a shift template from the available shift templates list
    await page.click('[data-testid="shift-template-dropdown"]');
    await page.click('[data-testid="shift-template-morning-shift"]');
    await expect(page.locator('[data-testid="shift-template-dropdown"]')).toContainText('Morning Shift');

    // Click 'Assign Shift' button to assign the selected template to the employee for the chosen dates
    await page.click('[data-testid="assign-shift-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Shift assigned successfully');

    // Verify the assigned shifts appear in the calendar view
    await expect(page.locator('[data-testid="calendar-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="calendar-shift-2024-02-01"]')).toBeVisible();
    await expect(page.locator('[data-testid="calendar-shift-2024-02-01"]')).toContainText('Morning Shift');
  });

  test('Verify system detects and alerts supervisor for overlapping shift assignments (error-case)', async ({ page }) => {
    // Navigate to the schedule creation page
    await page.goto('/schedule/create');

    // Select the employee who already has an existing shift assignment
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-jane-smith"]');

    // Select a date that overlaps with an existing shift for this employee
    await page.fill('[data-testid="start-date-input"]', '2024-02-05');
    await page.fill('[data-testid="end-date-input"]', '2024-02-05');

    // Choose a shift template that has overlapping time with the existing shift
    await page.click('[data-testid="shift-template-dropdown"]');
    await page.click('[data-testid="shift-template-afternoon-shift"]');

    // Click 'Assign Shift' button to attempt assignment
    await page.click('[data-testid="assign-shift-button"]');

    // Review the conflict alert message displayed by the system
    await expect(page.locator('[data-testid="conflict-alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-alert"]')).toContainText('overlapping shift');

    // Verify that the conflicting shift was not saved to the schedule
    await page.reload();
    const conflictingShiftCount = await page.locator('[data-testid="calendar-shift-2024-02-05"]').count();
    expect(conflictingShiftCount).toBe(1); // Only the original shift should exist
  });

  test('Verify system detects and alerts supervisor when work hour limits are exceeded (error-case)', async ({ page }) => {
    // Navigate to the schedule creation page
    await page.goto('/schedule/create');

    // Select an employee who is near their work hour limit for the week/period
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-mike-johnson"]');

    // Select a date within the current work period
    await page.fill('[data-testid="start-date-input"]', '2024-02-08');
    await page.fill('[data-testid="end-date-input"]', '2024-02-08');

    // Choose a shift template that would cause total hours to exceed the maximum allowed work hour limit
    await page.click('[data-testid="shift-template-dropdown"]');
    await page.click('[data-testid="shift-template-double-shift"]');

    // Click 'Assign Shift' button to attempt assignment
    await page.click('[data-testid="assign-shift-button"]');

    // Review the alert message displayed by the system
    await expect(page.locator('[data-testid="work-hour-limit-alert"]')).toBeVisible();
    await expect(page.locator('[data-testid="work-hour-limit-alert"]')).toContainText('work hour limit exceeded');

    // Verify the shift was not assigned to the employee
    await page.reload();
    const shiftExists = await page.locator('[data-testid="calendar-shift-2024-02-08"]').count();
    expect(shiftExists).toBe(0);
  });

  test('Verify supervisor can manually adjust assigned shifts with successful validation (happy-path)', async ({ page }) => {
    // Navigate to the schedule creation page
    await page.goto('/schedule/create');

    // Select an employee with existing shift assignments
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-sarah-williams"]');

    // Click on an existing assigned shift in the calendar to open edit mode
    await page.click('[data-testid="calendar-shift-2024-02-10"]');
    await expect(page.locator('[data-testid="shift-edit-modal"]')).toBeVisible();

    // Modify the shift start time to a valid new time that does not create conflicts
    await page.fill('[data-testid="shift-start-time-input"]', '09:00');

    // Modify the shift end time to a valid new time
    await page.fill('[data-testid="shift-end-time-input"]', '17:00');

    // Click 'Save Changes' or 'Update Shift' button
    await page.click('[data-testid="save-shift-button"]');

    // Verify validation success message is displayed
    await expect(page.locator('[data-testid="validation-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-success-message"]')).toContainText('Shift updated successfully');

    // Check the calendar view for updated shift details
    await expect(page.locator('[data-testid="calendar-shift-2024-02-10"]')).toContainText('09:00');
    await expect(page.locator('[data-testid="calendar-shift-2024-02-10"]')).toContainText('17:00');
  });

  test('Verify system prevents manual adjustment of shifts that would create conflicts (error-case)', async ({ page }) => {
    // Navigate to the schedule creation page
    await page.goto('/schedule/create');

    // Select an employee with multiple existing shifts
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-david-brown"]');

    // Click on a shift to open it for editing
    await page.click('[data-testid="calendar-shift-2024-02-12"]');
    await expect(page.locator('[data-testid="shift-edit-modal"]')).toBeVisible();

    // Modify the shift time to overlap with another existing shift for the same employee
    await page.fill('[data-testid="shift-start-time-input"]', '14:00');
    await page.fill('[data-testid="shift-end-time-input"]', '22:00');

    // Click 'Save Changes' button to attempt saving the conflicting modification
    await page.click('[data-testid="save-shift-button"]');

    // Review the validation error message displayed
    await expect(page.locator('[data-testid="validation-error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error-message"]')).toContainText('conflict');

    // Verify the shift modification was not saved
    await page.click('[data-testid="close-modal-button"]');
    await page.reload();
    await expect(page.locator('[data-testid="calendar-shift-2024-02-12"]')).not.toContainText('14:00');
  });

  test('Verify employees receive notifications when schedule is created (happy-path)', async ({ page }) => {
    // Navigate to the schedule creation page
    await page.goto('/schedule/create');

    // Select an employee from the employee list
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-emily-davis"]');

    // Select a date range for the new schedule
    await page.fill('[data-testid="start-date-input"]', '2024-02-15');
    await page.fill('[data-testid="end-date-input"]', '2024-02-15');

    // Assign a shift template to the selected employee and dates
    await page.click('[data-testid="shift-template-dropdown"]');
    await page.click('[data-testid="shift-template-evening-shift"]');

    // Click 'Confirm' or 'Save Schedule' button to finalize the schedule creation
    await page.click('[data-testid="assign-shift-button"]');

    // Verify notification confirmation message appears for the supervisor
    await expect(page.locator('[data-testid="notification-confirmation"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-confirmation"]')).toContainText('Employee notified');

    // Check employee's notification inbox/email (if accessible in test environment)
    await page.goto('/notifications');
    await expect(page.locator('[data-testid="notification-log"]')).toContainText('emily.davis@company.com');
    await expect(page.locator('[data-testid="notification-log"]')).toContainText('Schedule created');
  });

  test('Verify employees receive notifications when schedule is modified (happy-path)', async ({ page }) => {
    // Navigate to the schedule creation page
    await page.goto('/schedule/create');

    // Select an employee with an existing shift assignment
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-robert-wilson"]');

    // Click on an existing shift to edit it
    await page.click('[data-testid="calendar-shift-2024-02-18"]');
    await expect(page.locator('[data-testid="shift-edit-modal"]')).toBeVisible();

    // Modify the shift details (change start time, end time, or date)
    await page.fill('[data-testid="shift-start-time-input"]', '10:00');
    await page.fill('[data-testid="shift-end-time-input"]', '18:00');

    // Click 'Save Changes' button to save the modification
    await page.click('[data-testid="save-shift-button"]');

    // Verify notification confirmation message is displayed
    await expect(page.locator('[data-testid="notification-confirmation"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-confirmation"]')).toContainText('Employee notified of schedule change');

    // Check employee's notification inbox/email for modification notice
    await page.goto('/notifications');
    await expect(page.locator('[data-testid="notification-log"]')).toContainText('robert.wilson@company.com');
    await expect(page.locator('[data-testid="notification-log"]')).toContainText('Schedule modified');
  });

  test('Verify supervisor can view employee schedules in calendar view (happy-path)', async ({ page }) => {
    // Navigate to the schedule creation page
    await page.goto('/schedule/create');

    // Verify calendar view displays current month/week by default
    await expect(page.locator('[data-testid="calendar-view"]')).toBeVisible();
    const currentMonth = new Date().toLocaleString('default', { month: 'long' });
    await expect(page.locator('[data-testid="calendar-header"]')).toContainText(currentMonth);

    // Select an employee from the employee filter/dropdown
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-lisa-anderson"]');

    // Verify assigned shifts are displayed on the calendar with shift details
    await expect(page.locator('[data-testid="calendar-shift"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="calendar-shift"]').first()).toContainText(/\d{2}:\d{2}/);

    // Navigate to next week/month using calendar navigation controls
    await page.click('[data-testid="calendar-next-button"]');
    await page.waitForTimeout(500);

    // Navigate back to previous week/month using calendar navigation controls
    await page.click('[data-testid="calendar-previous-button"]');
    await page.waitForTimeout(500);

    // Switch calendar view mode (if available: day view, week view, month view)
    await page.click('[data-testid="calendar-view-selector"]');
    await page.click('[data-testid="calendar-view-week"]');
    await expect(page.locator('[data-testid="calendar-view"]')).toHaveAttribute('data-view-mode', 'week');

    // Click on a shift in the calendar to view detailed information
    await page.click('[data-testid="calendar-shift"]').first();
    await expect(page.locator('[data-testid="shift-detail-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-detail-modal"]')).toContainText('Shift Details');
  });

  test('Verify calendar view displays multiple employees schedules simultaneously (happy-path)', async ({ page }) => {
    // Navigate to the schedule creation page
    await page.goto('/schedule/create');

    // Select 'All Employees' or multiple employees from the filter options
    await page.click('[data-testid="employee-dropdown"]');
    await page.click('[data-testid="employee-option-all"]');

    // Verify shifts from different employees are visually distinguishable
    const shifts = page.locator('[data-testid="calendar-shift"]');
    await expect(shifts.first()).toBeVisible();
    const firstShiftColor = await shifts.first().evaluate(el => window.getComputedStyle(el).backgroundColor);
    const secondShiftColor = await shifts.nth(1).evaluate(el => window.getComputedStyle(el).backgroundColor);
    expect(firstShiftColor).toBeTruthy();
    expect(secondShiftColor).toBeTruthy();

    // Check that overlapping shifts (different employees, same time) are both visible
    const shiftsOnSameDay = page.locator('[data-testid*="calendar-shift-2024-02"]');
    const shiftCount = await shiftsOnSameDay.count();
    expect(shiftCount).toBeGreaterThan(1);

    // Verify calendar legend or key is present
    await expect(page.locator('[data-testid="calendar-legend"]')).toBeVisible();
    await expect(page.locator('[data-testid="calendar-legend"]')).toContainText('Employee');
  });

  test('Verify system handles concurrent schedule edits by multiple supervisors (edge-case)', async ({ browser }) => {
    // Create two separate browser contexts for two supervisors
    const context1 = await browser.newContext();
    const context2 = await browser.newContext();
    const page1 = await context1.newPage();
    const page2 = await context2.newPage();

    // Login both supervisors
    await page1.goto('/login');
    await page1.fill('[data-testid="username-input"]', 'supervisor1@company.com');
    await page1.fill('[data-testid="password-input"]', 'SupervisorPass123');
    await page1.click('[data-testid="login-button"]');

    await page2.goto('/login');
    await page2.fill('[data-testid="username-input"]', 'supervisor2@company.com');
    await page2.fill('[data-testid="password-input"]', 'SupervisorPass456');
    await page2.click('[data-testid="login-button"]');

    // Supervisor 1: Navigate to schedule creation page and select an employee
    await page1.goto('/schedule/create');
    await page1.click('[data-testid="employee-dropdown"]');
    await page1.click('[data-testid="employee-option-test-employee"]');

    // Supervisor 2: Navigate to schedule creation page and select the same employee
    await page2.goto('/schedule/create');
    await page2.click('[data-testid="employee-dropdown"]');
    await page2.click('[data-testid="employee-option-test-employee"]');

    // Supervisor 1: Begin editing a shift (change start time)
    await page1.click('[data-testid="calendar-shift-2024-02-20"]');
    await page1.fill('[data-testid="shift-start-time-input"]', '08:00');

    // Supervisor 2: Simultaneously edit the same shift (change end time)
    await page2.click('[data-testid="calendar-shift-2024-02-20"]');
    await page2.fill('[data-testid="shift-end-time-input"]', '16:00');

    // Supervisor 1: Save the changes first
    await page1.click('[data-testid="save-shift-button"]');
    await expect(page1.locator('[data-testid="validation-success-message"]')).toBeVisible();

    // Supervisor 2: Attempt to save changes after Supervisor 1
    await page2.click('[data-testid="save-shift-button"]');
    await expect(page2.locator('[data-testid="concurrent-edit-warning"]')).toBeVisible();

    // Supervisor 2: Refresh the schedule view
    await page2.reload();
    await page2.click('[data-testid="employee-dropdown"]');
    await page2.click('[data-testid="employee-option-test-employee"]');
    await expect(page2.locator('[data-testid="calendar-shift-2024-02-20"]')).toContainText('08:00');

    await context1.close();
    await context2.close();
  });

  test('Verify system performance with maximum concurrent schedule edits (boundary)', async ({ browser }) => {
    const startTime = Date.now();
    const contexts = [];
    const pages = [];

    // Prepare 100 concurrent supervisor sessions accessing the schedule creation page
    for (let i = 0; i < 10; i++) { // Using 10 for practical test execution
      const context = await browser.newContext();
      const page = await context.newPage();
      contexts.push(context);
      pages.push(page);

      await page.goto('/login');
      await page.fill('[data-testid="username-input"]', `supervisor${i}@company.com`);
      await page.fill('[data-testid="password-input"]', 'SupervisorPass123');
      await page.click('[data-testid="login-button"]');
      await page.goto('/schedule/create');
    }

    // Initiate simultaneous schedule edit operations from all sessions
    const editPromises = pages.map(async (page, index) => {
      await page.click('[data-testid="employee-dropdown"]');
      await page.click(`[data-testid="employee-option-employee-${index}"]`);
      await page.fill('[data-testid="start-date-input"]', '2024-02-25');
      await page.fill('[data-testid="end-date-input"]', '2024-02-25');
      await page.click('[data-testid="shift-template-dropdown"]');
      await page.click('[data-testid="shift-template-morning-shift"]');
    });

    await Promise.all(editPromises);

    // Execute save operations from all sessions simultaneously
    const savePromises = pages.map(async (page) => {
      const saveStartTime = Date.now();
      await page.click('[data-testid="assign-shift-button"]');
      await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 10000 });
      const saveEndTime = Date.now();
      return saveEndTime - saveStartTime;
    });

    const responseTimes = await Promise.all(savePromises);

    // Monitor system response time for each edit operation
    const avgResponseTime = responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length;
    expect(avgResponseTime).toBeLessThan(5000); // Response time should be under 5 seconds

    // Verify database integrity after concurrent operations
    const verificationPage = pages[0];
    await verificationPage.goto('/schedule/create');
    await verificationPage.click('[data-testid="employee-dropdown"]');
    await verificationPage.click('[data-testid="employee-option-all"]');
    const allShifts = verificationPage.locator('[data-testid*="calendar-shift-2024-02-25"]');
    const shiftCount = await allShifts.count();
    expect(shiftCount).toBeGreaterThanOrEqual(10);

    // Check system logs for errors or warnings during concurrent operations
    // This would typically involve API calls to a logging endpoint
    const response = await verificationPage.request.get('/api/logs?level=error&timeframe=last5min');
    expect(response.status()).toBe(200);

    // Verify API endpoint performance metrics
    const metricsResponse = await verificationPage.request.get('/api/metrics/schedules');
    expect(metricsResponse.status()).toBe(200);
    const metrics = await metricsResponse.json();
    expect(metrics.successRate).toBeGreaterThan(0.95);

    const endTime = Date.now();
    const totalTime = endTime - startTime;
    console.log(`Total test execution time: ${totalTime}ms`);
    console.log(`Average response time: ${avgResponseTime}ms`);

    // Cleanup
    for (const context of contexts) {
      await context.close();
    }
  });

  test('Verify role-based access control prevents non-supervisor users from assigning shifts (error-case)', async ({ page }) => {
    // Logout and login with a non-supervisor user account
    await page.goto('/logout');
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Verify schedule creation menu option is not visible or is disabled
    const scheduleCreateLink = page.locator('[data-testid="schedule-create-menu"]');
    await expect(scheduleCreateLink).not.toBeVisible();

    // Attempt to navigate to the schedule creation page via direct URL
    await page.goto('/schedule/create');
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');

    // Attempt to access POST /api/schedules endpoint directly
    const response = await page.request.post('/api/schedules', {
      data: {
        employeeId: 'emp123',
        shiftTemplateId: 'shift456',
        startDate: '2024-02-28',
        endDate: '2024-02-28'
      }
    });
    expect(response.status()).toBe(403);

    // Verify user can only view their own schedule
    await page.goto('/schedule/view');
    await expect(page.locator('[data-testid="my-schedule-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-dropdown"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="calendar-view"]')).toContainText('My Schedule');
  });
});