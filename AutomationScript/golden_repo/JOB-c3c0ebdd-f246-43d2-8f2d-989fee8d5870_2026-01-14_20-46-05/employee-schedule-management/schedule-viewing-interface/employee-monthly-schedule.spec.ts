import { test, expect } from '@playwright/test';

test.describe('Employee Monthly Schedule View', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto('/login');
  });

  test('Validate monthly schedule display and navigation', async ({ page }) => {
    // Step 1: Log in as employee
    await page.fill('[data-testid="username-input"]', 'employee.user@company.com');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123!');
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Schedule dashboard is displayed
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Step 2: Select monthly view
    await page.click('[data-testid="monthly-view-button"]');
    
    // Expected Result: Current month's schedule is displayed
    await expect(page.locator('[data-testid="monthly-schedule-view"]')).toBeVisible();
    const currentMonth = new Date().toLocaleString('default', { month: 'long', year: 'numeric' });
    await expect(page.locator('[data-testid="current-month-header"]')).toContainText(currentMonth);
    await expect(page.locator('[data-testid="shift-entry"]').first()).toBeVisible();
    
    // Step 3: Navigate to next month
    await page.click('[data-testid="next-month-button"]');
    
    // Expected Result: Next month's schedule is displayed accurately
    const nextMonthDate = new Date();
    nextMonthDate.setMonth(nextMonthDate.getMonth() + 1);
    const nextMonth = nextMonthDate.toLocaleString('default', { month: 'long', year: 'numeric' });
    await expect(page.locator('[data-testid="current-month-header"]')).toContainText(nextMonth);
    await expect(page.locator('[data-testid="monthly-schedule-view"]')).toBeVisible();
    
    // Verify schedule data loads within 5 seconds
    const scheduleLoadTime = await page.evaluate(() => {
      return performance.now();
    });
    expect(scheduleLoadTime).toBeLessThan(5000);
  });

  test('Verify access restriction to employee\'s monthly schedule', async ({ page }) => {
    // Step 1: Log in as employee A
    await page.fill('[data-testid="username-input"]', 'employeeA@company.com');
    await page.fill('[data-testid="password-input"]', 'EmployeeAPass123!');
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Schedule dashboard is displayed
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Get employee A's ID from the page or session
    const employeeAId = await page.locator('[data-testid="employee-id"]').textContent();
    
    // Step 2: Attempt to access employee B's monthly schedule
    const employeeBId = 'employee-b-12345';
    
    // Attempt via URL manipulation
    await page.goto(`/schedules/monthly?employeeId=${employeeBId}`);
    
    // Expected Result: Access denied with error message
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText(/access denied|unauthorized|permission/i);
    
    // Verify employee A's schedule is not replaced with employee B's data
    const displayedEmployeeId = await page.locator('[data-testid="employee-id"]').textContent();
    expect(displayedEmployeeId).toBe(employeeAId);
    
    // Attempt via API call interception
    const response = await page.request.get(`/api/schedules/monthly?employeeId=${employeeBId}`);
    expect(response.status()).toBe(403);
  });

  test('Verify monthly schedule loads within 5 seconds', async ({ page }) => {
    // Log in as employee
    await page.fill('[data-testid="username-input"]', 'employee.user@company.com');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123!');
    await page.click('[data-testid="login-button"]');
    
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
    
    // Measure load time for monthly view
    const startTime = Date.now();
    await page.click('[data-testid="monthly-view-button"]');
    await expect(page.locator('[data-testid="monthly-schedule-view"]')).toBeVisible();
    const endTime = Date.now();
    
    const loadTime = endTime - startTime;
    expect(loadTime).toBeLessThan(5000);
  });

  test('Verify current month is highlighted in schedule view', async ({ page }) => {
    // Log in as employee
    await page.fill('[data-testid="username-input"]', 'employee.user@company.com');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123!');
    await page.click('[data-testid="login-button"]');
    
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
    
    // Select monthly view
    await page.click('[data-testid="monthly-view-button"]');
    await expect(page.locator('[data-testid="monthly-schedule-view"]')).toBeVisible();
    
    // Verify current month has highlight class or attribute
    const currentMonthElement = page.locator('[data-testid="current-month-header"]');
    await expect(currentMonthElement).toHaveClass(/highlighted|active|current/);
  });

  test('Verify navigation to previous month', async ({ page }) => {
    // Log in as employee
    await page.fill('[data-testid="username-input"]', 'employee.user@company.com');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123!');
    await page.click('[data-testid="login-button"]');
    
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
    
    // Select monthly view
    await page.click('[data-testid="monthly-view-button"]');
    await expect(page.locator('[data-testid="monthly-schedule-view"]')).toBeVisible();
    
    // Navigate to previous month
    await page.click('[data-testid="previous-month-button"]');
    
    // Verify previous month is displayed
    const previousMonthDate = new Date();
    previousMonthDate.setMonth(previousMonthDate.getMonth() - 1);
    const previousMonth = previousMonthDate.toLocaleString('default', { month: 'long', year: 'numeric' });
    await expect(page.locator('[data-testid="current-month-header"]')).toContainText(previousMonth);
    await expect(page.locator('[data-testid="monthly-schedule-view"]')).toBeVisible();
  });

  test('Verify shift details are displayed in monthly schedule', async ({ page }) => {
    // Log in as employee
    await page.fill('[data-testid="username-input"]', 'employee.user@company.com');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123!');
    await page.click('[data-testid="login-button"]');
    
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
    
    // Select monthly view
    await page.click('[data-testid="monthly-view-button"]');
    await expect(page.locator('[data-testid="monthly-schedule-view"]')).toBeVisible();
    
    // Verify shift entries contain required details
    const firstShift = page.locator('[data-testid="shift-entry"]').first();
    await expect(firstShift).toBeVisible();
    await expect(firstShift.locator('[data-testid="shift-start-time"]')).toBeVisible();
    await expect(firstShift.locator('[data-testid="shift-end-time"]')).toBeVisible();
    await expect(firstShift.locator('[data-testid="shift-location"]')).toBeVisible();
  });
});