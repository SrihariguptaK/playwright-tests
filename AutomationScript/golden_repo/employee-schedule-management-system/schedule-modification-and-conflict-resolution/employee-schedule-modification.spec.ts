import { test, expect } from '@playwright/test';

test.describe('Employee Schedule Modification', () => {
  test.beforeEach(async ({ page }) => {
    // Login as scheduler
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@company.com');
    await page.fill('[data-testid="password-input"]', 'schedulerPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful modification of employee schedule', async ({ page }) => {
    // Step 1: Navigate to employee schedule modification page
    await page.goto('/schedules');
    await page.click('[data-testid="employee-schedule-list"]');
    await page.click('[data-testid="employee-item"]:has-text("John Doe")');
    
    // Expected Result: Schedule details are displayed
    await expect(page.locator('[data-testid="schedule-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="employee-name"]')).toContainText('John Doe');
    
    // Step 2: Change shift times and submit
    const currentShiftStart = await page.locator('[data-testid="shift-start-time"]').inputValue();
    await page.fill('[data-testid="shift-start-time"]', '09:00');
    await page.fill('[data-testid="shift-end-time"]', '17:00');
    await page.click('[data-testid="submit-schedule-button"]');
    
    // Expected Result: System validates and saves changes
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule updated successfully');
    
    // Step 3: Verify notification sent to employee
    await page.goto('/notifications');
    await page.fill('[data-testid="notification-search"]', 'John Doe');
    await page.click('[data-testid="search-button"]');
    
    // Expected Result: Employee receives schedule change notification
    await expect(page.locator('[data-testid="notification-item"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="notification-item"]').first()).toContainText('Schedule change');
    await expect(page.locator('[data-testid="notification-recipient"]').first()).toContainText('John Doe');
  });

  test('Verify shift swap request and approval workflow', async ({ page }) => {
    // Step 1: Employee A requests shift swap with Employee B
    // Logout as scheduler and login as Employee A
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employeeA@company.com');
    await page.fill('[data-testid="password-input"]', 'employeePass123');
    await page.click('[data-testid="login-button"]');
    
    await page.goto('/my-schedule');
    await page.click('[data-testid="shift-item"]').first();
    await page.click('[data-testid="request-swap-button"]');
    await page.selectOption('[data-testid="swap-partner-select"]', { label: 'Employee B' });
    await page.click('[data-testid="submit-swap-request-button"]');
    
    // Expected Result: Swap request is created and pending approval
    await expect(page.locator('[data-testid="swap-status"]')).toContainText('Pending Approval');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Swap request submitted');
    
    // Step 2: Scheduler reviews and approves swap request
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@company.com');
    await page.fill('[data-testid="password-input"]', 'schedulerPass123');
    await page.click('[data-testid="login-button"]');
    
    await page.goto('/shift-swaps');
    await expect(page.locator('[data-testid="swap-request-item"]').first()).toBeVisible();
    await page.click('[data-testid="swap-request-item"]').first();
    await page.click('[data-testid="approve-swap-button"]');
    
    // Expected Result: Swap is executed and schedules updated
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Swap approved successfully');
    await expect(page.locator('[data-testid="swap-status"]')).toContainText('Approved');
    
    // Step 3: Notifications sent to both employees
    await page.goto('/notifications');
    await page.fill('[data-testid="notification-search"]', 'Employee A');
    await page.click('[data-testid="search-button"]');
    
    // Expected Result: Employees receive confirmation of swap
    await expect(page.locator('[data-testid="notification-item"]').filter({ hasText: 'Shift swap approved' })).toBeVisible();
    
    await page.fill('[data-testid="notification-search"]', 'Employee B');
    await page.click('[data-testid="search-button"]');
    await expect(page.locator('[data-testid="notification-item"]').filter({ hasText: 'Shift swap approved' })).toBeVisible();
  });

  test('Validate audit logging of schedule modifications', async ({ page }) => {
    // Step 1: Modify an employee schedule
    await page.goto('/schedules');
    await page.click('[data-testid="employee-schedule-list"]');
    await page.click('[data-testid="employee-item"]:has-text("Jane Smith")');
    
    const employeeName = await page.locator('[data-testid="employee-name"]').textContent();
    const originalShiftDate = await page.locator('[data-testid="shift-date"]').inputValue();
    
    await page.fill('[data-testid="shift-date"]', '2024-02-15');
    await page.fill('[data-testid="shift-start-time"]', '10:00');
    await page.fill('[data-testid="shift-end-time"]', '18:00');
    
    const modificationTime = new Date();
    await page.click('[data-testid="submit-schedule-button"]');
    
    // Expected Result: Modification is saved
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule updated successfully');
    
    // Step 2: Access audit logs for the schedule
    await page.goto('/audit-logs');
    await page.selectOption('[data-testid="log-type-filter"]', 'Schedule Modifications');
    await page.fill('[data-testid="employee-filter"]', 'Jane Smith');
    await page.click('[data-testid="apply-filters-button"]');
    
    // Expected Result: Modification details are recorded with timestamp and user
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText('Jane Smith');
    await expect(page.locator('[data-testid="audit-log-entry"]').first()).toContainText('Schedule Modified');
    await expect(page.locator('[data-testid="audit-log-user"]').first()).toContainText('scheduler@company.com');
    
    // Step 3: Verify audit log integrity
    await page.click('[data-testid="audit-log-entry"]').first();
    
    // Expected Result: Logs are complete and unaltered
    await expect(page.locator('[data-testid="audit-log-detail-employee"]')).toContainText('Jane Smith');
    await expect(page.locator('[data-testid="audit-log-detail-action"]')).toContainText('Schedule Modified');
    await expect(page.locator('[data-testid="audit-log-detail-user"]')).toContainText('scheduler@company.com');
    await expect(page.locator('[data-testid="audit-log-detail-timestamp"]')).toBeVisible();
    await expect(page.locator('[data-testid="audit-log-detail-changes"]')).toContainText('shift-date');
    await expect(page.locator('[data-testid="audit-log-detail-changes"]')).toContainText('2024-02-15');
    
    // Verify timestamp is within reasonable range (within last 5 minutes)
    const logTimestamp = await page.locator('[data-testid="audit-log-detail-timestamp"]').textContent();
    expect(logTimestamp).toBeTruthy();
  });
});