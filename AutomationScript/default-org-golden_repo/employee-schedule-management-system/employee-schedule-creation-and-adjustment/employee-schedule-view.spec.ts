import { test, expect } from '@playwright/test';

test.describe('Employee Schedule View', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto('/login');
  });

  test('Employee views assigned schedule successfully', async ({ page }) => {
    // Step 1: Employee logs into the system
    await page.fill('[data-testid="username-input"]', 'employee.user@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123!');
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Authentication succeeds and dashboard loads
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="dashboard-container"]')).toBeVisible();
    
    // Step 2: Navigate to 'My Schedule' page
    await page.click('[data-testid="my-schedule-link"]');
    
    // Expected Result: Calendar view displays assigned shifts
    await expect(page).toHaveURL(/.*schedule/);
    await expect(page.locator('[data-testid="schedule-calendar"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-item"]').first()).toBeVisible();
    
    // Verify shift basic information is displayed
    const firstShift = page.locator('[data-testid="shift-item"]').first();
    await expect(firstShift).toContainText(/\d{1,2}:\d{2}/);
    
    // Step 3: Click on a shift to view details
    await firstShift.click();
    
    // Expected Result: Shift details popup is displayed
    await expect(page.locator('[data-testid="shift-details-popup"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-role"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-date"]')).toBeVisible();
    
    // Close the shift details popup
    await page.click('[data-testid="close-shift-details"]');
    await expect(page.locator('[data-testid="shift-details-popup"]')).not.toBeVisible();
    
    // Verify calendar remains functional
    await expect(page.locator('[data-testid="schedule-calendar"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-item"]').first()).toBeVisible();
  });

  test('Schedule loads within performance requirements', async ({ page }) => {
    // Login first
    await page.fill('[data-testid="username-input"]', 'employee.user@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Step 1: Start timer and navigate to 'My Schedule' page
    const startTime = Date.now();
    await page.click('[data-testid="my-schedule-link"]');
    
    // Wait for schedule calendar to be fully rendered
    await page.waitForSelector('[data-testid="schedule-calendar"]', { state: 'visible' });
    await page.waitForSelector('[data-testid="shift-item"]', { state: 'visible' });
    
    // Measure load time
    const endTime = Date.now();
    const loadTime = endTime - startTime;
    
    // Expected Result: Schedule data loads within 2 seconds (2000ms)
    expect(loadTime).toBeLessThan(2000);
    
    // Verify all shifts are visible and interactive
    const shiftCount = await page.locator('[data-testid="shift-item"]').count();
    expect(shiftCount).toBeGreaterThan(0);
    
    // Verify shifts are interactive
    await expect(page.locator('[data-testid="shift-item"]').first()).toBeEnabled();
  });

  test('Notifications display for schedule changes', async ({ page, context }) => {
    // Step 1: Scheduler logs in and navigates to schedule management
    await page.fill('[data-testid="username-input"]', 'scheduler.admin@company.com');
    await page.fill('[data-testid="password-input"]', 'AdminPassword123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
    
    await page.click('[data-testid="schedule-management-link"]');
    await expect(page.locator('[data-testid="schedule-management-container"]')).toBeVisible();
    
    // Step 2: Scheduler selects employee and makes a modification
    await page.click('[data-testid="employee-selector"]');
    await page.click('[data-testid="employee-option"]', { hasText: 'employee.user@company.com' });
    
    const existingShift = page.locator('[data-testid="schedule-shift-row"]').first();
    await existingShift.click();
    
    // Modify shift time
    await page.click('[data-testid="edit-shift-button"]');
    await page.fill('[data-testid="shift-start-time"]', '09:00');
    await page.fill('[data-testid="shift-end-time"]', '17:00');
    
    // Step 3: Scheduler saves the updated schedule
    await page.click('[data-testid="save-shift-button"]');
    
    // Expected Result: Notification is sent to employee
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule updated');
    
    // Open new page for employee to check notification
    const employeePage = await context.newPage();
    await employeePage.goto('/login');
    
    // Step 4: Employee logs in and views notification
    await employeePage.fill('[data-testid="username-input"]', 'employee.user@company.com');
    await employeePage.fill('[data-testid="password-input"]', 'ValidPassword123!');
    await employeePage.click('[data-testid="login-button"]');
    await expect(employeePage).toHaveURL(/.*dashboard/);
    
    // Check notification center
    await expect(employeePage.locator('[data-testid="notification-badge"]')).toBeVisible();
    await employeePage.click('[data-testid="notification-icon"]');
    
    // Expected Result: Notification content is accurate and actionable
    await expect(employeePage.locator('[data-testid="notification-panel"]')).toBeVisible();
    const notification = employeePage.locator('[data-testid="notification-item"]').first();
    await expect(notification).toBeVisible();
    await expect(notification).toContainText('schedule');
    await expect(notification).toContainText('updated');
    
    // Step 5: Click on notification to view details
    await notification.click();
    
    // Verify actionable link works
    await expect(employeePage).toHaveURL(/.*schedule/);
    await expect(employeePage.locator('[data-testid="schedule-calendar"]')).toBeVisible();
    
    // Verify updated shift is displayed
    const updatedShift = employeePage.locator('[data-testid="shift-item"]').first();
    await expect(updatedShift).toBeVisible();
    
    await employeePage.close();
  });
});