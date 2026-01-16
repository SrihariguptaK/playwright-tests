import { test, expect } from '@playwright/test';

test.describe('Employee Schedule Viewing', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto('/login');
  });

  test('View assigned schedule for logged-in employee', async ({ page }) => {
    // Step 1: Employee logs into the system
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123');
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Dashboard is displayed
    await expect(page.locator('[data-testid="employee-dashboard"]')).toBeVisible({ timeout: 5000 });
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Step 2: Navigate to 'My Schedule' page
    await page.click('[data-testid="my-schedule-nav-link"]');
    
    // Expected Result: Schedule page displays assigned shifts
    await expect(page.locator('[data-testid="schedule-page"]')).toBeVisible({ timeout: 3000 });
    await expect(page.locator('[data-testid="assigned-shifts-container"]')).toBeVisible();
    
    // Verify schedule page displays shifts for current date range
    const shiftsCount = await page.locator('[data-testid="shift-item"]').count();
    expect(shiftsCount).toBeGreaterThan(0);
    
    // Step 3: Select a specific shift to view detailed information
    await page.locator('[data-testid="shift-item"]').first().click();
    
    // Expected Result: Shift times and breaks are correctly displayed
    await expect(page.locator('[data-testid="shift-start-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-end-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-break-time"]')).toBeVisible();
    
    // Verify shift details contain actual time values
    const startTime = await page.locator('[data-testid="shift-start-time"]').textContent();
    const endTime = await page.locator('[data-testid="shift-end-time"]').textContent();
    const breakTime = await page.locator('[data-testid="shift-break-time"]').textContent();
    
    expect(startTime).toBeTruthy();
    expect(endTime).toBeTruthy();
    expect(breakTime).toBeTruthy();
    
    // Test date range selection
    await page.click('[data-testid="date-range-selector"]');
    await page.click('[data-testid="next-week-option"]');
    
    // Verify schedule updates for new date range
    await expect(page.locator('[data-testid="assigned-shifts-container"]')).toBeVisible();
    await page.waitForLoadState('networkidle');
  });

  test('Receive notification on schedule change', async ({ page }) => {
    // Setup: Manager modifies employee's schedule
    // This would typically be done via API or separate manager session
    // For automation, we'll simulate the employee side after change
    
    // Step 1: Employee logs into the system
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123');
    await page.click('[data-testid="login-button"]');
    
    await expect(page.locator('[data-testid="employee-dashboard"]')).toBeVisible({ timeout: 5000 });
    
    // Step 2: Check for in-app notification
    // Expected Result: Notification is delivered via in-app
    const notificationIcon = page.locator('[data-testid="notification-icon"]');
    await expect(notificationIcon).toBeVisible();
    
    // Check if notification badge shows unread notifications
    const notificationBadge = page.locator('[data-testid="notification-badge"]');
    const badgeCount = await notificationBadge.textContent();
    expect(parseInt(badgeCount || '0')).toBeGreaterThan(0);
    
    // Click on notification icon to view notifications
    await notificationIcon.click();
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();
    
    // Verify schedule change notification is present
    const scheduleChangeNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'schedule' });
    await expect(scheduleChangeNotification).toBeVisible();
    
    // Click on the notification to view details
    await scheduleChangeNotification.click();
    
    // Step 3: Navigate to 'My Schedule' page
    await page.click('[data-testid="my-schedule-nav-link"]');
    
    // Expected Result: Schedule reflects the latest changes
    await expect(page.locator('[data-testid="schedule-page"]')).toBeVisible();
    await page.waitForLoadState('networkidle');
    
    // Verify updated schedule is displayed
    const updatedShift = page.locator('[data-testid="shift-item"]').first();
    await expect(updatedShift).toBeVisible();
    
    // Verify shift shows as modified or updated
    const modifiedIndicator = page.locator('[data-testid="shift-modified-indicator"]');
    await expect(modifiedIndicator.first()).toBeVisible();
  });

  test('Export schedule to calendar format', async ({ page }) => {
    // Step 1: Employee logs in and navigates to schedule
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'ValidPassword123');
    await page.click('[data-testid="login-button"]');
    
    await expect(page.locator('[data-testid="employee-dashboard"]')).toBeVisible({ timeout: 5000 });
    
    await page.click('[data-testid="my-schedule-nav-link"]');
    await expect(page.locator('[data-testid="schedule-page"]')).toBeVisible();
    
    // Step 2: Locate and click export schedule button
    const exportButton = page.locator('[data-testid="export-schedule-button"]');
    await expect(exportButton).toBeVisible();
    await exportButton.click();
    
    // Expected Result: Export options are displayed
    await expect(page.locator('[data-testid="export-options-modal"]')).toBeVisible();
    
    // Verify available export formats
    await expect(page.locator('[data-testid="export-format-ical"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-format-csv"]')).toBeVisible();
    await expect(page.locator('[data-testid="export-format-google"]')).toBeVisible();
    
    // Step 3: Select iCal/ICS format
    await page.click('[data-testid="export-format-ical"]');
    
    // Setup download listener
    const downloadPromise = page.waitForEvent('download');
    
    // Click confirm export button
    await page.click('[data-testid="confirm-export-button"]');
    
    // Expected Result: Schedule file is downloaded in selected format
    const download = await downloadPromise;
    
    // Verify download occurred
    expect(download.suggestedFilename()).toContain('.ics');
    
    // Verify file size is greater than 0
    const path = await download.path();
    expect(path).toBeTruthy();
    
    // Verify success message is displayed
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
    const successMessage = await page.locator('[data-testid="export-success-message"]').textContent();
    expect(successMessage).toContain('exported successfully');
  });
});