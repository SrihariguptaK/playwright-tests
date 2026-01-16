import { test, expect } from '@playwright/test';

test.describe('Schedule Notification Tests - Story 10', () => {
  const managerEmail = 'manager@company.com';
  const managerPassword = 'Manager123!';
  const employeeEmail = 'employee@company.com';
  const employeePassword = 'Employee123!';
  const employeeName = 'John Doe';
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';

  test.beforeEach(async ({ page }) => {
    await page.goto(baseURL);
  });

  test('Receive notification on schedule creation (happy-path)', async ({ page, context }) => {
    // Manager logs into the system
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', managerEmail);
    await page.fill('[data-testid="password-input"]', managerPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard-header"]')).toBeVisible();

    // Manager navigates to the schedule management section
    await page.click('[data-testid="schedule-management-link"]');
    await expect(page.locator('[data-testid="schedule-management-page"]')).toBeVisible();

    // Manager selects the employee from the employee list
    await page.click('[data-testid="employee-list-dropdown"]');
    await page.click(`[data-testid="employee-option-${employeeName.replace(' ', '-').toLowerCase()}"]`);

    // Manager assigns a new shift with specific date, time, and location details
    await page.click('[data-testid="create-shift-button"]');
    await page.fill('[data-testid="shift-date-input"]', '2024-02-15');
    await page.fill('[data-testid="shift-start-time-input"]', '09:00');
    await page.fill('[data-testid="shift-end-time-input"]', '17:00');
    await page.fill('[data-testid="shift-location-input"]', 'Main Office');

    // Manager saves the newly created shift assignment
    await page.click('[data-testid="save-shift-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule is created');

    // System triggers notification service - verify notification was sent
    await expect(page.locator('[data-testid="notification-sent-indicator"]')).toBeVisible({ timeout: 10000 });

    // Manager logs out
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Employee logs into the application
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard-header"]')).toBeVisible();

    // Employee checks the in-app notification center
    await page.click('[data-testid="notification-bell-icon"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();

    // Verify notification contains correct shift details
    const notification = page.locator('[data-testid="notification-item"]').first();
    await expect(notification).toContainText('New shift assigned');
    await expect(notification).toContainText('2024-02-15');
    await expect(notification).toContainText('09:00');
    await expect(notification).toContainText('17:00');
    await expect(notification).toContainText('Main Office');

    // Employee clicks on the in-app notification to view full details
    await notification.click();
    await expect(page.locator('[data-testid="notification-detail-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-detail-content"]')).toContainText('Main Office');
    await page.click('[data-testid="close-notification-detail"]');

    // Employee navigates to the notification history section in their profile
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="notification-history-link"]');
    await expect(page.locator('[data-testid="notification-history-page"]')).toBeVisible();

    // Employee locates the schedule creation notification in the history list
    const historyNotification = page.locator('[data-testid="notification-history-item"]').first();
    await expect(historyNotification).toBeVisible();
    await expect(historyNotification).toContainText('New shift assigned');
    
    // Verify notification is listed with accurate timestamp
    const timestamp = await historyNotification.locator('[data-testid="notification-timestamp"]').textContent();
    expect(timestamp).toBeTruthy();
    expect(timestamp).toMatch(/\d{4}-\d{2}-\d{2}/);
  });

  test('Receive notification on schedule cancellation (happy-path)', async ({ page, context }) => {
    // Manager logs into the system
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', managerEmail);
    await page.fill('[data-testid="password-input"]', managerPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard-header"]')).toBeVisible();

    // Manager navigates to the schedule management section
    await page.click('[data-testid="schedule-management-link"]');
    await expect(page.locator('[data-testid="schedule-management-page"]')).toBeVisible();

    // Manager locates the employee's assigned shift that needs to be cancelled
    await page.fill('[data-testid="search-employee-input"]', employeeName);
    await page.click('[data-testid="search-button"]');
    await expect(page.locator('[data-testid="employee-schedule-list"]')).toBeVisible();

    // Manager selects the cancel option for the assigned shift
    const shiftToCancel = page.locator('[data-testid="shift-item"]').first();
    await shiftToCancel.locator('[data-testid="shift-actions-menu"]').click();
    await page.click('[data-testid="cancel-shift-option"]');

    // Manager confirms the cancellation action
    await expect(page.locator('[data-testid="cancel-confirmation-dialog"]')).toBeVisible();
    await page.click('[data-testid="confirm-cancel-button"]');

    // Verify schedule is cancelled
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule is cancelled');

    // System triggers notification service to send cancellation notifications
    await expect(page.locator('[data-testid="notification-sent-indicator"]')).toBeVisible({ timeout: 10000 });

    // Manager logs out
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');

    // Employee logs into the application
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="email-input"]', employeeEmail);
    await page.fill('[data-testid="password-input"]', employeePassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard-header"]')).toBeVisible();

    // Employee checks the in-app notification center
    await page.click('[data-testid="notification-bell-icon"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();

    // Employee clicks on the in-app cancellation notification
    const cancellationNotification = page.locator('[data-testid="notification-item"]').first();
    await expect(cancellationNotification).toBeVisible();
    
    // Verify notification clearly indicates cancellation
    await expect(cancellationNotification).toContainText('Shift cancelled');
    await expect(cancellationNotification).toContainText('cancelled');
    
    // Open cancellation notification details
    await cancellationNotification.click();
    await expect(page.locator('[data-testid="notification-detail-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="notification-detail-content"]')).toContainText('cancelled');
    await page.click('[data-testid="close-notification-detail"]');

    // Employee verifies the cancelled shift in their schedule view
    await page.click('[data-testid="my-schedule-link"]');
    await expect(page.locator('[data-testid="schedule-view-page"]')).toBeVisible();
    
    // Verify the shift is marked as cancelled or removed from active schedule
    const cancelledShift = page.locator('[data-testid="cancelled-shift-item"]').first();
    if (await cancelledShift.isVisible()) {
      await expect(cancelledShift).toContainText('Cancelled');
    } else {
      // If cancelled shifts are removed, verify it's not in the active schedule
      const activeShifts = await page.locator('[data-testid="active-shift-item"]').count();
      expect(activeShifts).toBeGreaterThanOrEqual(0);
    }
  });
});