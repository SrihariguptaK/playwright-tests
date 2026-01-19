import { test, expect } from '@playwright/test';

test.describe('Story-4: Modify Assigned Employee Schedules', () => {
  test.beforeEach(async ({ page }) => {
    // Login as Scheduler
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@company.com');
    await page.fill('[data-testid="password-input"]', 'schedulerPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful schedule modification with audit trail', async ({ page }) => {
    // Navigate to employee schedule view
    await page.click('[data-testid="schedule-management-menu"]');
    await page.click('[data-testid="view-schedules-link"]');
    await expect(page.locator('[data-testid="schedule-list"]')).toBeVisible();

    // Select an employee from the list
    await page.click('[data-testid="employee-row-1"]');
    await expect(page.locator('[data-testid="employee-schedule-details"]')).toBeVisible();

    // Click on a specific shift to open edit mode
    await page.click('[data-testid="shift-item-1"]');
    await page.click('[data-testid="edit-shift-button"]');
    await expect(page.locator('[data-testid="shift-edit-form"]')).toBeVisible();

    // Modify the shift start time
    await page.fill('[data-testid="shift-start-time-input"]', '10:00');
    await expect(page.locator('[data-testid="shift-start-time-input"]')).toHaveValue('10:00');

    // Modify the shift end time
    await page.fill('[data-testid="shift-end-time-input"]', '18:00');
    await expect(page.locator('[data-testid="shift-end-time-input"]')).toHaveValue('18:00');

    // Save modifications
    await page.click('[data-testid="save-schedule-button"]');
    
    // Verify confirmation displayed
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Schedule updated successfully');

    // Verify the updated shift is displayed with new times
    await expect(page.locator('[data-testid="shift-item-1"]')).toContainText('10:00');
    await expect(page.locator('[data-testid="shift-item-1"]')).toContainText('18:00');

    // Access the audit trail
    await page.click('[data-testid="view-audit-trail-button"]');
    await expect(page.locator('[data-testid="audit-trail-panel"]')).toBeVisible();

    // Verify audit trail contains required information
    const auditEntry = page.locator('[data-testid="audit-entry-latest"]');
    await expect(auditEntry).toBeVisible();
    await expect(auditEntry).toContainText('scheduler@company.com');
    await expect(auditEntry).toContainText(/\d{4}-\d{2}-\d{2}/);
    await expect(auditEntry).toContainText('Modified shift');
    await expect(auditEntry).toContainText('10:00');
    await expect(auditEntry).toContainText('18:00');
  });

  test('Reject schedule modification with overlapping shifts', async ({ page }) => {
    // Navigate to employee schedule view
    await page.click('[data-testid="schedule-management-menu"]');
    await page.click('[data-testid="view-schedules-link"]');
    await expect(page.locator('[data-testid="schedule-list"]')).toBeVisible();

    // Select an employee with multiple shifts
    await page.click('[data-testid="employee-row-2"]');
    await expect(page.locator('[data-testid="employee-schedule-details"]')).toBeVisible();

    // Verify existing shifts are displayed
    await expect(page.locator('[data-testid="shift-item-1"]')).toContainText('09:00');
    await expect(page.locator('[data-testid="shift-item-1"]')).toContainText('17:00');
    await expect(page.locator('[data-testid="shift-item-2"]')).toContainText('14:00');
    await expect(page.locator('[data-testid="shift-item-2"]')).toContainText('22:00');

    // Click to edit the first shift
    await page.click('[data-testid="shift-item-1"]');
    await page.click('[data-testid="edit-shift-button"]');
    await expect(page.locator('[data-testid="shift-edit-form"]')).toBeVisible();

    // Modify shift end time to create overlap
    await page.fill('[data-testid="shift-end-time-input"]', '20:00');
    await expect(page.locator('[data-testid="shift-end-time-input"]')).toHaveValue('20:00');

    // Attempt to save changes
    await page.click('[data-testid="save-schedule-button"]');

    // Verify validation error is displayed
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('overlapping');

    // Attempt to save again without resolving
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();

    // Verify save is blocked
    await expect(page.locator('[data-testid="shift-edit-form"]')).toBeVisible();

    // Cancel and verify original schedule unchanged
    await page.click('[data-testid="cancel-edit-button"]');
    await expect(page.locator('[data-testid="shift-item-1"]')).toContainText('09:00');
    await expect(page.locator('[data-testid="shift-item-1"]')).toContainText('17:00');

    // Modify to non-overlapping time
    await page.click('[data-testid="shift-item-1"]');
    await page.click('[data-testid="edit-shift-button"]');
    await page.fill('[data-testid="shift-end-time-input"]', '13:00');
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
  });

  test('Verify notification sent upon schedule update', async ({ page }) => {
    // Navigate to employee schedule view
    await page.click('[data-testid="schedule-management-menu"]');
    await page.click('[data-testid="view-schedules-link"]');
    await expect(page.locator('[data-testid="schedule-list"]')).toBeVisible();

    // Select an employee
    await page.click('[data-testid="employee-row-3"]');
    await expect(page.locator('[data-testid="employee-schedule-details"]')).toBeVisible();

    // Open shift for editing
    await page.click('[data-testid="shift-item-1"]');
    await page.click('[data-testid="edit-shift-button"]');
    await expect(page.locator('[data-testid="shift-edit-form"]')).toBeVisible();

    // Modify shift times
    await page.fill('[data-testid="shift-start-time-input"]', '10:00');
    await page.fill('[data-testid="shift-end-time-input"]', '18:00');

    // Save schedule
    await page.click('[data-testid="save-schedule-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Navigate to notification queue/log
    await page.click('[data-testid="notifications-menu"]');
    await page.click('[data-testid="notification-log-link"]');
    await expect(page.locator('[data-testid="notification-log-panel"]')).toBeVisible();

    // Verify notification for employee
    const employeeNotification = page.locator('[data-testid="notification-employee-latest"]');
    await expect(employeeNotification).toBeVisible();
    await expect(employeeNotification).toContainText('Schedule change');
    await expect(employeeNotification).toContainText('10:00');
    await expect(employeeNotification).toContainText('18:00');

    // Verify notification for manager
    const managerNotification = page.locator('[data-testid="notification-manager-latest"]');
    await expect(managerNotification).toBeVisible();
    await expect(managerNotification).toContainText('Schedule change');
    await expect(managerNotification).toContainText('10:00');
    await expect(managerNotification).toContainText('18:00');

    // Check notification delivery status
    await page.click('[data-testid="notification-delivery-status-button"]');
    await expect(page.locator('[data-testid="delivery-status-panel"]')).toBeVisible();

    // Verify delivery confirmed
    const deliveryStatus = page.locator('[data-testid="delivery-status-latest"]');
    await expect(deliveryStatus).toContainText('Delivered');
    await expect(deliveryStatus).toContainText(/\d{4}-\d{2}-\d{2}/);

    // Verify delivery timestamp recorded
    const timestamp = await deliveryStatus.locator('[data-testid="delivery-timestamp"]').textContent();
    expect(timestamp).toMatch(/\d{4}-\d{2}-\d{2} \d{2}:\d{2}/);
  });
});