import { test, expect } from '@playwright/test';

test.describe('Attendance Anomaly Threshold Configuration', () => {
  test.beforeEach(async ({ page }) => {
    // Login as supervisor
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'supervisor@example.com');
    await page.fill('[data-testid="password-input"]', 'SupervisorPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate updating attendance anomaly thresholds (happy-path)', async ({ page }) => {
    // Step 1: Navigate to attendance anomaly notification settings page
    await page.goto('/settings/attendance-thresholds');
    await expect(page.locator('[data-testid="threshold-settings-page"]')).toBeVisible();

    // Step 2: Review currently displayed threshold values
    const currentLateArrival = await page.locator('[data-testid="late-arrival-threshold"]').inputValue();
    const currentAbsence = await page.locator('[data-testid="absence-threshold"]').inputValue();
    const currentEarlyDeparture = await page.locator('[data-testid="early-departure-threshold"]').inputValue();
    expect(currentLateArrival).toBeTruthy();
    expect(currentAbsence).toBeTruthy();
    expect(currentEarlyDeparture).toBeTruthy();

    // Step 3: Enter valid threshold values
    await page.fill('[data-testid="late-arrival-threshold"]', '15');
    await page.fill('[data-testid="absence-threshold"]', '2');
    await page.fill('[data-testid="early-departure-threshold"]', '10');

    // Step 4: Click Save button
    await page.click('[data-testid="save-thresholds-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Changes saved and applied immediately');

    // Step 5: Verify changes are persisted
    await page.reload();
    await expect(page.locator('[data-testid="late-arrival-threshold"]')).toHaveValue('15');
    await expect(page.locator('[data-testid="absence-threshold"]')).toHaveValue('2');
    await expect(page.locator('[data-testid="early-departure-threshold"]')).toHaveValue('10');

    // Step 6: Simulate attendance event triggering threshold (16 minutes late)
    await page.goto('/attendance/test-scenario');
    await page.fill('[data-testid="employee-id"]', 'EMP001');
    await page.fill('[data-testid="late-minutes"]', '16');
    await page.click('[data-testid="trigger-event-button"]');

    // Step 7: Check notifications dashboard for alerts
    await page.goto('/notifications');
    await expect(page.locator('[data-testid="notification-item"]').first()).toBeVisible();
    await expect(page.locator('[data-testid="notification-item"]').first()).toContainText('Late arrival');
    await expect(page.locator('[data-testid="notification-item"]').first()).toContainText('16 minutes');

    // Step 8: Test event below threshold (10 minutes late)
    await page.goto('/attendance/test-scenario');
    await page.fill('[data-testid="employee-id"]', 'EMP002');
    await page.fill('[data-testid="late-minutes"]', '10');
    await page.click('[data-testid="trigger-event-button"]');

    // Step 9: Verify no new notification for below-threshold event
    await page.goto('/notifications');
    const notificationCount = await page.locator('[data-testid="notification-item"]').count();
    const hasEmp002Notification = await page.locator('[data-testid="notification-item"]', { hasText: 'EMP002' }).count();
    expect(hasEmp002Notification).toBe(0);
  });

  test('Verify validation of invalid threshold inputs (error-case)', async ({ page }) => {
    // Step 1: Navigate to attendance anomaly notification settings page
    await page.goto('/settings/attendance-thresholds');
    await expect(page.locator('[data-testid="threshold-settings-page"]')).toBeVisible();

    // Step 2: Enter negative number in late arrival threshold
    await page.fill('[data-testid="late-arrival-threshold"]', '-5');

    // Step 3: Click Save button
    await page.click('[data-testid="save-thresholds-button"]');

    // Step 4: Verify validation error is displayed
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('negative');

    // Step 5: Enter non-numeric value in absence threshold
    await page.fill('[data-testid="late-arrival-threshold"]', '15');
    await page.fill('[data-testid="absence-threshold"]', 'abc');
    await page.click('[data-testid="save-thresholds-button"]');
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('numeric');

    // Step 6: Enter extremely large number
    await page.fill('[data-testid="absence-threshold"]', '2');
    await page.fill('[data-testid="late-arrival-threshold"]', '99999');
    await page.click('[data-testid="save-thresholds-button"]');
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('exceeds');

    // Step 7: Leave required field empty
    await page.fill('[data-testid="late-arrival-threshold"]', '');
    await page.click('[data-testid="save-thresholds-button"]');
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('required');

    // Step 8: Correct all invalid inputs with valid values
    await page.fill('[data-testid="late-arrival-threshold"]', '20');
    await page.fill('[data-testid="absence-threshold"]', '3');
    await page.fill('[data-testid="early-departure-threshold"]', '15');

    // Step 9: Click Save button
    await page.click('[data-testid="save-thresholds-button"]');

    // Step 10: Verify changes accepted and applied
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Changes accepted and applied');
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
  });

  test('Ensure reset to default thresholds works (happy-path)', async ({ page }) => {
    // Step 1: Navigate to attendance anomaly notification settings page
    await page.goto('/settings/attendance-thresholds');
    await expect(page.locator('[data-testid="threshold-settings-page"]')).toBeVisible();

    // Step 2: Set custom threshold values first
    await page.fill('[data-testid="late-arrival-threshold"]', '25');
    await page.fill('[data-testid="absence-threshold"]', '5');
    await page.fill('[data-testid="early-departure-threshold"]', '20');
    await page.click('[data-testid="save-thresholds-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();

    // Step 3: Note current custom threshold values
    const customLateArrival = await page.locator('[data-testid="late-arrival-threshold"]').inputValue();
    const customAbsence = await page.locator('[data-testid="absence-threshold"]').inputValue();
    const customEarlyDeparture = await page.locator('[data-testid="early-departure-threshold"]').inputValue();
    expect(customLateArrival).toBe('25');
    expect(customAbsence).toBe('5');
    expect(customEarlyDeparture).toBe('20');

    // Step 4: Locate and click Reset to Default button
    await page.click('[data-testid="reset-to-default-button"]');

    // Step 5: Click Confirm in confirmation dialog
    await page.click('[data-testid="confirm-reset-button"]');

    // Step 6: Verify threshold fields display default values
    await expect(page.locator('[data-testid="late-arrival-threshold"]')).toHaveValue('10');
    await expect(page.locator('[data-testid="absence-threshold"]')).toHaveValue('1');
    await expect(page.locator('[data-testid="early-departure-threshold"]')).toHaveValue('5');

    // Step 7: Click Save button to persist default values
    await page.click('[data-testid="save-thresholds-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Defaults applied and logged');

    // Step 8: Navigate to audit log
    await page.goto('/audit-log');
    await expect(page.locator('[data-testid="audit-log-page"]')).toBeVisible();

    // Step 9: Verify reset action is logged
    const latestLogEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(latestLogEntry).toBeVisible();
    await expect(latestLogEntry).toContainText('Reset to default');
    await expect(latestLogEntry).toContainText('supervisor@example.com');

    // Step 10: Trigger test attendance anomaly with default threshold
    await page.goto('/attendance/test-scenario');
    await page.fill('[data-testid="employee-id"]', 'EMP003');
    await page.fill('[data-testid="late-minutes"]', '11');
    await page.click('[data-testid="trigger-event-button"]');

    // Step 11: Verify notification generated with default threshold
    await page.goto('/notifications');
    await expect(page.locator('[data-testid="notification-item"]', { hasText: 'EMP003' })).toBeVisible();
    await expect(page.locator('[data-testid="notification-item"]', { hasText: 'EMP003' })).toContainText('11 minutes');
  });
});