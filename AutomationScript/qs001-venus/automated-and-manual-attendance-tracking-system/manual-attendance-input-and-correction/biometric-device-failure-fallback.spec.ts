import { test, expect } from '@playwright/test';

test.describe('Biometric Device Failure Fallback - Story 26', () => {
  test.beforeEach(async ({ page }) => {
    // Login as Attendance Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'attendance.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard"]')).toBeVisible();
  });

  test('Validate detection and notification of biometric device failure', async ({ page }) => {
    // Navigate to device management or monitoring page
    await page.goto('/attendance/device-management');
    await expect(page.locator('[data-testid="device-status-panel"]')).toBeVisible();

    // Step 1: Simulate biometric device failure
    await page.click('[data-testid="simulate-device-failure-button"]');
    
    // Expected Result: System detects failure within 1 minute
    await expect(page.locator('[data-testid="device-status-indicator"]')).toHaveText('Offline', { timeout: 60000 });
    await expect(page.locator('[data-testid="device-failure-alert"]')).toBeVisible({ timeout: 60000 });
    await expect(page.locator('[data-testid="device-failure-alert"]')).toContainText('Biometric device failure detected');

    // Step 2: System sends notification to attendance manager
    await page.click('[data-testid="notifications-icon"]');
    await expect(page.locator('[data-testid="notification-panel"]')).toBeVisible();
    
    // Expected Result: Manager receives alert promptly
    const notification = page.locator('[data-testid="notification-item"]').first();
    await expect(notification).toBeVisible();
    await expect(notification).toContainText('Biometric device failure');
    await expect(notification).toContainText('Switch to manual input');

    // Step 3: Manager switches to manual input mode
    await page.goto('/attendance/input');
    await expect(page.locator('[data-testid="manual-input-mode-option"]')).toBeVisible();
    await page.click('[data-testid="manual-input-mode-option"]');
    
    // Expected Result: Manual attendance input enabled
    await expect(page.locator('[data-testid="manual-input-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="manual-input-enabled-indicator"]')).toHaveText('Manual Input Mode Active');
  });

  test('Verify logging of fallback events', async ({ page }) => {
    // Setup: Enable manual input mode first
    await page.goto('/attendance/device-management');
    await page.click('[data-testid="simulate-device-failure-button"]');
    await page.waitForSelector('[data-testid="device-status-indicator"][text="Offline"]', { timeout: 60000 });
    await page.goto('/attendance/input');
    await page.click('[data-testid="manual-input-mode-option"]');
    await expect(page.locator('[data-testid="manual-input-form"]')).toBeVisible();

    // Step 1: Manager inputs attendance manually during fallback
    await page.fill('[data-testid="employee-id-input"]', 'EMP12345');
    await page.fill('[data-testid="attendance-date-input"]', '2024-01-15');
    await page.fill('[data-testid="check-in-time-input"]', '09:00');
    await page.fill('[data-testid="check-out-time-input"]', '17:30');
    await page.click('[data-testid="submit-manual-attendance-button"]');
    
    // Expected Result: Attendance record saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Attendance record saved successfully');

    // Step 2: System logs fallback event with timestamp and user details
    await page.goto('/attendance/audit-log');
    await expect(page.locator('[data-testid="audit-log-table"]')).toBeVisible();
    
    // Filter for fallback events
    await page.click('[data-testid="filter-dropdown"]');
    await page.click('[data-testid="filter-fallback-events"]');
    await page.click('[data-testid="apply-filter-button"]');
    
    // Expected Result: Audit log entry created
    const auditLogEntry = page.locator('[data-testid="audit-log-row"]').first();
    await expect(auditLogEntry).toBeVisible();
    await expect(auditLogEntry.locator('[data-testid="event-type"]')).toContainText('Fallback');
    await expect(auditLogEntry.locator('[data-testid="employee-id"]')).toContainText('EMP12345');
    await expect(auditLogEntry.locator('[data-testid="timestamp"]')).not.toBeEmpty();
    await expect(auditLogEntry.locator('[data-testid="user-details"]')).toContainText('attendance.manager@company.com');
  });

  test('Ensure system resumes biometric capture after device restoration', async ({ page }) => {
    // Setup: Simulate device failure and enable manual mode
    await page.goto('/attendance/device-management');
    await page.click('[data-testid="simulate-device-failure-button"]');
    await expect(page.locator('[data-testid="device-status-indicator"]')).toHaveText('Offline', { timeout: 60000 });
    await page.goto('/attendance/input');
    await page.click('[data-testid="manual-input-mode-option"]');
    await expect(page.locator('[data-testid="manual-input-form"]')).toBeVisible();

    // Step 1: Simulate biometric device restoration
    await page.goto('/attendance/device-management');
    await page.click('[data-testid="simulate-device-restoration-button"]');
    
    // Expected Result: System detects device is online
    await expect(page.locator('[data-testid="device-status-indicator"]')).toHaveText('Online', { timeout: 60000 });
    await expect(page.locator('[data-testid="device-restored-notification"]')).toBeVisible();
    await expect(page.locator('[data-testid="device-restored-notification"]')).toContainText('Biometric device restored');

    // Step 2: System disables manual input mode
    await page.goto('/attendance/input');
    
    // Expected Result: Biometric attendance capture resumes automatically
    await expect(page.locator('[data-testid="manual-input-form"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="biometric-capture-interface"]')).toBeVisible();
    await expect(page.locator('[data-testid="biometric-mode-indicator"]')).toHaveText('Biometric Mode Active');

    // Navigate to the attendance capture interface
    await page.goto('/attendance/capture');
    await expect(page.locator('[data-testid="biometric-scanner-status"]')).toHaveText('Ready');

    // Simulate a biometric attendance capture
    await page.click('[data-testid="simulate-biometric-scan-button"]');
    await page.fill('[data-testid="test-employee-id"]', 'EMP67890');
    await page.click('[data-testid="confirm-scan-button"]');
    
    await expect(page.locator('[data-testid="scan-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="scan-success-message"]')).toContainText('Biometric attendance captured successfully');

    // Check the audit log for device restoration event
    await page.goto('/attendance/audit-log');
    await page.click('[data-testid="filter-dropdown"]');
    await page.click('[data-testid="filter-device-events"]');
    await page.click('[data-testid="apply-filter-button"]');
    
    const restorationLogEntry = page.locator('[data-testid="audit-log-row"]').filter({ hasText: 'Device Restoration' }).first();
    await expect(restorationLogEntry).toBeVisible();
    await expect(restorationLogEntry.locator('[data-testid="event-type"]')).toContainText('Device Restoration');
    await expect(restorationLogEntry.locator('[data-testid="timestamp"]')).not.toBeEmpty();
  });
});