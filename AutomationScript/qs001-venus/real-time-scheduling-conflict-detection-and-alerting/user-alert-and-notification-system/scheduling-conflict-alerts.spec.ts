import { test, expect } from '@playwright/test';

test.describe('Real-time Pop-up Alerts for Scheduling Conflicts', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the scheduling interface before each test
    await page.goto('/scheduling');
    // Wait for the page to be fully loaded
    await page.waitForLoadState('networkidle');
  });

  test('Verify pop-up alert displays on conflict detection', async ({ page }) => {
    // Step 1: Enter scheduling data causing conflict
    await page.fill('[data-testid="resource-input"]', 'Conference Room A');
    await page.fill('[data-testid="date-input"]', '2024-03-15');
    await page.fill('[data-testid="start-time-input"]', '10:00');
    await page.fill('[data-testid="end-time-input"]', '11:00');
    
    // Trigger conflict detection by moving focus or clicking submit
    await page.click('[data-testid="check-availability-button"]');
    
    // Expected Result: Pop-up alert appears within 1 second
    const popupAlert = page.locator('[data-testid="conflict-alert-popup"]');
    await expect(popupAlert).toBeVisible({ timeout: 1000 });
    
    // Step 2: Read alert details
    const alertTitle = page.locator('[data-testid="alert-title"]');
    const alertDetails = page.locator('[data-testid="alert-details"]');
    const conflictingResource = page.locator('[data-testid="conflicting-resource"]');
    const conflictingTime = page.locator('[data-testid="conflicting-time"]');
    
    // Expected Result: Alert shows accurate conflict information
    await expect(alertTitle).toContainText('Scheduling Conflict Detected');
    await expect(alertDetails).toBeVisible();
    await expect(conflictingResource).toContainText('Conference Room A');
    await expect(conflictingTime).toContainText('10:00');
    
    // Step 3: Acknowledge alert
    await page.click('[data-testid="acknowledge-alert-button"]');
    
    // Expected Result: Alert is dismissed and acknowledgment recorded
    await expect(popupAlert).not.toBeVisible();
    
    // Verify acknowledgment was recorded by checking system logs or audit trail
    await page.goto('/audit-trail');
    const auditLog = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(auditLog).toContainText('Conflict alert acknowledged');
    await expect(auditLog).toContainText('Conference Room A');
  });

  test('Test alert preference configuration - disable and enable pop-up alerts', async ({ page }) => {
    // Step 1: Navigate to user settings or preferences page
    await page.goto('/user-settings');
    await page.waitForLoadState('networkidle');
    
    // Step 2: Locate the pop-up alert configuration option
    const alertPreferenceToggle = page.locator('[data-testid="popup-alerts-toggle"]');
    await expect(alertPreferenceToggle).toBeVisible();
    
    // Step 3: Disable pop-up alerts by toggling off or unchecking the option
    const isEnabled = await alertPreferenceToggle.isChecked();
    if (isEnabled) {
      await alertPreferenceToggle.click();
    }
    
    // Step 4: Save the preference changes
    await page.click('[data-testid="save-preferences-button"]');
    
    // Wait for save confirmation
    const saveConfirmation = page.locator('[data-testid="save-confirmation"]');
    await expect(saveConfirmation).toBeVisible();
    await expect(saveConfirmation).toContainText('Preferences saved successfully');
    
    // Step 5: Navigate to scheduling interface and enter scheduling data causing a conflict
    await page.goto('/scheduling');
    await page.waitForLoadState('networkidle');
    
    await page.fill('[data-testid="resource-input"]', 'Conference Room B');
    await page.fill('[data-testid="date-input"]', '2024-03-16');
    await page.fill('[data-testid="start-time-input"]', '14:00');
    await page.fill('[data-testid="end-time-input"]', '15:00');
    await page.click('[data-testid="check-availability-button"]');
    
    // Expected Result: Pop-up alerts are not shown on conflicts
    const popupAlert = page.locator('[data-testid="conflict-alert-popup"]');
    await expect(popupAlert).not.toBeVisible({ timeout: 2000 });
    
    // Step 6: Return to user settings and enable pop-up alerts
    await page.goto('/user-settings');
    await page.waitForLoadState('networkidle');
    
    const alertToggle = page.locator('[data-testid="popup-alerts-toggle"]');
    const isDisabled = await alertToggle.isChecked();
    if (!isDisabled) {
      await alertToggle.click();
    }
    
    // Step 7: Save the preference changes
    await page.click('[data-testid="save-preferences-button"]');
    await expect(saveConfirmation).toBeVisible();
    
    // Step 8: Navigate to scheduling interface and enter scheduling data causing a conflict
    await page.goto('/scheduling');
    await page.waitForLoadState('networkidle');
    
    await page.fill('[data-testid="resource-input"]', 'Conference Room C');
    await page.fill('[data-testid="date-input"]', '2024-03-17');
    await page.fill('[data-testid="start-time-input"]', '09:00');
    await page.fill('[data-testid="end-time-input"]', '10:00');
    await page.click('[data-testid="check-availability-button"]');
    
    // Expected Result: Pop-up alerts resume displaying on conflicts
    const enabledPopupAlert = page.locator('[data-testid="conflict-alert-popup"]');
    await expect(enabledPopupAlert).toBeVisible({ timeout: 1000 });
    
    // Verify alert contains conflict information
    const alertTitle = page.locator('[data-testid="alert-title"]');
    await expect(alertTitle).toContainText('Scheduling Conflict Detected');
  });
});