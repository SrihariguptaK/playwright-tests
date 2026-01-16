import { test, expect } from '@playwright/test';

test.describe('Override Scheduling Conflicts', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application
    await page.goto('/dashboard');
  });

  test('Authorized user overrides conflict successfully', async ({ page }) => {
    // Login as authorized user
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'authorized_scheduler');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the conflict alert dashboard and locate a conflict
    await page.click('[data-testid="conflict-alerts-menu"]');
    await expect(page.locator('[data-testid="conflict-alert-dashboard"]')).toBeVisible();
    
    // Locate a conflict that requires override
    const conflictAlert = page.locator('[data-testid="conflict-alert-item"]').first();
    await expect(conflictAlert).toBeVisible();
    const conflictId = await conflictAlert.getAttribute('data-conflict-id');

    // Click on the 'Override' option on the conflict alert
    await conflictAlert.locator('[data-testid="override-button"]').click();
    
    // Wait for system to complete permission validation
    await page.waitForResponse(response => 
      response.url().includes('/api/permissions/validate') && response.status() === 200
    );

    // System prompts for confirmation
    const confirmationDialog = page.locator('[data-testid="override-confirmation-dialog"]');
    await expect(confirmationDialog).toBeVisible();
    
    // Review the confirmation dialog details
    await expect(confirmationDialog.locator('[data-testid="conflict-information"]')).toBeVisible();
    await expect(confirmationDialog.locator('[data-testid="override-implications"]')).toBeVisible();

    // Click the 'Confirm' button in the override confirmation dialog
    await confirmationDialog.locator('[data-testid="confirm-override-button"]').click();
    
    // Wait for override operation to complete
    await page.waitForResponse(response => 
      response.url().includes(`/api/conflicts/${conflictId}/override`) && response.status() === 200,
      { timeout: 2000 }
    );

    // Conflict is overridden and logged
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Conflict overridden successfully');

    // Verify the conflict status has been updated in the conflict alert dashboard
    const updatedConflict = page.locator(`[data-conflict-id="${conflictId}"]`);
    await expect(updatedConflict.locator('[data-testid="conflict-status"]')).toContainText('Overridden');

    // Navigate to the audit log section
    await page.click('[data-testid="audit-log-menu"]');
    await expect(page.locator('[data-testid="audit-log-section"]')).toBeVisible();

    // Search for the override action entry in the audit log
    await page.fill('[data-testid="audit-log-search"]', conflictId || '');
    await page.click('[data-testid="search-button"]');

    // Verify audit log entry
    const auditLogEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(auditLogEntry).toBeVisible();
    
    // Override action recorded with user details
    await expect(auditLogEntry.locator('[data-testid="action-type"]')).toContainText('Override');
    await expect(auditLogEntry.locator('[data-testid="user-details"]')).toContainText('authorized_scheduler');
    await expect(auditLogEntry.locator('[data-testid="timestamp"]')).toBeVisible();
    await expect(auditLogEntry.locator('[data-testid="conflict-id"]')).toContainText(conflictId || '');
  });

  test('Unauthorized user cannot override conflict', async ({ page }) => {
    // Login as unauthorized user
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'unauthorized_user');
    await page.fill('[data-testid="password-input"]', 'UserPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to the conflict alert dashboard as an unauthorized user
    await page.click('[data-testid="conflict-alerts-menu"]');
    await expect(page.locator('[data-testid="conflict-alert-dashboard"]')).toBeVisible();

    // Locate a conflict alert and check for available action options
    const conflictAlert = page.locator('[data-testid="conflict-alert-item"]').first();
    await expect(conflictAlert).toBeVisible();
    const conflictId = await conflictAlert.getAttribute('data-conflict-id');

    // Attempt to click on the 'Override' option if visible
    const overrideButton = conflictAlert.locator('[data-testid="override-button"]');
    
    // Check if override button is disabled or hidden for unauthorized users
    const isOverrideButtonVisible = await overrideButton.isVisible().catch(() => false);
    
    if (isOverrideButtonVisible) {
      // Attempt to access override functionality
      await overrideButton.click();
      
      // Wait for system to validate user permissions
      await page.waitForResponse(response => 
        response.url().includes('/api/permissions/validate') && (response.status() === 403 || response.status() === 401),
        { timeout: 2000 }
      );
    }

    // System denies override and displays error
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).toBeVisible();
    await expect(errorMessage).toContainText(/unauthorized|permission denied|access denied/i);

    // Verify that no confirmation dialog appears for the override action
    const confirmationDialog = page.locator('[data-testid="override-confirmation-dialog"]');
    await expect(confirmationDialog).not.toBeVisible();

    // Check the conflict status in the dashboard
    const conflictStatus = conflictAlert.locator('[data-testid="conflict-status"]');
    await expect(conflictStatus).not.toContainText('Overridden');

    // Verify no audit log entry is created for the failed override attempt
    await page.click('[data-testid="audit-log-menu"]');
    await expect(page.locator('[data-testid="audit-log-section"]')).toBeVisible();
    
    // Search for any override action for this conflict
    await page.fill('[data-testid="audit-log-search"]', conflictId || '');
    await page.click('[data-testid="search-button"]');
    
    // Verify no override entry exists or the most recent entry is not from unauthorized user
    const auditLogEntries = page.locator('[data-testid="audit-log-entry"]');
    const entryCount = await auditLogEntries.count();
    
    if (entryCount > 0) {
      const latestEntry = auditLogEntries.first();
      const actionType = await latestEntry.locator('[data-testid="action-type"]').textContent();
      
      // Ensure no override action was logged for unauthorized user
      if (actionType?.includes('Override')) {
        const userDetails = await latestEntry.locator('[data-testid="user-details"]').textContent();
        expect(userDetails).not.toContain('unauthorized_user');
      }
    }
  });
});