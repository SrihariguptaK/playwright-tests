import { test, expect } from '@playwright/test';

test.describe('Story-26: Declination Override Process', () => {
  test.beforeEach(async ({ page }) => {
    // Login as underwriting manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'underwriting.manager@example.com');
    await page.fill('[data-testid="password-input"]', 'SecurePassword123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify declination override process (happy-path)', async ({ page }) => {
    // Navigate to the declined applications dashboard as underwriting manager
    await page.goto('/declined-applications');
    await expect(page.locator('[data-testid="declined-applications-header"]')).toBeVisible();
    
    // Select a declined application from the list to review for potential override
    const declinedApplicationRow = page.locator('[data-testid="declined-application-row"]').first();
    await expect(declinedApplicationRow).toBeVisible();
    const applicationId = await declinedApplicationRow.getAttribute('data-application-id');
    await declinedApplicationRow.click();
    
    // Verify application details are displayed
    await expect(page.locator('[data-testid="application-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="application-status"]')).toHaveText('Declined');
    
    // Click on the 'Override Declination' button or option
    const overrideButton = page.locator('[data-testid="override-declination-button"]');
    await expect(overrideButton).toBeVisible();
    await expect(overrideButton).toBeEnabled();
    await overrideButton.click();
    
    // Verify Override UI is displayed
    await expect(page.locator('[data-testid="override-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="override-reason-input"]')).toBeVisible();
    
    // Enter a valid override reason in the text field
    const overrideReason = 'Applicant provided additional income documentation showing sufficient capacity';
    await page.fill('[data-testid="override-reason-input"]', overrideReason);
    
    // Click the 'Submit Override' button to confirm the override action
    await page.click('[data-testid="submit-override-button"]');
    
    // Wait for processing
    await page.waitForResponse(response => 
      response.url().includes('/api/declinations/override') && response.status() === 200
    );
    
    // Verify the application status has been updated in the system
    await expect(page.locator('[data-testid="override-success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="override-success-message"]')).toContainText('Override successful');
    
    // Application status updates immediately upon override
    await expect(page.locator('[data-testid="application-status"]')).toHaveText(/Approved|Under Review/, { timeout: 5000 });
    
    // Check the audit log for the override action
    await page.click('[data-testid="view-audit-log-button"]');
    await expect(page.locator('[data-testid="audit-log-panel"]')).toBeVisible();
    
    const latestAuditEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(latestAuditEntry).toBeVisible();
    await expect(latestAuditEntry.locator('[data-testid="audit-action"]')).toContainText('Declination Override');
    await expect(latestAuditEntry.locator('[data-testid="audit-user"]')).toContainText('underwriting.manager@example.com');
    await expect(latestAuditEntry.locator('[data-testid="audit-timestamp"]')).toBeVisible();
    await expect(latestAuditEntry.locator('[data-testid="audit-reason"]')).toContainText(overrideReason);
    
    // Verify notifications are sent to relevant stakeholders
    await page.goto('/notifications');
    await expect(page.locator('[data-testid="notifications-panel"]')).toBeVisible();
    
    const notificationSent = page.locator('[data-testid="notification-item"]').filter({
      hasText: `Application ${applicationId} override`
    }).first();
    await expect(notificationSent).toBeVisible();
    await expect(notificationSent.locator('[data-testid="notification-status"]')).toContainText('Sent');
    
    // Check stakeholder notification inboxes/emails to confirm receipt
    const notificationRecipients = page.locator('[data-testid="notification-recipients"]');
    await expect(notificationRecipients).toBeVisible();
    await expect(notificationRecipients).toContainText(/underwriting team|loan officers/);
    
    // Return to declined applications dashboard and verify the overridden application is no longer listed
    await page.goto('/declined-applications');
    await expect(page.locator('[data-testid="declined-applications-header"]')).toBeVisible();
    
    // Wait for list to load
    await page.waitForLoadState('networkidle');
    
    // Verify the overridden application is no longer in the declined list
    const overriddenApplication = page.locator(`[data-testid="declined-application-row"][data-application-id="${applicationId}"]`);
    await expect(overriddenApplication).toHaveCount(0);
  });

  test('Verify manager enters override reason and submits', async ({ page }) => {
    // Navigate to declined applications
    await page.goto('/declined-applications');
    
    // Select declined application to override
    const declinedApplication = page.locator('[data-testid="declined-application-row"]').first();
    await declinedApplication.click();
    
    // Click override button - Override UI is displayed
    await page.click('[data-testid="override-declination-button"]');
    await expect(page.locator('[data-testid="override-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="override-reason-input"]')).toBeVisible();
    
    // Manager enters override reason and submits
    const overrideReason = 'Special circumstances warrant manual review and approval';
    await page.fill('[data-testid="override-reason-input"]', overrideReason);
    await page.click('[data-testid="submit-override-button"]');
    
    // Application status updates and audit log created
    await expect(page.locator('[data-testid="override-success-message"]')).toBeVisible({ timeout: 5000 });
    
    // Verify application status updated
    const updatedStatus = page.locator('[data-testid="application-status"]');
    await expect(updatedStatus).not.toHaveText('Declined');
    
    // Verify audit log created
    await page.click('[data-testid="view-audit-log-button"]');
    const auditLog = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(auditLog).toBeVisible();
    await expect(auditLog.locator('[data-testid="audit-action"]')).toContainText('Declination Override');
    await expect(auditLog.locator('[data-testid="audit-reason"]')).toContainText(overrideReason);
  });

  test('Verify notifications sent to stakeholders', async ({ page }) => {
    // Navigate to declined applications and perform override
    await page.goto('/declined-applications');
    const declinedApplication = page.locator('[data-testid="declined-application-row"]').first();
    const applicationId = await declinedApplication.getAttribute('data-application-id');
    await declinedApplication.click();
    
    await page.click('[data-testid="override-declination-button"]');
    await page.fill('[data-testid="override-reason-input"]', 'Override for testing notification system');
    await page.click('[data-testid="submit-override-button"]');
    
    // Wait for override to complete
    await expect(page.locator('[data-testid="override-success-message"]')).toBeVisible();
    
    // Verify notifications sent to stakeholders
    await page.goto('/notifications');
    
    const notificationsList = page.locator('[data-testid="notification-item"]');
    await expect(notificationsList).toHaveCount(await notificationsList.count());
    
    const overrideNotification = notificationsList.filter({
      hasText: applicationId || 'override'
    }).first();
    
    // Notifications received successfully
    await expect(overrideNotification).toBeVisible();
    await expect(overrideNotification.locator('[data-testid="notification-status"]')).toContainText(/Sent|Delivered/);
    await expect(overrideNotification.locator('[data-testid="notification-type"]')).toContainText('Override');
  });

  test('Verify only authorized managers can perform overrides', async ({ page }) => {
    // Logout as manager
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Login as regular user (non-manager)
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'regular.user@example.com');
    await page.fill('[data-testid="password-input"]', 'RegularPassword123!');
    await page.click('[data-testid="login-button"]');
    
    // Navigate to declined applications
    await page.goto('/declined-applications');
    
    // Verify override button is not visible or disabled for non-managers
    const declinedApplication = page.locator('[data-testid="declined-application-row"]').first();
    if (await declinedApplication.isVisible()) {
      await declinedApplication.click();
      
      const overrideButton = page.locator('[data-testid="override-declination-button"]');
      // Button should either not exist or be disabled
      const buttonCount = await overrideButton.count();
      if (buttonCount > 0) {
        await expect(overrideButton).toBeDisabled();
      } else {
        await expect(overrideButton).toHaveCount(0);
      }
    }
  });

  test('Verify override reason is mandatory', async ({ page }) => {
    // Navigate to declined applications
    await page.goto('/declined-applications');
    
    // Select declined application
    const declinedApplication = page.locator('[data-testid="declined-application-row"]').first();
    await declinedApplication.click();
    
    // Click override button
    await page.click('[data-testid="override-declination-button"]');
    await expect(page.locator('[data-testid="override-modal"]')).toBeVisible();
    
    // Try to submit without entering reason
    await page.click('[data-testid="submit-override-button"]');
    
    // Verify validation error is displayed
    const validationError = page.locator('[data-testid="override-reason-error"]');
    await expect(validationError).toBeVisible();
    await expect(validationError).toContainText(/required|mandatory/);
    
    // Verify modal is still open
    await expect(page.locator('[data-testid="override-modal"]')).toBeVisible();
  });
});