import { test, expect } from '@playwright/test';

test.describe('Schedule Change Request Escalation', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to approval dashboard before each test
    await page.goto('/approval-dashboard');
    await expect(page).toHaveURL(/.*approval-dashboard/);
  });

  test('Escalate a schedule change request successfully', async ({ page }) => {
    // Step 1: Approver selects a schedule change request
    await page.click('[data-testid="schedule-change-request-item"]');
    
    // Expected Result: Request details are displayed
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="request-id"]')).toBeVisible();
    
    // Step 2: Click 'Escalate' and enter comments
    await page.click('[data-testid="escalate-button"]');
    
    // Expected Result: Escalation input accepted
    await expect(page.locator('[data-testid="escalation-modal"]')).toBeVisible();
    await expect(page.locator('[data-testid="escalation-comments-field"]')).toBeVisible();
    
    await page.fill('[data-testid="escalation-comments-field"]', 'Requires senior management approval due to budget implications');
    
    // Step 3: Submit escalation
    const startTime = Date.now();
    await page.click('[data-testid="submit-escalation-button"]');
    
    // Expected Result: Request status updated to 'Escalated'
    await expect(page.locator('[data-testid="request-status"]')).toHaveText('Escalated', { timeout: 5000 });
    
    // Verify escalation processing time is under 2 seconds
    const processingTime = Date.now() - startTime;
    expect(processingTime).toBeLessThan(2000);
    
    // Expected Result: Notification sent confirmation
    await expect(page.locator('[data-testid="notification-success-message"]')).toContainText('Higher-level approvers have been notified');
    
    // Expected Result: Escalation logged - verify audit log entry
    await page.click('[data-testid="view-audit-log-button"]');
    await expect(page.locator('[data-testid="audit-log-panel"]')).toBeVisible();
    
    const latestLogEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(latestLogEntry).toContainText('Escalated');
    await expect(latestLogEntry).toContainText('Requires senior management approval due to budget implications');
    await expect(latestLogEntry.locator('[data-testid="log-timestamp"]')).toBeVisible();
    await expect(latestLogEntry.locator('[data-testid="log-user"]')).toBeVisible();
  });

  test('Reject escalation with missing comments', async ({ page }) => {
    // Step 1: Select a schedule change request from the list
    await page.click('[data-testid="schedule-change-request-item"]');
    await expect(page.locator('[data-testid="request-details-panel"]')).toBeVisible();
    
    // Step 2: Click 'Escalate' without entering comments
    await page.click('[data-testid="escalate-button"]');
    await expect(page.locator('[data-testid="escalation-modal"]')).toBeVisible();
    
    // Leave comments field empty and attempt to submit
    await page.click('[data-testid="submit-escalation-button"]');
    
    // Expected Result: Validation error displayed requiring comments
    await expect(page.locator('[data-testid="escalation-comments-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="escalation-comments-error"]')).toContainText('Comments are required');
    
    // Expected Result: Submission blocked - modal still visible
    await expect(page.locator('[data-testid="escalation-modal"]')).toBeVisible();
    
    // Step 3: Attempt to submit escalation again without comments
    await page.click('[data-testid="submit-escalation-button"]');
    
    // Verify error persists
    await expect(page.locator('[data-testid="escalation-comments-error"]')).toBeVisible();
    
    // Expected Result: Request status has not changed
    await page.click('[data-testid="cancel-escalation-button"]');
    await expect(page.locator('[data-testid="request-status"]')).not.toHaveText('Escalated');
    
    // Step 4: Enter valid comments and submit successfully
    await page.click('[data-testid="escalate-button"]');
    await page.fill('[data-testid="escalation-comments-field"]', 'Escalating for policy review');
    await page.click('[data-testid="submit-escalation-button"]');
    
    // Expected Result: Escalation succeeds with valid comments
    await expect(page.locator('[data-testid="request-status"]')).toHaveText('Escalated', { timeout: 5000 });
    await expect(page.locator('[data-testid="notification-success-message"]')).toBeVisible();
  });
});