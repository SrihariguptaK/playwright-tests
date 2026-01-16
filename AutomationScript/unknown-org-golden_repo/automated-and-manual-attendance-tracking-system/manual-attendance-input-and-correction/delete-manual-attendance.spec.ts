import { test, expect } from '@playwright/test';

test.describe('Delete Manual Attendance Records', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const HR_OFFICER_EMAIL = 'hr.officer@company.com';
  const HR_OFFICER_PASSWORD = 'HRPassword123!';
  const UNAUTHORIZED_USER_EMAIL = 'regular.employee@company.com';
  const UNAUTHORIZED_USER_PASSWORD = 'EmployeePass123!';

  test('Delete manual attendance record with confirmation', async ({ page }) => {
    // Step 1: Login as authorized HR officer
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', HR_OFFICER_EMAIL);
    await page.fill('[data-testid="password-input"]', HR_OFFICER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Access granted to manual attendance records
    await expect(page).toHaveURL(/.*dashboard/);
    await page.waitForSelector('[data-testid="navigation-menu"]');
    
    // Navigate to manual attendance records
    await page.click('[data-testid="attendance-menu"]');
    await page.click('[data-testid="manual-attendance-link"]');
    await expect(page).toHaveURL(/.*attendance\/manual/);
    await expect(page.locator('[data-testid="manual-attendance-table"]')).toBeVisible();
    
    // Step 2: Select a manual attendance record and initiate delete
    const firstRecord = page.locator('[data-testid="attendance-record-row"]').first();
    await expect(firstRecord).toBeVisible();
    
    // Store record details for verification
    const recordId = await firstRecord.getAttribute('data-record-id');
    
    await firstRecord.locator('[data-testid="delete-button"]').click();
    
    // Expected Result: Confirmation prompt is displayed
    const confirmDialog = page.locator('[data-testid="delete-confirmation-dialog"]');
    await expect(confirmDialog).toBeVisible();
    await expect(confirmDialog.locator('[data-testid="dialog-title"]')).toContainText('Confirm Deletion');
    await expect(confirmDialog.locator('[data-testid="dialog-message"]')).toContainText('Are you sure you want to delete this manual attendance record?');
    await expect(confirmDialog.locator('[data-testid="warning-text"]')).toContainText('This action cannot be undone');
    
    // Step 3: Confirm deletion
    await confirmDialog.locator('[data-testid="confirm-delete-button"]').click();
    
    // Expected Result: Record is deleted and confirmation message shown
    const successMessage = page.locator('[data-testid="success-message"]');
    await expect(successMessage).toBeVisible();
    await expect(successMessage).toContainText('Manual attendance record deleted successfully');
    
    // Verify record is removed from the table
    await page.waitForTimeout(1000); // Wait for table refresh
    const deletedRecord = page.locator(`[data-testid="attendance-record-row"][data-record-id="${recordId}"]`);
    await expect(deletedRecord).not.toBeVisible();
    
    // Verify audit log entry (navigate to audit log)
    await page.click('[data-testid="audit-log-link"]');
    await expect(page).toHaveURL(/.*audit-log/);
    
    const latestAuditEntry = page.locator('[data-testid="audit-entry-row"]').first();
    await expect(latestAuditEntry.locator('[data-testid="action-type"]')).toContainText('DELETE');
    await expect(latestAuditEntry.locator('[data-testid="resource-type"]')).toContainText('Manual Attendance');
    await expect(latestAuditEntry.locator('[data-testid="user-name"]')).toContainText('HR Officer');
    await expect(latestAuditEntry.locator('[data-testid="timestamp"]')).toBeVisible();
  });

  test('Prevent unauthorized deletion attempts', async ({ page, request }) => {
    // Step 1: Login as unauthorized user
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', UNAUTHORIZED_USER_EMAIL);
    await page.fill('[data-testid="password-input"]', UNAUTHORIZED_USER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Access to delete functionality is denied
    await expect(page).toHaveURL(/.*dashboard/);
    
    // Try to navigate to manual attendance records
    await page.click('[data-testid="attendance-menu"]');
    
    // Check if manual attendance link is not available or restricted
    const manualAttendanceLink = page.locator('[data-testid="manual-attendance-link"]');
    const isLinkVisible = await manualAttendanceLink.isVisible().catch(() => false);
    
    if (isLinkVisible) {
      await manualAttendanceLink.click();
      
      // Should show access denied message or redirect
      const accessDeniedMessage = page.locator('[data-testid="access-denied-message"]');
      const isAccessDenied = await accessDeniedMessage.isVisible().catch(() => false);
      
      if (isAccessDenied) {
        await expect(accessDeniedMessage).toContainText('You do not have permission to access this page');
      } else {
        // If page loads, delete button should not be visible
        const deleteButtons = page.locator('[data-testid="delete-button"]');
        await expect(deleteButtons.first()).not.toBeVisible();
      }
    }
    
    // Step 2: Attempt to delete manual attendance record via API
    const testRecordId = '12345'; // Sample record ID
    
    // Get auth token from cookies or local storage
    const cookies = await page.context().cookies();
    const authToken = cookies.find(c => c.name === 'auth_token')?.value || '';
    
    // Expected Result: Request is rejected with authorization error
    const response = await request.delete(`${BASE_URL}/api/attendance/manual/${testRecordId}`, {
      headers: {
        'Authorization': `Bearer ${authToken}`,
        'Content-Type': 'application/json'
      }
    });
    
    // Verify unauthorized response
    expect(response.status()).toBe(403);
    
    const responseBody = await response.json();
    expect(responseBody.error).toBeTruthy();
    expect(responseBody.message).toMatch(/unauthorized|forbidden|permission denied/i);
    
    // Verify audit log shows failed attempt
    await page.goto(`${BASE_URL}/logout`);
    
    // Login as HR officer to check audit log
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', HR_OFFICER_EMAIL);
    await page.fill('[data-testid="password-input"]', HR_OFFICER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    await page.click('[data-testid="audit-log-link"]');
    await expect(page).toHaveURL(/.*audit-log/);
    
    // Filter for failed deletion attempts
    await page.fill('[data-testid="audit-search-input"]', 'DELETE');
    await page.selectOption('[data-testid="status-filter"]', 'FAILED');
    
    const failedAttempt = page.locator('[data-testid="audit-entry-row"]').filter({ hasText: 'FAILED' }).first();
    await expect(failedAttempt.locator('[data-testid="action-type"]')).toContainText('DELETE');
    await expect(failedAttempt.locator('[data-testid="status"]')).toContainText('FAILED');
    await expect(failedAttempt.locator('[data-testid="reason"]')).toContainText('Unauthorized');
  });

  test.afterEach(async ({ page }) => {
    // Cleanup: Logout after each test
    await page.goto(`${BASE_URL}/logout`);
  });
});