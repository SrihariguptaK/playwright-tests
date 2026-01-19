import { test, expect } from '@playwright/test';

test.describe('Attendance Record Correction with Audit Logging', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const attendanceOfficerCredentials = {
    username: 'attendance.officer@company.com',
    password: 'SecurePass123!'
  };

  test.beforeEach(async ({ page }) => {
    // Navigate to login page
    await page.goto(`${baseURL}/login`);
  });

  test('Validate attendance record correction with audit logging', async ({ page }) => {
    // Step 1: Login as authorized attendance officer
    await page.fill('[data-testid="username-input"]', attendanceOfficerCredentials.username);
    await page.fill('[data-testid="password-input"]', attendanceOfficerCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Access granted to attendance management page
    await expect(page).toHaveURL(/.*dashboard/);
    await expect(page.locator('[data-testid="attendance-management-link"]')).toBeVisible();

    // Navigate to attendance management page
    await page.click('[data-testid="attendance-management-link"]');
    await expect(page).toHaveURL(/.*attendance/);
    await expect(page.locator('h1, h2').filter({ hasText: /attendance management/i })).toBeVisible();

    // Search for specific attendance record
    await page.fill('[data-testid="employee-id-search"]', 'EMP001');
    await page.fill('[data-testid="date-filter"]', '2024-01-15');
    await page.click('[data-testid="search-button"]');
    await page.waitForLoadState('networkidle');

    // Step 2: Select attendance record and edit details
    const attendanceRecord = page.locator('[data-testid="attendance-record-row"]').first();
    await expect(attendanceRecord).toBeVisible();
    
    // Store original values for verification
    const originalTime = await attendanceRecord.locator('[data-testid="check-in-time"]').textContent();
    const originalStatus = await attendanceRecord.locator('[data-testid="attendance-status"]').textContent();
    
    await attendanceRecord.locator('[data-testid="edit-button"]').click();
    
    // Expected Result: Edit form displayed with current data
    await expect(page.locator('[data-testid="edit-attendance-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="current-check-in-time"]')).toHaveValue(/\d{2}:\d{2}/);
    await expect(page.locator('[data-testid="current-status"]')).not.toBeEmpty();

    // Modify attendance details
    await page.fill('[data-testid="check-in-time-input"]', '09:00');
    await page.selectOption('[data-testid="status-select"]', 'Present');
    await page.fill('[data-testid="correction-notes"]', 'Correcting time entry error - employee arrived at 09:00 AM');

    // Step 3: Submit corrected attendance record
    await page.click('[data-testid="submit-correction-button"]');
    
    // Expected Result: Changes saved and audit log updated
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/successfully updated|saved/i);
    
    // Verify corrected record shows updated values
    await page.waitForTimeout(1000); // Wait for UI to refresh
    const updatedRecord = page.locator('[data-testid="attendance-record-row"]').first();
    await expect(updatedRecord.locator('[data-testid="check-in-time"]')).toContainText('09:00');
    await expect(updatedRecord.locator('[data-testid="attendance-status"]')).toContainText('Present');

    // Navigate to audit log section
    await updatedRecord.locator('[data-testid="view-audit-history-button"]').click();
    await expect(page.locator('[data-testid="audit-history-modal"]')).toBeVisible();

    // Review latest audit log entry
    const latestAuditEntry = page.locator('[data-testid="audit-log-entry"]').first();
    await expect(latestAuditEntry).toBeVisible();
    await expect(latestAuditEntry.locator('[data-testid="audit-user"]')).toContainText(attendanceOfficerCredentials.username);
    await expect(latestAuditEntry.locator('[data-testid="audit-timestamp"]')).toContainText(/\d{4}-\d{2}-\d{2}/);
    await expect(latestAuditEntry.locator('[data-testid="audit-action"]')).toContainText(/correction|edit/i);
    await expect(latestAuditEntry.locator('[data-testid="audit-changes"]')).toContainText('09:00');
  });

  test('Verify audit history display for attendance records', async ({ page }) => {
    // Step 1: Login as authorized attendance officer
    await page.fill('[data-testid="username-input"]', attendanceOfficerCredentials.username);
    await page.fill('[data-testid="password-input"]', attendanceOfficerCredentials.password);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Navigate to attendance management page
    await page.click('[data-testid="attendance-management-link"]');
    await expect(page).toHaveURL(/.*attendance/);

    // Locate specific attendance record that has been previously modified
    await page.fill('[data-testid="employee-id-search"]', 'EMP001');
    await page.fill('[data-testid="date-filter"]', '2024-01-15');
    await page.click('[data-testid="search-button"]');
    await page.waitForLoadState('networkidle');

    const attendanceRecord = page.locator('[data-testid="attendance-record-row"]').first();
    await expect(attendanceRecord).toBeVisible();

    // Click View Audit History button
    await attendanceRecord.locator('[data-testid="view-audit-history-button"]').click();
    
    // Expected Result: Audit log shows all changes with user and timestamps
    await expect(page.locator('[data-testid="audit-history-modal"]')).toBeVisible();
    await expect(page.locator('h2, h3').filter({ hasText: /audit history/i })).toBeVisible();

    // Review audit log entries in chronological order
    const auditEntries = page.locator('[data-testid="audit-log-entry"]');
    await expect(auditEntries).toHaveCount(await auditEntries.count());
    const entryCount = await auditEntries.count();
    expect(entryCount).toBeGreaterThan(0);

    // Verify each audit log entry contains required information
    for (let i = 0; i < Math.min(entryCount, 5); i++) {
      const entry = auditEntries.nth(i);
      
      // Verify user information
      const userInfo = entry.locator('[data-testid="audit-user"]');
      await expect(userInfo).toBeVisible();
      const userText = await userInfo.textContent();
      expect(userText).toBeTruthy();
      expect(userText?.length).toBeGreaterThan(0);

      // Verify timestamp information
      const timestamp = entry.locator('[data-testid="audit-timestamp"]');
      await expect(timestamp).toBeVisible();
      const timestampText = await timestamp.textContent();
      expect(timestampText).toMatch(/\d{4}-\d{2}-\d{2}|\d{2}\/\d{2}\/\d{4}/);

      // Verify action type
      const actionType = entry.locator('[data-testid="audit-action"]');
      await expect(actionType).toBeVisible();
      const actionText = await actionType.textContent();
      expect(actionText).toMatch(/create|edit|delete|correction/i);

      // Verify changed fields with original and new values
      const changesSection = entry.locator('[data-testid="audit-changes"]');
      if (await changesSection.isVisible()) {
        const changesText = await changesSection.textContent();
        expect(changesText).toBeTruthy();
      }
    }

    // Verify comments/reasons are displayed if available
    const firstEntry = auditEntries.first();
    const commentsField = firstEntry.locator('[data-testid="audit-comments"]');
    if (await commentsField.isVisible()) {
      const commentsText = await commentsField.textContent();
      expect(commentsText).toBeTruthy();
    }

    // Verify all historical changes are displayed completely
    const auditHistoryContainer = page.locator('[data-testid="audit-history-list"]');
    await expect(auditHistoryContainer).toBeVisible();
    
    // Verify chronological order (most recent first)
    if (entryCount > 1) {
      const firstTimestamp = await auditEntries.first().locator('[data-testid="audit-timestamp"]').getAttribute('data-timestamp');
      const secondTimestamp = await auditEntries.nth(1).locator('[data-testid="audit-timestamp"]').getAttribute('data-timestamp');
      
      if (firstTimestamp && secondTimestamp) {
        expect(new Date(firstTimestamp).getTime()).toBeGreaterThanOrEqual(new Date(secondTimestamp).getTime());
      }
    }
  });
});