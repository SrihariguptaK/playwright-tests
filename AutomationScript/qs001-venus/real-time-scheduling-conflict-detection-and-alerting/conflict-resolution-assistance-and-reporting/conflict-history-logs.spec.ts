import { test, expect } from '@playwright/test';

test.describe('Story-15: View Conflict History Logs', () => {
  const adminCredentials = {
    username: 'admin@example.com',
    password: 'AdminPass123!'
  };

  const nonAdminCredentials = {
    username: 'user@example.com',
    password: 'UserPass123!'
  };

  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const apiBaseURL = process.env.API_BASE_URL || 'http://localhost:3000/api';

  test('Verify all conflicts are logged with complete details (happy-path)', async ({ page, request }) => {
    // Create first scheduling conflict - same resource for overlapping time slots
    await page.goto(`${baseURL}/scheduling`);
    await page.fill('[data-testid="resource-selector"]', 'Conference Room A');
    await page.fill('[data-testid="start-time"]', '2024-01-15T10:00');
    await page.fill('[data-testid="end-time"]', '2024-01-15T12:00');
    await page.click('[data-testid="book-resource-btn"]');
    await expect(page.locator('[data-testid="booking-success"]')).toBeVisible();

    // Attempt to book same resource for overlapping time
    await page.fill('[data-testid="resource-selector"]', 'Conference Room A');
    await page.fill('[data-testid="start-time"]', '2024-01-15T11:00');
    await page.fill('[data-testid="end-time"]', '2024-01-15T13:00');
    await page.click('[data-testid="book-resource-btn"]');
    await expect(page.locator('[data-testid="conflict-error"]')).toBeVisible();

    // Create second scheduling conflict - resource already assigned to another event
    await page.goto(`${baseURL}/events/create`);
    await page.fill('[data-testid="event-name"]', 'Team Meeting');
    await page.fill('[data-testid="event-resource"]', 'Projector-001');
    await page.fill('[data-testid="event-start-time"]', '2024-01-16T14:00');
    await page.fill('[data-testid="event-end-time"]', '2024-01-16T16:00');
    await page.click('[data-testid="create-event-btn"]');
    await expect(page.locator('[data-testid="event-created"]')).toBeVisible();

    // Attempt to assign same resource to another event
    await page.fill('[data-testid="event-name"]', 'Training Session');
    await page.fill('[data-testid="event-resource"]', 'Projector-001');
    await page.fill('[data-testid="event-start-time"]', '2024-01-16T15:00');
    await page.fill('[data-testid="event-end-time"]', '2024-01-16T17:00');
    await page.click('[data-testid="create-event-btn"]');
    await expect(page.locator('[data-testid="conflict-error"]')).toBeVisible();

    // Create third scheduling conflict - user already scheduled elsewhere
    await page.goto(`${baseURL}/scheduling/user`);
    await page.fill('[data-testid="user-selector"]', 'john.doe@example.com');
    await page.fill('[data-testid="schedule-start"]', '2024-01-17T09:00');
    await page.fill('[data-testid="schedule-end"]', '2024-01-17T11:00');
    await page.click('[data-testid="schedule-user-btn"]');
    await expect(page.locator('[data-testid="schedule-success"]')).toBeVisible();

    // Attempt to schedule same user for overlapping time
    await page.fill('[data-testid="user-selector"]', 'john.doe@example.com');
    await page.fill('[data-testid="schedule-start"]', '2024-01-17T10:00');
    await page.fill('[data-testid="schedule-end"]', '2024-01-17T12:00');
    await page.click('[data-testid="schedule-user-btn"]');
    await expect(page.locator('[data-testid="conflict-error"]')).toBeVisible();

    // Wait for conflicts to be logged
    await page.waitForTimeout(2000);

    // Log into admin portal
    await page.goto(`${baseURL}/admin/login`);
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-btn"]');
    await expect(page.locator('[data-testid="admin-dashboard"]')).toBeVisible();

    // Navigate to conflict history section
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="conflict-history-link"]');
    await expect(page.locator('[data-testid="conflict-history-page"]')).toBeVisible();

    // Query conflict logs
    await page.click('[data-testid="refresh-logs-btn"]');
    await page.waitForSelector('[data-testid="conflict-log-entry"]');

    // Verify all triggered conflicts appear
    const conflictEntries = page.locator('[data-testid="conflict-log-entry"]');
    await expect(conflictEntries).toHaveCount(3, { timeout: 5000 });

    // Verify each conflict entry contains required fields
    for (let i = 0; i < 3; i++) {
      const entry = conflictEntries.nth(i);
      await expect(entry.locator('[data-testid="conflict-timestamp"]')).toBeVisible();
      await expect(entry.locator('[data-testid="conflict-user-details"]')).toBeVisible();
      await expect(entry.locator('[data-testid="conflict-resource-info"]')).toBeVisible();
      await expect(entry.locator('[data-testid="conflict-type"]')).toBeVisible();
      await expect(entry.locator('[data-testid="conflict-resolution-status"]')).toBeVisible();
    }

    // Verify timestamp format and validity
    const firstTimestamp = await conflictEntries.nth(0).locator('[data-testid="conflict-timestamp"]').textContent();
    expect(firstTimestamp).toMatch(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/);

    // Verify user details are present
    const firstUserDetails = await conflictEntries.nth(0).locator('[data-testid="conflict-user-details"]').textContent();
    expect(firstUserDetails).toBeTruthy();
    expect(firstUserDetails?.length).toBeGreaterThan(0);

    // Verify resource information is present
    const firstResourceInfo = await conflictEntries.nth(0).locator('[data-testid="conflict-resource-info"]').textContent();
    expect(firstResourceInfo).toBeTruthy();

    // Verify conflict type is specified
    const firstConflictType = await conflictEntries.nth(0).locator('[data-testid="conflict-type"]').textContent();
    expect(['Resource Overlap', 'User Double-Booking', 'Time Conflict']).toContain(firstConflictType?.trim());
  });

  test('Test administrator access control to conflict logs (error-case)', async ({ page, request }) => {
    // Log in as non-admin user
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', nonAdminCredentials.username);
    await page.fill('[data-testid="password-input"]', nonAdminCredentials.password);
    await page.click('[data-testid="login-btn"]');
    await expect(page.locator('[data-testid="user-dashboard"]')).toBeVisible();

    // Attempt to navigate to conflict logs by entering URL directly
    await page.goto(`${baseURL}/admin/conflicts`);
    
    // Verify access is denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    const errorMessage = await page.locator('[data-testid="access-denied-message"]').textContent();
    expect(errorMessage).toContain('Access denied');

    // Get non-admin user token from localStorage or cookies
    const nonAdminToken = await page.evaluate(() => {
      return localStorage.getItem('authToken') || document.cookie.match(/authToken=([^;]+)/)?.[1];
    });

    // Attempt to access conflict logs via API
    const apiResponse = await request.get(`${apiBaseURL}/admin/conflicts`, {
      headers: {
        'Authorization': `Bearer ${nonAdminToken}`
      }
    });

    // Verify API returns 403 Forbidden
    expect(apiResponse.status()).toBe(403);

    // Verify no conflict log data is exposed in error response
    const responseBody = await apiResponse.json();
    expect(responseBody).not.toHaveProperty('conflicts');
    expect(responseBody).not.toHaveProperty('data');
    expect(responseBody.error || responseBody.message).toBeTruthy();

    // Log out non-admin user
    await page.goto(`${baseURL}/logout`);
    await page.click('[data-testid="logout-btn"]');
    await expect(page.locator('[data-testid="login-page"]')).toBeVisible();

    // Log in as administrator
    await page.goto(`${baseURL}/admin/login`);
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-btn"]');
    await expect(page.locator('[data-testid="admin-dashboard"]')).toBeVisible();

    // Navigate to conflict history section
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="conflict-history-link"]');
    await expect(page.locator('[data-testid="conflict-history-page"]')).toBeVisible();

    // Verify conflict logs are displayed
    await page.waitForSelector('[data-testid="conflict-log-entry"]', { timeout: 5000 });
    const conflictEntries = page.locator('[data-testid="conflict-log-entry"]');
    const entryCount = await conflictEntries.count();
    expect(entryCount).toBeGreaterThan(0);

    // Get admin token
    const adminToken = await page.evaluate(() => {
      return localStorage.getItem('authToken') || document.cookie.match(/authToken=([^;]+)/)?.[1];
    });

    // Send GET request to API with admin token
    const adminApiResponse = await request.get(`${apiBaseURL}/admin/conflicts`, {
      headers: {
        'Authorization': `Bearer ${adminToken}`
      }
    });

    // Verify API returns 200 OK
    expect(adminApiResponse.status()).toBe(200);

    // Verify response contains conflict data
    const adminResponseBody = await adminApiResponse.json();
    expect(adminResponseBody.conflicts || adminResponseBody.data).toBeTruthy();
    const conflicts = adminResponseBody.conflicts || adminResponseBody.data;
    expect(Array.isArray(conflicts)).toBe(true);
    expect(conflicts.length).toBeGreaterThan(0);
  });

  test('Validate export functionality for conflict logs (happy-path)', async ({ page }) => {
    // Log into admin portal
    await page.goto(`${baseURL}/admin/login`);
    await page.fill('[data-testid="username-input"]', adminCredentials.username);
    await page.fill('[data-testid="password-input"]', adminCredentials.password);
    await page.click('[data-testid="login-btn"]');
    await expect(page.locator('[data-testid="admin-dashboard"]')).toBeVisible();

    // Navigate to conflict history section
    await page.click('[data-testid="admin-menu"]');
    await page.click('[data-testid="conflict-history-link"]');
    await expect(page.locator('[data-testid="conflict-history-page"]')).toBeVisible();

    // Verify conflict logs are displayed with multiple entries
    await page.waitForSelector('[data-testid="conflict-log-entry"]', { timeout: 5000 });
    const conflictEntries = page.locator('[data-testid="conflict-log-entry"]');
    const entryCount = await conflictEntries.count();
    expect(entryCount).toBeGreaterThan(0);

    // Locate and click export option button
    await page.click('[data-testid="export-logs-btn"]');
    await expect(page.locator('[data-testid="export-options-menu"]')).toBeVisible();

    // Select CSV format from export options
    const downloadPromiseCSV = page.waitForEvent('download');
    await page.click('[data-testid="export-csv-option"]');
    
    // Wait for CSV file download to complete
    const downloadCSV = await downloadPromiseCSV;
    expect(downloadCSV.suggestedFilename()).toMatch(/conflict.*\.csv$/i);
    
    // Save and verify CSV file
    const csvPath = `./downloads/${downloadCSV.suggestedFilename()}`;
    await downloadCSV.saveAs(csvPath);
    
    // Verify CSV file exists and has content
    const fs = require('fs');
    expect(fs.existsSync(csvPath)).toBe(true);
    const csvContent = fs.readFileSync(csvPath, 'utf-8');
    expect(csvContent.length).toBeGreaterThan(0);

    // Verify CSV content includes required fields
    const csvHeaders = csvContent.split('\n')[0].toLowerCase();
    expect(csvHeaders).toContain('timestamp');
    expect(csvHeaders).toContain('user');
    expect(csvHeaders).toContain('resource');
    expect(csvHeaders).toContain('type');
    expect(csvHeaders).toContain('description');

    // Verify CSV has data rows
    const csvRows = csvContent.split('\n').filter(row => row.trim().length > 0);
    expect(csvRows.length).toBeGreaterThan(1); // Header + at least one data row

    // Return to conflict logs interface
    await page.waitForTimeout(1000);
    
    // Click export option button again
    await page.click('[data-testid="export-logs-btn"]');
    await expect(page.locator('[data-testid="export-options-menu"]')).toBeVisible();

    // Select PDF format from export options
    const downloadPromisePDF = page.waitForEvent('download');
    await page.click('[data-testid="export-pdf-option"]');
    
    // Wait for PDF file download to complete
    const downloadPDF = await downloadPromisePDF;
    expect(downloadPDF.suggestedFilename()).toMatch(/conflict.*\.pdf$/i);
    
    // Save and verify PDF file
    const pdfPath = `./downloads/${downloadPDF.suggestedFilename()}`;
    await downloadPDF.saveAs(pdfPath);
    
    // Verify PDF file exists and has content
    expect(fs.existsSync(pdfPath)).toBe(true);
    const pdfStats = fs.statSync(pdfPath);
    expect(pdfStats.size).toBeGreaterThan(1000); // PDF should be at least 1KB

    // Verify PDF file signature (PDF files start with %PDF)
    const pdfBuffer = fs.readFileSync(pdfPath);
    const pdfSignature = pdfBuffer.toString('utf-8', 0, 4);
    expect(pdfSignature).toBe('%PDF');

    // Verify export success message is displayed
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible({ timeout: 5000 });
    const successMessage = await page.locator('[data-testid="export-success-message"]').textContent();
    expect(successMessage).toContain('exported successfully');
  });
});