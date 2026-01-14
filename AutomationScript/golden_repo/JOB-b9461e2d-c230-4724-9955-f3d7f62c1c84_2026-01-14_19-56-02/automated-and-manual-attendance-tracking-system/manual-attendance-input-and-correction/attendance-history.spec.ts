import { test, expect } from '@playwright/test';

test.describe('Attendance History - Story 8', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const clerkUsername = 'attendance.clerk@company.com';
  const clerkPassword = 'ClerkPass123!';
  const validEmployeeId = 'EMP001';

  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto(`${baseURL}/login`);
  });

  test('Search and view attendance history (happy-path)', async ({ page }) => {
    // Step 1: Login as Attendance Clerk
    await page.fill('[data-testid="username-input"]', clerkUsername);
    await page.fill('[data-testid="password-input"]', clerkPassword);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Access granted to attendance history section
    await expect(page.locator('[data-testid="attendance-history-menu"]')).toBeVisible({ timeout: 10000 });
    
    // Step 2: Navigate to Attendance History section
    await page.click('[data-testid="attendance-history-menu"]');
    await expect(page).toHaveURL(/.*attendance-history/);
    
    // Step 3: Enter employee ID and date range
    await page.fill('[data-testid="employee-id-input"]', validEmployeeId);
    
    // Select valid start date
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - 30);
    const startDateString = startDate.toISOString().split('T')[0];
    await page.fill('[data-testid="start-date-picker"]', startDateString);
    
    // Select valid end date (after start date)
    const endDate = new Date();
    const endDateString = endDate.toISOString().split('T')[0];
    await page.fill('[data-testid="end-date-picker"]', endDateString);
    
    // Expected Result: Inputs accepted without validation errors
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    
    // Step 4: Submit search query
    await page.click('[data-testid="search-button"]');
    
    // Wait for search results to load
    await page.waitForSelector('[data-testid="attendance-results-table"]', { timeout: 5000 });
    
    // Expected Result: Attendance records displayed with combined biometric and manual data
    await expect(page.locator('[data-testid="attendance-results-table"]')).toBeVisible();
    
    // Verify table contains expected columns
    await expect(page.locator('[data-testid="column-date"]')).toBeVisible();
    await expect(page.locator('[data-testid="column-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="column-entry-type"]')).toBeVisible();
    await expect(page.locator('[data-testid="column-status"]')).toBeVisible();
    
    // Verify at least one record is displayed
    const recordCount = await page.locator('[data-testid="attendance-record-row"]').count();
    expect(recordCount).toBeGreaterThan(0);
    
    // Verify combined biometric and manual data is present
    const firstRecord = page.locator('[data-testid="attendance-record-row"]').first();
    await expect(firstRecord).toContainText(/biometric|manual/i);
  });

  test('Export attendance history data (happy-path)', async ({ page }) => {
    // Step 1: Login as Attendance Clerk
    await page.fill('[data-testid="username-input"]', clerkUsername);
    await page.fill('[data-testid="password-input"]', clerkPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="attendance-history-menu"]')).toBeVisible({ timeout: 10000 });
    
    // Navigate to Attendance History section
    await page.click('[data-testid="attendance-history-menu"]');
    
    // Perform attendance history search
    await page.fill('[data-testid="employee-id-input"]', validEmployeeId);
    
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - 30);
    await page.fill('[data-testid="start-date-picker"]', startDate.toISOString().split('T')[0]);
    
    const endDate = new Date();
    await page.fill('[data-testid="end-date-picker"]', endDate.toISOString().split('T')[0]);
    
    await page.click('[data-testid="search-button"]');
    
    // Expected Result: Results displayed
    await page.waitForSelector('[data-testid="attendance-results-table"]', { timeout: 5000 });
    await expect(page.locator('[data-testid="attendance-results-table"]')).toBeVisible();
    
    // Step 2: Click export button
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-button"]');
    
    // Expected Result: CSV file downloaded with correct attendance data
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/attendance.*\.csv$/i);
    
    // Verify download completed successfully
    const path = await download.path();
    expect(path).toBeTruthy();
    
    // Read and verify CSV content
    const fs = require('fs');
    const csvContent = fs.readFileSync(path, 'utf-8');
    
    // Verify CSV contains expected headers
    expect(csvContent).toContain('Employee ID');
    expect(csvContent).toContain('Date');
    expect(csvContent).toContain('Time');
    expect(csvContent).toContain('Entry Type');
    expect(csvContent).toContain('Status');
    
    // Verify CSV contains both biometric and manual entries
    expect(csvContent).toMatch(/biometric|manual/i);
  });

  test('Validate search input errors (error-case)', async ({ page }) => {
    // Step 1: Login as Attendance Clerk
    await page.fill('[data-testid="username-input"]', clerkUsername);
    await page.fill('[data-testid="password-input"]', clerkPassword);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="attendance-history-menu"]')).toBeVisible({ timeout: 10000 });
    
    // Navigate to Attendance History section
    await page.click('[data-testid="attendance-history-menu"]');
    
    // Step 2: Enter valid employee ID
    await page.fill('[data-testid="employee-id-input"]', validEmployeeId);
    
    // Step 3: Enter invalid date range (end date before start date)
    const endDate = new Date();
    endDate.setDate(endDate.getDate() - 30);
    const endDateString = endDate.toISOString().split('T')[0];
    await page.fill('[data-testid="end-date-picker"]', endDateString);
    
    const startDate = new Date();
    const startDateString = startDate.toISOString().split('T')[0];
    await page.fill('[data-testid="start-date-picker"]', startDateString);
    
    // Expected Result: Validation error displayed
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible({ timeout: 3000 });
    await expect(page.locator('[data-testid="validation-error"]')).toContainText(/date range|invalid|start date.*end date/i);
    
    // Step 4: Attempt search with invalid inputs
    await page.click('[data-testid="search-button"]');
    
    // Expected Result: Search blocked until inputs corrected
    // Verify no results table appears
    await expect(page.locator('[data-testid="attendance-results-table"]')).not.toBeVisible();
    
    // Verify error message persists
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    
    // Step 5: Correct the date range
    const correctedStartDate = new Date();
    correctedStartDate.setDate(correctedStartDate.getDate() - 30);
    await page.fill('[data-testid="start-date-picker"]', correctedStartDate.toISOString().split('T')[0]);
    
    const correctedEndDate = new Date();
    await page.fill('[data-testid="end-date-picker"]', correctedEndDate.toISOString().split('T')[0]);
    
    // Verify validation error disappears
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    
    // Verify Search button becomes enabled
    await expect(page.locator('[data-testid="search-button"]')).toBeEnabled();
    
    // Click search with corrected valid inputs
    await page.click('[data-testid="search-button"]');
    
    // Verify search executes successfully
    await page.waitForSelector('[data-testid="attendance-results-table"]', { timeout: 5000 });
    await expect(page.locator('[data-testid="attendance-results-table"]')).toBeVisible();
  });
});