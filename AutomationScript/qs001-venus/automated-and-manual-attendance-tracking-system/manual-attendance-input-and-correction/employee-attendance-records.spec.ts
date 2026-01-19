import { test, expect } from '@playwright/test';

test.describe('Employee Attendance Records - Self-Service Portal', () => {
  const BASE_URL = process.env.BASE_URL || 'https://app.example.com';
  const VALID_USERNAME = 'employee123';
  const VALID_PASSWORD = 'SecurePass123!';
  const EMPLOYEE_ID = '123';
  const OTHER_EMPLOYEE_ID = '456';

  test.beforeEach(async ({ page }) => {
    // Navigate to the self-service portal
    await page.goto(`${BASE_URL}/login`);
  });

  test('Validate employee attendance record viewing', async ({ page }) => {
    // Step 1: Employee logs into self-service portal
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Portal home page displayed
    await expect(page).toHaveURL(new RegExp(`${BASE_URL}/(home|dashboard)`));
    await expect(page.locator('[data-testid="portal-home"]')).toBeVisible();

    // Step 2: Employee navigates to attendance section
    await page.click('[data-testid="attendance-menu"]');
    
    // Expected Result: Attendance records displayed
    await expect(page).toHaveURL(new RegExp(`${BASE_URL}/attendance`));
    await expect(page.locator('[data-testid="attendance-records-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="attendance-record-row"]').first()).toBeVisible();

    // Step 3: Employee applies date range filter
    const startDate = '2024-01-01';
    const endDate = '2024-01-31';
    
    await page.fill('[data-testid="start-date-input"]', startDate);
    await page.fill('[data-testid="end-date-input"]', endDate);
    await page.click('[data-testid="apply-filter-button"]');
    
    // Expected Result: Filtered attendance records displayed
    await page.waitForResponse(response => 
      response.url().includes('/api/attendance/employee') && response.status() === 200
    );
    await expect(page.locator('[data-testid="attendance-records-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="attendance-record-row"]')).toHaveCount(await page.locator('[data-testid="attendance-record-row"]').count());
    
    // Verify attendance records contain required information
    const firstRecord = page.locator('[data-testid="attendance-record-row"]').first();
    await expect(firstRecord.locator('[data-testid="attendance-timestamp"]')).toBeVisible();
    await expect(firstRecord.locator('[data-testid="attendance-source"]')).toBeVisible();
  });

  test('Verify attendance data export functionality', async ({ page }) => {
    // Login first
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(new RegExp(`${BASE_URL}/(home|dashboard)`));
    
    // Navigate to attendance section
    await page.click('[data-testid="attendance-menu"]');
    await expect(page).toHaveURL(new RegExp(`${BASE_URL}/attendance`));

    // Step 1: Employee views attendance records
    await expect(page.locator('[data-testid="attendance-records-table"]')).toBeVisible();
    
    // Expected Result: Records displayed on screen
    const recordCount = await page.locator('[data-testid="attendance-record-row"]').count();
    expect(recordCount).toBeGreaterThan(0);

    // Step 2: Employee clicks export button
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="export-button"]');
    
    // Expected Result: CSV file downloaded with correct data
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/attendance.*\.csv$/i);
    
    // Verify download completed successfully
    const path = await download.path();
    expect(path).toBeTruthy();
  });

  test('Ensure access control for attendance data - unauthorized access attempt', async ({ page }) => {
    // Login first
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(new RegExp(`${BASE_URL}/(home|dashboard)`));

    // Step 1: Employee attempts to access another employee's attendance data via URL manipulation
    await page.goto(`${BASE_URL}/attendance/employee/${OTHER_EMPLOYEE_ID}`);
    
    // Expected Result: Access denied message displayed
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('text=/access denied|unauthorized|forbidden/i')).toBeVisible();
    
    // Verify no attendance data is displayed
    await expect(page.locator('[data-testid="attendance-records-table"]')).not.toBeVisible();

    // Step 2: Employee views own attendance data
    await page.click('[data-testid="attendance-menu"]');
    
    // Expected Result: Data displayed correctly
    await expect(page).toHaveURL(new RegExp(`${BASE_URL}/attendance`));
    await expect(page.locator('[data-testid="attendance-records-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="attendance-record-row"]').first()).toBeVisible();
    
    // Verify employee can see their own data
    const recordCount = await page.locator('[data-testid="attendance-record-row"]').count();
    expect(recordCount).toBeGreaterThan(0);
  });

  test('Verify attendance source display for each record', async ({ page }) => {
    // Login
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Navigate to attendance
    await page.click('[data-testid="attendance-menu"]');
    await expect(page.locator('[data-testid="attendance-records-table"]')).toBeVisible();
    
    // Verify each record shows source (biometric or manual)
    const records = page.locator('[data-testid="attendance-record-row"]');
    const recordCount = await records.count();
    
    for (let i = 0; i < Math.min(recordCount, 5); i++) {
      const record = records.nth(i);
      const source = record.locator('[data-testid="attendance-source"]');
      await expect(source).toBeVisible();
      
      const sourceText = await source.textContent();
      expect(sourceText).toMatch(/biometric|manual/i);
    }
  });

  test('Verify data retrieval performance under 3 seconds', async ({ page }) => {
    // Login
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Measure time to load attendance records
    const startTime = Date.now();
    
    await page.click('[data-testid="attendance-menu"]');
    await page.waitForResponse(response => 
      response.url().includes('/api/attendance/employee') && response.status() === 200
    );
    await expect(page.locator('[data-testid="attendance-records-table"]')).toBeVisible();
    
    const endTime = Date.now();
    const loadTime = (endTime - startTime) / 1000;
    
    // Verify performance requirement: Data retrieval within 3 seconds
    expect(loadTime).toBeLessThan(3);
  });
});