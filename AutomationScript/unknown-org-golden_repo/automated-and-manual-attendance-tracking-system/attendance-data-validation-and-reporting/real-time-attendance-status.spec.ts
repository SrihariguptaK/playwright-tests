import { test, expect } from '@playwright/test';

test.describe('Real-time Attendance Status Dashboard', () => {
  const MANAGER_USERNAME = 'attendance.manager@company.com';
  const MANAGER_PASSWORD = 'Manager@123';
  const UNAUTHORIZED_USERNAME = 'regular.employee@company.com';
  const UNAUTHORIZED_PASSWORD = 'Employee@123';
  const DASHBOARD_URL = '/attendance/real-time-dashboard';
  const LOGIN_URL = '/login';

  test('View real-time attendance status with filtering', async ({ page }) => {
    // Step 1: Login as attendance manager
    await page.goto(LOGIN_URL);
    await page.fill('[data-testid="username-input"]', MANAGER_USERNAME);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Access granted to real-time dashboard
    await expect(page).toHaveURL(new RegExp(DASHBOARD_URL));
    await expect(page.locator('[data-testid="real-time-dashboard"]')).toBeVisible();
    await expect(page.locator('[data-testid="dashboard-title"]')).toContainText('Real-Time Attendance Status');
    
    // Step 2: View attendance status and apply department filter
    await expect(page.locator('[data-testid="attendance-grid"]')).toBeVisible();
    
    // Verify initial employee count is displayed
    const initialEmployeeCount = await page.locator('[data-testid="employee-row"]').count();
    expect(initialEmployeeCount).toBeGreaterThan(0);
    
    // Apply department filter
    await page.click('[data-testid="department-filter-dropdown"]');
    await page.click('[data-testid="department-option-engineering"]');
    await page.click('[data-testid="apply-filter-button"]');
    
    // Expected Result: Dashboard updates to show filtered employees
    await page.waitForTimeout(500); // Wait for filter to apply
    await expect(page.locator('[data-testid="active-filter-badge"]')).toContainText('Engineering');
    
    const filteredEmployeeCount = await page.locator('[data-testid="employee-row"]').count();
    expect(filteredEmployeeCount).toBeGreaterThan(0);
    expect(filteredEmployeeCount).toBeLessThanOrEqual(initialEmployeeCount);
    
    // Verify filtered employees belong to Engineering department
    const departmentCells = await page.locator('[data-testid="employee-department"]').allTextContents();
    departmentCells.forEach(dept => {
      expect(dept).toContain('Engineering');
    });
    
    // Step 3: Verify data refreshes every minute
    // Capture initial timestamp
    const initialTimestamp = await page.locator('[data-testid="last-updated-timestamp"]').textContent();
    expect(initialTimestamp).toBeTruthy();
    
    // Wait for auto-refresh (61 seconds to ensure refresh occurs)
    await page.waitForTimeout(61000);
    
    // Expected Result: Attendance status updates automatically
    const updatedTimestamp = await page.locator('[data-testid="last-updated-timestamp"]').textContent();
    expect(updatedTimestamp).toBeTruthy();
    expect(updatedTimestamp).not.toBe(initialTimestamp);
    
    // Verify refresh indicator appeared
    await expect(page.locator('[data-testid="refresh-indicator"]')).toHaveAttribute('data-refreshed', 'true');
  });

  test('Verify access restriction to real-time dashboard', async ({ page }) => {
    // Step 1: Login as unauthorized user
    await page.goto(LOGIN_URL);
    await page.fill('[data-testid="username-input"]', UNAUTHORIZED_USERNAME);
    await page.fill('[data-testid="password-input"]', UNAUTHORIZED_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Wait for login to complete
    await page.waitForLoadState('networkidle');
    
    // Attempt to navigate to real-time dashboard
    await page.goto(DASHBOARD_URL);
    
    // Expected Result: Access to dashboard denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    await expect(page.locator('[data-testid="error-description"]')).toContainText('You do not have permission to view this dashboard');
    
    // Verify user is redirected or dashboard content is not visible
    await expect(page.locator('[data-testid="real-time-dashboard"]')).not.toBeVisible();
    
    // Verify HTTP response code indicates forbidden access
    const response = await page.goto(DASHBOARD_URL);
    expect(response?.status()).toBe(403);
  });

  test('System differentiates between biometric and manual attendance entries', async ({ page }) => {
    // Login as attendance manager
    await page.goto(LOGIN_URL);
    await page.fill('[data-testid="username-input"]', MANAGER_USERNAME);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(new RegExp(DASHBOARD_URL));
    await expect(page.locator('[data-testid="attendance-grid"]')).toBeVisible();
    
    // Verify biometric entries are marked
    const biometricEntries = page.locator('[data-testid="attendance-source"][data-source="biometric"]');
    await expect(biometricEntries.first()).toBeVisible();
    await expect(biometricEntries.first()).toContainText('Biometric');
    
    // Verify manual entries are marked
    const manualEntries = page.locator('[data-testid="attendance-source"][data-source="manual"]');
    if (await manualEntries.count() > 0) {
      await expect(manualEntries.first()).toContainText('Manual');
    }
    
    // Verify visual differentiation (icons or badges)
    await expect(page.locator('[data-testid="biometric-icon"]').first()).toBeVisible();
  });

  test('System highlights absent and late employees clearly', async ({ page }) => {
    // Login as attendance manager
    await page.goto(LOGIN_URL);
    await page.fill('[data-testid="username-input"]', MANAGER_USERNAME);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(new RegExp(DASHBOARD_URL));
    await expect(page.locator('[data-testid="attendance-grid"]')).toBeVisible();
    
    // Verify absent employees are highlighted
    const absentEmployees = page.locator('[data-testid="employee-row"][data-status="absent"]');
    if (await absentEmployees.count() > 0) {
      await expect(absentEmployees.first()).toHaveClass(/absent|highlight-absent/);
      await expect(absentEmployees.first().locator('[data-testid="status-badge"]')).toContainText('Absent');
    }
    
    // Verify late employees are highlighted
    const lateEmployees = page.locator('[data-testid="employee-row"][data-status="late"]');
    if (await lateEmployees.count() > 0) {
      await expect(lateEmployees.first()).toHaveClass(/late|highlight-late/);
      await expect(lateEmployees.first().locator('[data-testid="status-badge"]')).toContainText('Late');
    }
    
    // Verify summary counts
    await expect(page.locator('[data-testid="absent-count"]')).toBeVisible();
    await expect(page.locator('[data-testid="late-count"]')).toBeVisible();
  });

  test('System allows filtering by department and shift', async ({ page }) => {
    // Login as attendance manager
    await page.goto(LOGIN_URL);
    await page.fill('[data-testid="username-input"]', MANAGER_USERNAME);
    await page.fill('[data-testid="password-input"]', MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    await expect(page).toHaveURL(new RegExp(DASHBOARD_URL));
    await expect(page.locator('[data-testid="attendance-grid"]')).toBeVisible();
    
    // Test department filter
    await page.click('[data-testid="department-filter-dropdown"]');
    await expect(page.locator('[data-testid="department-option-engineering"]')).toBeVisible();
    await expect(page.locator('[data-testid="department-option-sales"]')).toBeVisible();
    await page.click('[data-testid="department-option-sales"]');
    await page.click('[data-testid="apply-filter-button"]');
    
    await page.waitForTimeout(500);
    await expect(page.locator('[data-testid="active-filter-badge"]')).toContainText('Sales');
    
    // Clear department filter
    await page.click('[data-testid="clear-filters-button"]');
    await page.waitForTimeout(500);
    
    // Test shift filter
    await page.click('[data-testid="shift-filter-dropdown"]');
    await expect(page.locator('[data-testid="shift-option-morning"]')).toBeVisible();
    await expect(page.locator('[data-testid="shift-option-evening"]')).toBeVisible();
    await page.click('[data-testid="shift-option-morning"]');
    await page.click('[data-testid="apply-filter-button"]');
    
    await page.waitForTimeout(500);
    await expect(page.locator('[data-testid="active-filter-badge"]')).toContainText('Morning');
    
    // Test combined filters
    await page.click('[data-testid="department-filter-dropdown"]');
    await page.click('[data-testid="department-option-engineering"]');
    await page.click('[data-testid="apply-filter-button"]');
    
    await page.waitForTimeout(500);
    const filterBadges = await page.locator('[data-testid="active-filter-badge"]').allTextContents();
    expect(filterBadges.some(badge => badge.includes('Engineering'))).toBeTruthy();
    expect(filterBadges.some(badge => badge.includes('Morning'))).toBeTruthy();
  });
});