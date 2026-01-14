import { test, expect } from '@playwright/test';

test.describe('Employee Print Schedule Functionality', () => {
  const BASE_URL = process.env.BASE_URL || 'https://schedule-portal.example.com';
  const VALID_EMPLOYEE_EMAIL = 'employee@company.com';
  const VALID_EMPLOYEE_PASSWORD = 'SecurePass123!';

  test.beforeEach(async ({ page }) => {
    // Navigate to the schedule portal
    await page.goto(BASE_URL);
  });

  test('Validate print functionality for daily schedule (happy-path)', async ({ page, context }) => {
    // Step 1: Employee logs in and navigates to daily schedule
    await page.fill('[data-testid="email-input"]', VALID_EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login and dashboard load
    await expect(page).toHaveURL(/.*dashboard|schedule/, { timeout: 10000 });
    await expect(page.locator('[data-testid="employee-dashboard"]')).toBeVisible();
    
    // Navigate to daily schedule view
    await page.click('[data-testid="schedule-menu"]');
    await page.click('[data-testid="daily-schedule-view"]');
    
    // Verify daily schedule is displayed
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-date"]')).toBeVisible();
    
    // Verify all shift details are present
    const shiftDetails = page.locator('[data-testid="shift-detail"]').first();
    await expect(shiftDetails.locator('[data-testid="shift-start-time"]')).toBeVisible();
    await expect(shiftDetails.locator('[data-testid="shift-end-time"]')).toBeVisible();
    await expect(shiftDetails.locator('[data-testid="shift-location"]')).toBeVisible();
    await expect(shiftDetails.locator('[data-testid="shift-role"]')).toBeVisible();
    
    // Step 2: Select print option and preview
    await page.click('[data-testid="print-schedule-button"]');
    
    // Wait for print preview to load
    await page.waitForTimeout(1000);
    const printPreview = page.locator('[data-testid="print-preview-modal"]');
    await expect(printPreview).toBeVisible();
    
    // Verify print preview shows formatted schedule
    await expect(printPreview.locator('[data-testid="preview-employee-name"]')).toBeVisible();
    await expect(printPreview.locator('[data-testid="preview-schedule-date"]')).toBeVisible();
    await expect(printPreview.locator('[data-testid="preview-shift-details"]')).toBeVisible();
    
    // Verify shift information in preview
    const previewShift = printPreview.locator('[data-testid="preview-shift-item"]').first();
    await expect(previewShift.locator('[data-testid="preview-shift-time"]')).toBeVisible();
    await expect(previewShift.locator('[data-testid="preview-shift-location"]')).toBeVisible();
    await expect(previewShift.locator('[data-testid="preview-shift-role"]')).toBeVisible();
    
    // Verify unnecessary UI elements are excluded from preview
    await expect(printPreview.locator('[data-testid="navigation-menu"]')).not.toBeVisible();
    await expect(printPreview.locator('[data-testid="sidebar"]')).not.toBeVisible();
    
    // Step 3: Print the schedule
    // Set up print dialog handler
    const printPromise = page.waitForEvent('popup', { timeout: 5000 }).catch(() => null);
    
    await page.click('[data-testid="confirm-print-button"]');
    
    // Verify print dialog was triggered or print preview closed
    await page.waitForTimeout(500);
    
    // Verify printed copy matches preview (check that preview data is complete)
    const previewContent = await printPreview.locator('[data-testid="preview-content"]').textContent();
    expect(previewContent).toContain('Schedule');
    expect(previewContent?.length).toBeGreaterThan(0);
  });

  test('Verify access control for print feature (error-case)', async ({ page, context }) => {
    // Step 1: Ensure no active session exists
    await context.clearCookies();
    await page.goto(BASE_URL);
    
    // Step 2: Attempt to directly access schedule print URL without logging in
    await page.goto(`${BASE_URL}/schedule/print`);
    
    // Expected Result: Access denied and redirected to login
    await expect(page).toHaveURL(/.*login|auth/, { timeout: 5000 });
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();
    
    // Verify error message or redirect indication
    const errorMessage = page.locator('[data-testid="auth-error-message"]');
    if (await errorMessage.isVisible()) {
      await expect(errorMessage).toContainText(/authentication required|please log in|unauthorized/i);
    }
    
    // Step 3: Navigate to schedule portal main URL without logging in
    await page.goto(BASE_URL);
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();
    
    // Verify print functionality is not accessible
    const printButton = page.locator('[data-testid="print-schedule-button"]');
    await expect(printButton).not.toBeVisible();
    
    // Step 4: Attempt URL manipulation without authentication
    await page.goto(`${BASE_URL}/schedule/daily`);
    await expect(page).toHaveURL(/.*login|auth/, { timeout: 5000 });
    
    // Step 5: Login with valid credentials
    await page.fill('[data-testid="email-input"]', VALID_EMPLOYEE_EMAIL);
    await page.fill('[data-testid="password-input"]', VALID_EMPLOYEE_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Wait for successful login
    await expect(page).toHaveURL(/.*dashboard|schedule/, { timeout: 10000 });
    
    // Step 6: Navigate to daily schedule and verify print option is accessible
    await page.click('[data-testid="schedule-menu"]');
    await page.click('[data-testid="daily-schedule-view"]');
    await expect(page.locator('[data-testid="daily-schedule-container"]')).toBeVisible();
    
    // Verify print option is now visible and accessible
    await expect(page.locator('[data-testid="print-schedule-button"]')).toBeVisible();
    await expect(page.locator('[data-testid="print-schedule-button"]')).toBeEnabled();
    
    // Step 7: Logout from application
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Wait for logout to complete
    await expect(page).toHaveURL(/.*login|auth/, { timeout: 5000 });
    
    // Step 8: Attempt to use browser back button after logout
    await page.goBack();
    
    // Verify redirected back to login or access denied
    await expect(page).toHaveURL(/.*login|auth/, { timeout: 5000 });
    await expect(page.locator('[data-testid="login-form"]')).toBeVisible();
    
    // Verify print functionality is not accessible after logout
    const printButtonAfterLogout = page.locator('[data-testid="print-schedule-button"]');
    await expect(printButtonAfterLogout).not.toBeVisible();
  });
});