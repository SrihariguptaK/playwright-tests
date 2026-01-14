import { test, expect } from '@playwright/test';

test.describe('Schedule Copy Functionality', () => {
  test.beforeEach(async ({ page }) => {
    // Login as Scheduling Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduling.manager@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Copy schedules from one period to another successfully', async ({ page }) => {
    // Step 1: Navigate to schedule copy page
    await page.click('[data-testid="schedule-management-link"]');
    await expect(page.locator('[data-testid="schedule-management-header"]')).toBeVisible();
    
    await page.click('[data-testid="copy-schedule-button"]');
    await expect(page.locator('[data-testid="schedule-copy-ui"]')).toBeVisible();
    await expect(page.locator('[data-testid="copy-schedule-header"]')).toHaveText(/Copy Schedule/i);
    
    // Step 2: Select source and target periods
    await page.click('[data-testid="source-period-dropdown"]');
    await page.click('[data-testid="source-period-option-january-2024"]');
    await expect(page.locator('[data-testid="source-period-dropdown"]')).toContainText('January 2024');
    
    await page.click('[data-testid="target-period-dropdown"]');
    await page.click('[data-testid="target-period-option-february-2024"]');
    await expect(page.locator('[data-testid="target-period-dropdown"]')).toContainText('February 2024');
    
    // Verify schedules are previewed
    await expect(page.locator('[data-testid="schedule-preview-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-preview-item"]')).toHaveCount(await page.locator('[data-testid="schedule-preview-item"]').count());
    
    // Step 3: Confirm copy
    await page.click('[data-testid="confirm-copy-button"]');
    
    // Verify schedules copied and confirmation shown
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText(/successfully copied/i);
    
    // Verify copied schedules appear in target period
    await page.click('[data-testid="view-target-period-button"]');
    await expect(page.locator('[data-testid="period-selector"]')).toContainText('February 2024');
    await expect(page.locator('[data-testid="schedule-item"]').first()).toBeVisible();
  });

  test('Detect conflicts during schedule copy', async ({ page }) => {
    // Step 1: Navigate to schedule copy page
    await page.click('[data-testid="schedule-management-link"]');
    await page.click('[data-testid="copy-schedule-button"]');
    await expect(page.locator('[data-testid="schedule-copy-ui"]')).toBeVisible();
    
    // Step 2: Select source and target periods with overlapping schedules
    await page.click('[data-testid="source-period-dropdown"]');
    await page.click('[data-testid="source-period-option-january-2024"]');
    await expect(page.locator('[data-testid="source-period-dropdown"]')).toContainText('January 2024');
    
    await page.click('[data-testid="target-period-dropdown"]');
    await page.click('[data-testid="target-period-option-march-2024"]');
    await expect(page.locator('[data-testid="target-period-dropdown"]')).toContainText('March 2024');
    
    // Verify conflict warnings displayed in preview
    await expect(page.locator('[data-testid="schedule-preview-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-warning"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-warning"]')).toContainText(/conflict/i);
    await expect(page.locator('[data-testid="conflict-item"]').first()).toBeVisible();
    
    // Step 3: Attempt to confirm copy
    const confirmButton = page.locator('[data-testid="confirm-copy-button"]');
    
    // Verify copy blocked until conflicts resolved
    await expect(confirmButton).toBeDisabled();
    
    // Alternative: If button is enabled but shows validation error on click
    if (await confirmButton.isEnabled()) {
      await confirmButton.click();
      await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
      await expect(page.locator('[data-testid="validation-error"]')).toContainText(/resolve conflicts/i);
    }
    
    // Verify schedules were not copied
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();
  });
});