import { test, expect } from '@playwright/test';

test.describe('Review Cycle Setup - Story 32', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const REVIEW_CYCLE_PAGE = `${BASE_URL}/review-cycles/management`;

  test.beforeEach(async ({ page }) => {
    // Authenticate user before each test
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', 'performance.manager@example.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful setup of review cycles', async ({ page }) => {
    // Step 1: Navigate to the review cycle management page
    await page.goto(REVIEW_CYCLE_PAGE);
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Review cycle management interface is displayed
    await expect(page.locator('[data-testid="review-cycle-management-page"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Review Cycle Management');

    // Step 2: Select a frequency for review cycles
    await page.click('[data-testid="frequency-dropdown"]');
    await page.click('[data-testid="frequency-option-weekly"]');
    
    // Expected Result: Selected frequency is displayed
    await expect(page.locator('[data-testid="frequency-dropdown"]')).toContainText('Weekly');

    // Step 3: Click on the save button
    await page.click('[data-testid="save-review-cycle-button"]');
    
    // Expected Result: Review cycle is saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Review cycle is saved successfully');
    
    // Verify the review cycle appears in the list
    await expect(page.locator('[data-testid="review-cycle-list"]')).toContainText('Weekly');
  });

  test('Ensure reminders are sent for upcoming review cycles', async ({ page }) => {
    // Step 1: Set up a review cycle with a defined frequency
    await page.goto(REVIEW_CYCLE_PAGE);
    await page.waitForLoadState('networkidle');
    
    await page.click('[data-testid="frequency-dropdown"]');
    await page.click('[data-testid="frequency-option-daily"]');
    await page.click('[data-testid="save-review-cycle-button"]');
    
    // Expected Result: Review cycle is saved
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Review cycle is saved successfully');

    // Step 2: Wait for the reminder time (simulated by checking notification system)
    // Navigate to notifications page to verify reminder
    await page.click('[data-testid="notifications-icon"]');
    await page.waitForTimeout(2000); // Allow notifications to load
    
    // Step 3: Check notification for review cycle
    // Expected Result: Notification contains correct review cycle details
    const notificationPanel = page.locator('[data-testid="notification-panel"]');
    await expect(notificationPanel).toBeVisible();
    
    const reviewCycleNotification = page.locator('[data-testid="notification-item"]').filter({ hasText: 'Review Cycle Reminder' });
    await expect(reviewCycleNotification).toBeVisible();
    await expect(reviewCycleNotification).toContainText('Daily');
    await expect(reviewCycleNotification).toContainText('upcoming review');
  });

  test('Verify error handling for incomplete review cycle setup', async ({ page }) => {
    // Step 1: Navigate to the review cycle management page
    await page.goto(REVIEW_CYCLE_PAGE);
    await page.waitForLoadState('networkidle');
    
    // Expected Result: Review cycle management interface is displayed
    await expect(page.locator('[data-testid="review-cycle-management-page"]')).toBeVisible();
    await expect(page.locator('h1')).toContainText('Review Cycle Management');

    // Step 2: Attempt to save a review cycle without selecting frequency
    await page.click('[data-testid="save-review-cycle-button"]');
    
    // Expected Result: Error message is displayed for missing frequency
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('frequency');
    await expect(page.locator('[data-testid="error-message"]')).toContainText('required');
    
    // Verify frequency field has error styling
    await expect(page.locator('[data-testid="frequency-dropdown"]')).toHaveClass(/error|invalid/);

    // Step 3: Select frequency and save
    await page.click('[data-testid="frequency-dropdown"]');
    await page.click('[data-testid="frequency-option-monthly"]');
    await expect(page.locator('[data-testid="frequency-dropdown"]')).toContainText('Monthly');
    
    await page.click('[data-testid="save-review-cycle-button"]');
    
    // Expected Result: Review cycle is saved successfully
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Review cycle is saved successfully');
    
    // Verify error message is no longer displayed
    await expect(page.locator('[data-testid="error-message"]')).not.toBeVisible();
    
    // Verify the review cycle appears in the list
    await expect(page.locator('[data-testid="review-cycle-list"]')).toContainText('Monthly');
  });

  test.afterEach(async ({ page }) => {
    // Cleanup: Close any open modals or notifications
    await page.close();
  });
});