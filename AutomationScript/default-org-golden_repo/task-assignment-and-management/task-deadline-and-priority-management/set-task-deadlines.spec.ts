import { test, expect } from '@playwright/test';

test.describe('Story-3: Set deadlines for tasks to achieve timely completion', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  
  test.beforeEach(async ({ page }) => {
    // Login as manager before each test
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', 'manager@example.com');
    await page.fill('[data-testid="password-input"]', 'manager123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Set valid future deadline successfully', async ({ page }) => {
    // Step 1: Navigate to task deadline setting page
    await page.goto(`${BASE_URL}/tasks/deadline-setting`);
    await expect(page.locator('[data-testid="deadline-input-form"]')).toBeVisible();
    
    // Step 2: Enter a valid future date and time (7 days from now at 5:00 PM)
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 7);
    futureDate.setHours(17, 0, 0, 0);
    
    const dateString = futureDate.toISOString().split('T')[0];
    const timeString = '17:00';
    
    await page.fill('[data-testid="deadline-date-input"]', dateString);
    await page.fill('[data-testid="deadline-time-input"]', timeString);
    
    // Verify input accepted without errors
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();
    
    // Step 3: Submit deadline
    await page.click('[data-testid="submit-deadline-button"]');
    
    // Verify deadline saved and confirmation displayed
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Deadline set successfully');
    
    // Verify deadline is displayed correctly
    await expect(page.locator('[data-testid="deadline-display"]')).toContainText(dateString);
  });

  test('Reject past date as deadline', async ({ page }) => {
    // Step 1: Navigate to deadline setting page
    await page.goto(`${BASE_URL}/tasks/deadline-setting`);
    await expect(page.locator('[data-testid="deadline-input-form"]')).toBeVisible();
    
    // Step 2: Enter a past date (yesterday at 3:00 PM)
    const pastDate = new Date();
    pastDate.setDate(pastDate.getDate() - 1);
    pastDate.setHours(15, 0, 0, 0);
    
    const pastDateString = pastDate.toISOString().split('T')[0];
    const pastTimeString = '15:00';
    
    await page.fill('[data-testid="deadline-date-input"]', pastDateString);
    await page.fill('[data-testid="deadline-time-input"]', pastTimeString);
    
    // Verify validation error displayed
    await expect(page.locator('[data-testid="validation-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-error"]')).toContainText('Deadline must be a future date');
    
    // Step 3: Attempt to submit deadline
    await page.click('[data-testid="submit-deadline-button"]');
    
    // Verify submission blocked with error message
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('Cannot set past date as deadline');
    
    // Verify no confirmation message is shown
    await expect(page.locator('[data-testid="confirmation-message"]')).not.toBeVisible();
  });

  test('Verify deadline update processing time', async ({ page }) => {
    // Step 1: Navigate to task with existing deadline and open update interface
    await page.goto(`${BASE_URL}/tasks/1/deadline-update`);
    await expect(page.locator('[data-testid="deadline-update-form"]')).toBeVisible();
    
    // Step 2: Update deadline with valid future date (10 days from now at 2:00 PM)
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 10);
    futureDate.setHours(14, 0, 0, 0);
    
    const dateString = futureDate.toISOString().split('T')[0];
    const timeString = '14:00';
    
    await page.fill('[data-testid="deadline-date-input"]', dateString);
    await page.fill('[data-testid="deadline-time-input"]', timeString);
    
    // Note timestamp before submission and measure response time
    const startTime = Date.now();
    
    await page.click('[data-testid="update-deadline-button"]');
    
    // Wait for response and measure time
    await page.waitForSelector('[data-testid="confirmation-message"]', { timeout: 3000 });
    const endTime = Date.now();
    const responseTime = endTime - startTime;
    
    // Verify response received within 2 seconds (2000ms)
    expect(responseTime).toBeLessThan(2000);
    
    // Step 3: Confirm confirmation message display
    await expect(page.locator('[data-testid="confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-message"]')).toContainText('Deadline updated successfully');
    
    // Verify updated deadline is displayed
    await expect(page.locator('[data-testid="deadline-display"]')).toContainText(dateString);
  });
});