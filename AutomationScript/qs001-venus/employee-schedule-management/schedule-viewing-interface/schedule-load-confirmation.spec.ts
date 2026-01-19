import { test, expect } from '@playwright/test';

test.describe('Schedule Load Confirmation', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application login page
    await page.goto('/login');
    // Login as employee
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    // Wait for successful login
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate confirmation message on schedule load', async ({ page }) => {
    // Action: Employee loads schedule view
    await page.click('[data-testid="my-schedule-menu"]');
    
    // Wait for schedule page to load
    await expect(page).toHaveURL(/.*schedule/);
    
    // Expected Result: Confirmation message is displayed
    const confirmationMessage = page.locator('[data-testid="schedule-load-confirmation"]');
    await expect(confirmationMessage).toBeVisible({ timeout: 10000 });
    
    // Verify confirmation message text
    await expect(confirmationMessage).toContainText(/schedule.*loaded.*successfully/i);
    
    // Action: Wait 5 seconds
    await page.waitForTimeout(5000);
    
    // Expected Result: Confirmation message disappears automatically
    await expect(confirmationMessage).not.toBeVisible();
  });

  test('Validate confirmation message on schedule load (happy-path)', async ({ page }) => {
    // Navigate to the schedule view page by clicking on 'My Schedule' or equivalent menu option
    await page.click('[data-testid="my-schedule-menu"]');
    
    // Wait for the schedule data to load completely
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
    
    // Verify the confirmation message is visible
    const confirmationMessage = page.locator('[data-testid="schedule-load-confirmation"]');
    await expect(confirmationMessage).toBeVisible({ timeout: 10000 });
    
    // Verify confirmation message does not obstruct schedule content or navigation elements
    const scheduleContent = page.locator('[data-testid="schedule-container"]');
    const navigationMenu = page.locator('[data-testid="navigation-menu"]');
    
    await expect(scheduleContent).toBeVisible();
    await expect(navigationMenu).toBeVisible();
    
    // Verify confirmation message is positioned appropriately (not blocking content)
    const messageBox = await confirmationMessage.boundingBox();
    const scheduleBox = await scheduleContent.boundingBox();
    
    if (messageBox && scheduleBox) {
      // Ensure message doesn't significantly overlap with schedule content
      expect(messageBox.y).toBeLessThan(scheduleBox.y);
    }
    
    // Wait for 5 seconds without any user interaction
    await page.waitForTimeout(5000);
    
    // Verify confirmation message disappears
    await expect(confirmationMessage).not.toBeVisible();
    
    // Verify schedule content remains fully visible and accessible after message disappears
    await expect(scheduleContent).toBeVisible();
    await expect(navigationMenu).toBeVisible();
    
    // Verify schedule data is still present and interactive
    const scheduleItems = page.locator('[data-testid="schedule-item"]');
    await expect(scheduleItems.first()).toBeVisible();
    
    // Verify user can interact with schedule after confirmation disappears
    const firstScheduleItem = scheduleItems.first();
    await expect(firstScheduleItem).toBeEnabled();
  });

  test('Validate confirmation message appears for all schedule views', async ({ page }) => {
    // Test weekly view
    await page.click('[data-testid="my-schedule-menu"]');
    await page.click('[data-testid="weekly-view-button"]');
    
    let confirmationMessage = page.locator('[data-testid="schedule-load-confirmation"]');
    await expect(confirmationMessage).toBeVisible({ timeout: 10000 });
    await page.waitForTimeout(5000);
    await expect(confirmationMessage).not.toBeVisible();
    
    // Test monthly view
    await page.click('[data-testid="monthly-view-button"]');
    
    confirmationMessage = page.locator('[data-testid="schedule-load-confirmation"]');
    await expect(confirmationMessage).toBeVisible({ timeout: 10000 });
    await page.waitForTimeout(5000);
    await expect(confirmationMessage).not.toBeVisible();
    
    // Test daily view
    await page.click('[data-testid="daily-view-button"]');
    
    confirmationMessage = page.locator('[data-testid="schedule-load-confirmation"]');
    await expect(confirmationMessage).toBeVisible({ timeout: 10000 });
    await page.waitForTimeout(5000);
    await expect(confirmationMessage).not.toBeVisible();
  });

  test('Validate confirmation message does not obstruct navigation', async ({ page }) => {
    // Navigate to schedule view
    await page.click('[data-testid="my-schedule-menu"]');
    
    // Wait for confirmation message to appear
    const confirmationMessage = page.locator('[data-testid="schedule-load-confirmation"]');
    await expect(confirmationMessage).toBeVisible({ timeout: 10000 });
    
    // Verify all navigation elements are still clickable
    const homeButton = page.locator('[data-testid="home-button"]');
    const profileButton = page.locator('[data-testid="profile-button"]');
    const settingsButton = page.locator('[data-testid="settings-button"]');
    
    await expect(homeButton).toBeVisible();
    await expect(profileButton).toBeVisible();
    await expect(settingsButton).toBeVisible();
    
    // Verify navigation buttons are enabled and clickable
    await expect(homeButton).toBeEnabled();
    await expect(profileButton).toBeEnabled();
    await expect(settingsButton).toBeEnabled();
  });
});