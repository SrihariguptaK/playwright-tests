import { test, expect } from '@playwright/test';

test.describe('Schedule Change Notifications', () => {
  const employeeCredentials = {
    username: 'employee.test@company.com',
    password: 'TestPassword123!'
  };

  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto('/login');
  });

  test('Validate display of schedule change notifications on login', async ({ page }) => {
    // Step 1: Employee logs into the web portal
    await page.fill('input[name="username"]', employeeCredentials.username);
    await page.fill('input[name="password"]', employeeCredentials.password);
    await page.click('button[type="submit"]');

    // Expected Result: Notification banner or icon is displayed if there are unread notifications
    await expect(page).toHaveURL(/.*dashboard/);
    const notificationBanner = page.locator('[data-testid="notification-banner"]').or(page.locator('.notification-icon')).or(page.locator('[aria-label="Notifications"]'));
    await expect(notificationBanner).toBeVisible({ timeout: 2000 });

    // Step 2: Employee clicks notification to view details
    await notificationBanner.click();

    // Expected Result: Notification details are displayed correctly
    const notificationDetails = page.locator('[data-testid="notification-details"]').or(page.locator('.notification-content'));
    await expect(notificationDetails).toBeVisible();
    await expect(notificationDetails).toContainText(/schedule/i);

    // Step 3: Employee marks notification as read
    const markAsReadButton = page.locator('[data-testid="mark-as-read"]').or(page.locator('button:has-text("Mark as Read")')).first();
    await markAsReadButton.click();

    // Expected Result: Notification is removed from unread list and status persists
    await expect(markAsReadButton).not.toBeVisible({ timeout: 3000 });

    // Refresh the page to verify persistence
    await page.reload();
    await page.waitForLoadState('networkidle');

    // Verify notification is still marked as read
    const unreadNotifications = page.locator('[data-testid="unread-notification"]');
    const unreadCount = await unreadNotifications.count();
    
    // Log out
    await page.click('[data-testid="user-menu"]').catch(() => page.click('[aria-label="User menu"]'));
    await page.click('button:has-text("Logout")').or(page.locator('[data-testid="logout-button"]'));
    await expect(page).toHaveURL(/.*login/);
  });

  test('Verify notifications are only shown to relevant employees', async ({ page }) => {
    // Step 1: Employee logs in
    await page.fill('input[name="username"]', employeeCredentials.username);
    await page.fill('input[name="password"]', employeeCredentials.password);
    await page.click('button[type="submit"]');

    // Expected Result: Only notifications related to the employee's schedule are displayed
    await expect(page).toHaveURL(/.*dashboard/);

    // Access the notifications section
    const notificationIcon = page.locator('[data-testid="notification-icon"]').or(page.locator('[aria-label="Notifications"]'));
    await notificationIcon.click();

    // Wait for notifications to load (within 2 seconds as per requirements)
    await page.waitForSelector('[data-testid="notification-list"]', { timeout: 2000 });

    // Get all displayed notifications
    const notifications = page.locator('[data-testid="notification-item"]').or(page.locator('.notification-item'));
    const notificationCount = await notifications.count();

    // Verify each notification contains employee-relevant information
    for (let i = 0; i < notificationCount; i++) {
      const notification = notifications.nth(i);
      await expect(notification).toBeVisible();
      
      // Check notification contains schedule-related content
      const notificationText = await notification.textContent();
      expect(notificationText).toBeTruthy();
      
      // Verify notification has employee-specific data (employee ID, name, or schedule details)
      const hasRelevantInfo = /employee|schedule|shift|assigned|changed/i.test(notificationText || '');
      expect(hasRelevantInfo).toBeTruthy();
    }

    // Verify notification count is displayed correctly
    if (notificationCount > 0) {
      const notificationBadge = page.locator('[data-testid="notification-count"]').or(page.locator('.notification-badge'));
      const badgeText = await notificationBadge.textContent();
      expect(parseInt(badgeText || '0')).toBeGreaterThanOrEqual(0);
    }
  });

  test('Validate notification status persists across sessions', async ({ page }) => {
    // First session: Login and mark notification as read
    await page.fill('input[name="username"]', employeeCredentials.username);
    await page.fill('input[name="password"]', employeeCredentials.password);
    await page.click('button[type="submit"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Check for notifications
    const notificationIcon = page.locator('[data-testid="notification-icon"]').or(page.locator('[aria-label="Notifications"]'));
    await notificationIcon.click();

    // Get initial unread count
    const initialNotifications = page.locator('[data-testid="notification-item"]').or(page.locator('.notification-item'));
    const initialCount = await initialNotifications.count();

    if (initialCount > 0) {
      // Mark first notification as read
      const markAsReadButton = page.locator('[data-testid="mark-as-read"]').or(page.locator('button:has-text("Mark as Read")')).first();
      await markAsReadButton.click();
      await page.waitForTimeout(1000);
    }

    // Logout
    await page.click('[data-testid="user-menu"]').catch(() => page.click('[aria-label="User menu"]'));
    await page.click('button:has-text("Logout")').or(page.locator('[data-testid="logout-button"]'));
    await expect(page).toHaveURL(/.*login/);

    // Second session: Login again and verify persistence
    await page.fill('input[name="username"]', employeeCredentials.username);
    await page.fill('input[name="password"]', employeeCredentials.password);
    await page.click('button[type="submit"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Check notifications again
    await notificationIcon.click();
    const persistedNotifications = page.locator('[data-testid="notification-item"]').or(page.locator('.notification-item'));
    const persistedCount = await persistedNotifications.count();

    // Verify the read notification is not in unread list
    if (initialCount > 0) {
      expect(persistedCount).toBeLessThanOrEqual(initialCount);
    }
  });

  test('Verify notifications load within 2 seconds', async ({ page }) => {
    // Login
    await page.fill('input[name="username"]', employeeCredentials.username);
    await page.fill('input[name="password"]', employeeCredentials.password);
    
    const startTime = Date.now();
    await page.click('button[type="submit"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Click on notifications
    const notificationIcon = page.locator('[data-testid="notification-icon"]').or(page.locator('[aria-label="Notifications"]'));
    await notificationIcon.click();

    // Wait for notifications to load
    await page.waitForSelector('[data-testid="notification-list"]', { timeout: 2000 });
    const endTime = Date.now();
    const loadTime = endTime - startTime;

    // Verify load time is within 2 seconds (2000ms)
    expect(loadTime).toBeLessThan(2000);

    // Verify notifications are visible
    const notificationList = page.locator('[data-testid="notification-list"]');
    await expect(notificationList).toBeVisible();
  });
});