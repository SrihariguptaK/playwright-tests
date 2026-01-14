import { test, expect, devices } from '@playwright/test';

const SCHEDULE_URL = process.env.SCHEDULE_URL || 'https://example.com/schedule';
const EMPLOYEE_EMAIL = process.env.EMPLOYEE_EMAIL || 'employee@company.com';
const EMPLOYEE_PASSWORD = process.env.EMPLOYEE_PASSWORD || 'Password123!';

test.describe('Responsive Schedule Interface - Mobile Accessibility', () => {
  test.describe('Validate responsive layout on mobile devices', () => {
    test('should adapt layout to smartphone screen size and maintain full functionality', async ({ browser }) => {
      // Use mobile device configuration
      const context = await browser.newContext({
        ...devices['iPhone 12']
      });
      const page = await context.newPage();

      // Action: Open smartphone browser and navigate to the schedule interface URL
      await page.goto(SCHEDULE_URL);
      await expect(page).toHaveTitle(/Schedule/i);

      // Action: Log in with valid employee credentials
      await page.fill('[data-testid="email-input"]', EMPLOYEE_EMAIL);
      await page.fill('[data-testid="password-input"]', EMPLOYEE_PASSWORD);
      await page.click('[data-testid="login-button"]');
      await page.waitForURL('**/schedule/dashboard');

      // Expected Result: Layout adjusts to screen size without horizontal scrolling
      const viewport = page.viewportSize();
      const bodyWidth = await page.evaluate(() => document.body.scrollWidth);
      expect(bodyWidth).toBeLessThanOrEqual(viewport!.width);

      // Action: Observe the layout of the schedule interface on the smartphone screen
      await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
      await expect(page.locator('[data-testid="schedule-header"]')).toBeVisible();
      await expect(page.locator('[data-testid="schedule-navigation"]')).toBeVisible();

      // Action: Navigate to different schedule views (daily, weekly, monthly)
      // Daily view
      await page.click('[data-testid="view-selector"]');
      await page.click('[data-testid="daily-view-option"]');
      await expect(page.locator('[data-testid="daily-schedule-view"]')).toBeVisible();
      await expect(page.locator('[data-testid="schedule-container"]')).toBeInViewport();

      // Weekly view
      await page.click('[data-testid="view-selector"]');
      await page.click('[data-testid="weekly-view-option"]');
      await expect(page.locator('[data-testid="weekly-schedule-view"]')).toBeVisible();
      await expect(page.locator('[data-testid="schedule-container"]')).toBeInViewport();

      // Monthly view
      await page.click('[data-testid="view-selector"]');
      await page.click('[data-testid="monthly-view-option"]');
      await expect(page.locator('[data-testid="monthly-schedule-view"]')).toBeVisible();
      await expect(page.locator('[data-testid="schedule-container"]')).toBeInViewport();

      // Action: Access and use filter options (date range, department, employee)
      // Expected Result: All features are accessible and functional
      await page.click('[data-testid="filter-button"]');
      await expect(page.locator('[data-testid="filter-panel"]')).toBeVisible();

      // Date range filter
      await page.click('[data-testid="date-range-filter"]');
      await page.click('[data-testid="start-date-picker"]');
      await page.click('text="15"');
      await page.click('[data-testid="end-date-picker"]');
      await page.click('text="20"');
      await page.click('[data-testid="apply-date-filter"]');

      // Department filter
      await page.click('[data-testid="department-filter"]');
      await page.click('[data-testid="department-option-sales"]');

      // Employee filter
      await page.click('[data-testid="employee-filter"]');
      await page.fill('[data-testid="employee-search-input"]', 'John');
      await page.click('[data-testid="employee-option-first"]');

      await page.click('[data-testid="apply-filters-button"]');
      await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();

      // Action: Scroll vertically and horizontally through the schedule content
      await page.evaluate(() => window.scrollTo(0, 200));
      await page.waitForTimeout(500);
      await page.evaluate(() => window.scrollTo(0, 0));

      // Action: Tap on various interactive controls (buttons, dropdowns, date pickers)
      // Expected Result: Controls respond accurately and promptly
      const startTime = Date.now();
      await page.click('[data-testid="add-shift-button"]');
      const responseTime = Date.now() - startTime;
      expect(responseTime).toBeLessThan(1000);
      await expect(page.locator('[data-testid="shift-modal"]')).toBeVisible();
      await page.click('[data-testid="close-modal-button"]');

      // Test dropdown responsiveness
      await page.click('[data-testid="view-selector"]');
      await expect(page.locator('[data-testid="view-options-menu"]')).toBeVisible();
      await page.click('[data-testid="daily-view-option"]');

      // Test date picker
      await page.click('[data-testid="date-picker-button"]');
      await expect(page.locator('[data-testid="calendar-widget"]')).toBeVisible();
      await page.click('text="Today"');

      // Action: Test touch gestures such as swipe and pinch-to-zoom if applicable
      const scheduleElement = page.locator('[data-testid="schedule-container"]');
      const boundingBox = await scheduleElement.boundingBox();
      if (boundingBox) {
        await page.touchscreen.tap(boundingBox.x + 50, boundingBox.y + 50);
        await expect(scheduleElement).toBeVisible();
      }

      // Action: Rotate device from portrait to landscape orientation
      await context.setViewportSize({ width: 844, height: 390 });
      await page.waitForTimeout(500);
      await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
      
      // Verify no horizontal scrolling in landscape
      const landscapeBodyWidth = await page.evaluate(() => document.body.scrollWidth);
      const landscapeViewport = page.viewportSize();
      expect(landscapeBodyWidth).toBeLessThanOrEqual(landscapeViewport!.width + 10);

      await context.close();
    });
  });

  test.describe('Verify load times on mobile network', () => {
    test('should load schedule interface within 5 seconds on 4G network', async ({ browser }) => {
      // Use mobile device configuration with network throttling
      const context = await browser.newContext({
        ...devices['iPhone 12'],
        // Simulate 4G network conditions
        offline: false
      });
      const page = await context.newPage();

      // Simulate 4G network throttling
      const client = await context.newCDPSession(page);
      await client.send('Network.emulateNetworkConditions', {
        offline: false,
        downloadThroughput: (4 * 1024 * 1024) / 8, // 4 Mbps
        uploadThroughput: (1 * 1024 * 1024) / 8,   // 1 Mbps
        latency: 50 // 50ms latency
      });

      // Action: Clear browser cache and cookies
      await context.clearCookies();

      // Action: Navigate to the schedule interface URL and start timer
      const startTime = Date.now();
      await page.goto(SCHEDULE_URL, { waitUntil: 'networkidle' });
      const initialLoadTime = Date.now() - startTime;

      // Expected Result: Page loads within 5 seconds
      expect(initialLoadTime).toBeLessThan(5000);
      console.log(`Initial page load time: ${initialLoadTime}ms`);

      // Action: Log in with valid credentials and measure dashboard load time
      await page.fill('[data-testid="email-input"]', EMPLOYEE_EMAIL);
      await page.fill('[data-testid="password-input"]', EMPLOYEE_PASSWORD);
      
      const loginStartTime = Date.now();
      await page.click('[data-testid="login-button"]');
      await page.waitForURL('**/schedule/dashboard', { waitUntil: 'networkidle' });
      const dashboardLoadTime = Date.now() - loginStartTime;

      // Expected Result: Dashboard loads within 5 seconds
      expect(dashboardLoadTime).toBeLessThan(5000);
      console.log(`Dashboard load time: ${dashboardLoadTime}ms`);
      await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();

      // Action: Navigate to different schedule views and measure load times for each
      // Daily view load time
      const dailyStartTime = Date.now();
      await page.click('[data-testid="view-selector"]');
      await page.click('[data-testid="daily-view-option"]');
      await page.waitForLoadState('networkidle');
      const dailyLoadTime = Date.now() - dailyStartTime;
      expect(dailyLoadTime).toBeLessThan(5000);
      console.log(`Daily view load time: ${dailyLoadTime}ms`);
      await expect(page.locator('[data-testid="daily-schedule-view"]')).toBeVisible();

      // Weekly view load time
      const weeklyStartTime = Date.now();
      await page.click('[data-testid="view-selector"]');
      await page.click('[data-testid="weekly-view-option"]');
      await page.waitForLoadState('networkidle');
      const weeklyLoadTime = Date.now() - weeklyStartTime;
      expect(weeklyLoadTime).toBeLessThan(5000);
      console.log(`Weekly view load time: ${weeklyLoadTime}ms`);
      await expect(page.locator('[data-testid="weekly-schedule-view"]')).toBeVisible();

      // Monthly view load time
      const monthlyStartTime = Date.now();
      await page.click('[data-testid="view-selector"]');
      await page.click('[data-testid="monthly-view-option"]');
      await page.waitForLoadState('networkidle');
      const monthlyLoadTime = Date.now() - monthlyStartTime;
      expect(monthlyLoadTime).toBeLessThan(5000);
      console.log(`Monthly view load time: ${monthlyLoadTime}ms`);
      await expect(page.locator('[data-testid="monthly-schedule-view"]')).toBeVisible();

      // Verify all load times are under 5 seconds
      const allLoadTimes = [initialLoadTime, dashboardLoadTime, dailyLoadTime, weeklyLoadTime, monthlyLoadTime];
      const maxLoadTime = Math.max(...allLoadTimes);
      expect(maxLoadTime).toBeLessThan(5000);

      await context.close();
    });
  });
});