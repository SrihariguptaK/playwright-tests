import { test, expect } from '@playwright/test';

test.describe('Story-19: Responsive Schedule Interface for Mobile Devices', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const VALID_USERNAME = 'employee@company.com';
  const VALID_PASSWORD = 'Password123!';

  test('Validate responsive layout on various screen sizes - Desktop', async ({ page }) => {
    // Set desktop viewport
    await page.setViewportSize({ width: 1920, height: 1080 });
    
    // Action: Access schedule interface on desktop browser
    await page.goto(`${BASE_URL}/login`);
    
    // Log in with valid employee credentials
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Wait for navigation to schedule page
    await page.waitForURL('**/schedule');
    
    // Expected Result: Layout displays correctly with full features
    await expect(page.locator('[data-testid="schedule-grid"]')).toBeVisible();
    await expect(page.locator('[data-testid="navigation-controls"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-filters"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-search"]')).toBeVisible();
    
    // Verify all interactive elements are clickable and properly sized
    const nextDayButton = page.locator('[data-testid="next-day-button"]');
    await expect(nextDayButton).toBeVisible();
    await expect(nextDayButton).toBeEnabled();
    
    const filterDropdown = page.locator('[data-testid="filter-dropdown"]');
    await expect(filterDropdown).toBeVisible();
    await expect(filterDropdown).toBeEnabled();
    
    // Verify desktop layout has proper spacing
    const scheduleGrid = page.locator('[data-testid="schedule-grid"]');
    const boundingBox = await scheduleGrid.boundingBox();
    expect(boundingBox?.width).toBeGreaterThan(800);
  });

  test('Validate responsive layout on various screen sizes - Tablet', async ({ page }) => {
    // Set tablet viewport (iPad dimensions)
    await page.setViewportSize({ width: 768, height: 1024 });
    
    // Action: Access schedule interface on tablet browser
    await page.goto(`${BASE_URL}/login`);
    
    // Log in with valid employee credentials
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Wait for navigation to schedule page
    await page.waitForURL('**/schedule');
    
    // Expected Result: Layout adjusts appropriately with usable controls
    await expect(page.locator('[data-testid="schedule-grid"]')).toBeVisible();
    await expect(page.locator('[data-testid="navigation-controls"]')).toBeVisible();
    
    // Verify text is readable without zooming
    const scheduleTitle = page.locator('[data-testid="schedule-title"]');
    await expect(scheduleTitle).toBeVisible();
    const fontSize = await scheduleTitle.evaluate((el) => window.getComputedStyle(el).fontSize);
    expect(parseInt(fontSize)).toBeGreaterThanOrEqual(14);
    
    // Test scrolling behavior on tablet view
    await page.evaluate(() => window.scrollTo(0, 200));
    await page.waitForTimeout(500);
    const scrollPosition = await page.evaluate(() => window.scrollY);
    expect(scrollPosition).toBeGreaterThan(0);
    
    // Verify controls are accessible and properly sized for tablet
    const nextDayButton = page.locator('[data-testid="next-day-button"]');
    const buttonBox = await nextDayButton.boundingBox();
    expect(buttonBox?.height).toBeGreaterThanOrEqual(40);
  });

  test('Validate responsive layout on various screen sizes - Mobile Portrait', async ({ page }) => {
    // Set mobile viewport (iPhone dimensions - portrait)
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Action: Access schedule interface on mobile device
    await page.goto(`${BASE_URL}/login`);
    
    // Log in with valid employee credentials
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Wait for navigation to schedule page
    await page.waitForURL('**/schedule');
    
    // Expected Result: Mobile layout is optimized for small screens
    await expect(page.locator('[data-testid="schedule-grid"]')).toBeVisible();
    
    // Verify large touch targets
    const nextDayButton = page.locator('[data-testid="next-day-button"]');
    const buttonBox = await nextDayButton.boundingBox();
    expect(buttonBox?.height).toBeGreaterThanOrEqual(44); // iOS minimum touch target
    expect(buttonBox?.width).toBeGreaterThanOrEqual(44);
    
    // Verify text is readable without zooming
    const scheduleTitle = page.locator('[data-testid="schedule-title"]');
    const fontSize = await scheduleTitle.evaluate((el) => window.getComputedStyle(el).fontSize);
    expect(parseInt(fontSize)).toBeGreaterThanOrEqual(14);
    
    // Verify mobile-optimized layout (stacked elements)
    const navigationControls = page.locator('[data-testid="navigation-controls"]');
    await expect(navigationControls).toBeVisible();
    
    // Verify page load time
    const performanceTiming = await page.evaluate(() => {
      const perfData = window.performance.timing;
      return perfData.loadEventEnd - perfData.navigationStart;
    });
    expect(performanceTiming).toBeLessThan(3000); // Under 3 seconds
  });

  test('Validate responsive layout on various screen sizes - Mobile Landscape', async ({ page }) => {
    // Set mobile viewport (iPhone dimensions - landscape)
    await page.setViewportSize({ width: 667, height: 375 });
    
    // Action: Access schedule interface on mobile device in landscape
    await page.goto(`${BASE_URL}/login`);
    
    // Log in with valid employee credentials
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    
    // Wait for navigation to schedule page
    await page.waitForURL('**/schedule');
    
    // Expected Result: Layout adapts to landscape orientation
    await expect(page.locator('[data-testid="schedule-grid"]')).toBeVisible();
    await expect(page.locator('[data-testid="navigation-controls"]')).toBeVisible();
    
    // Verify content is visible and usable in landscape
    const scheduleGrid = page.locator('[data-testid="schedule-grid"]');
    const gridBox = await scheduleGrid.boundingBox();
    expect(gridBox?.width).toBeGreaterThan(0);
    expect(gridBox?.height).toBeGreaterThan(0);
  });

  test('Test touch interaction on mobile devices - Navigation', async ({ page }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Navigate to schedule interface and log in
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('**/schedule');
    
    // Verify the schedule interface is loaded and displayed
    await expect(page.locator('[data-testid="schedule-grid"]')).toBeVisible();
    
    // Tap on the 'Next Day' navigation button using touch
    const nextDayButton = page.locator('[data-testid="next-day-button"]');
    await nextDayButton.tap();
    await page.waitForTimeout(300);
    // Expected Result: Navigation works smoothly without errors
    await expect(page.locator('[data-testid="schedule-grid"]')).toBeVisible();
    
    // Tap on the 'Previous Day' navigation button
    const prevDayButton = page.locator('[data-testid="prev-day-button"]');
    await prevDayButton.tap();
    await page.waitForTimeout(300);
    await expect(page.locator('[data-testid="schedule-grid"]')).toBeVisible();
    
    // Tap on the 'Next Week' navigation button
    const nextWeekButton = page.locator('[data-testid="next-week-button"]');
    await nextWeekButton.tap();
    await page.waitForTimeout(300);
    await expect(page.locator('[data-testid="schedule-grid"]')).toBeVisible();
    
    // Tap on the 'Previous Week' navigation button
    const prevWeekButton = page.locator('[data-testid="prev-week-button"]');
    await prevWeekButton.tap();
    await page.waitForTimeout(300);
    await expect(page.locator('[data-testid="schedule-grid"]')).toBeVisible();
  });

  test('Test touch interaction on mobile devices - Shift Selection and Filters', async ({ page }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Navigate to schedule interface and log in
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('**/schedule');
    
    // Tap on a specific shift entry in the schedule
    const firstShift = page.locator('[data-testid="shift-entry"]').first();
    await firstShift.tap();
    await page.waitForTimeout(300);
    // Expected Result: Shift selection works without errors
    await expect(page.locator('[data-testid="shift-details"]')).toBeVisible();
    
    // Close shift details if modal opened
    const closeButton = page.locator('[data-testid="close-shift-details"]');
    if (await closeButton.isVisible()) {
      await closeButton.tap();
      await page.waitForTimeout(300);
    }
    
    // Tap on the filter button or icon
    const filterButton = page.locator('[data-testid="filter-button"]');
    await filterButton.tap();
    await page.waitForTimeout(300);
    await expect(page.locator('[data-testid="filter-options"]')).toBeVisible();
    
    // Tap to select a filter option (e.g., shift type)
    const shiftTypeFilter = page.locator('[data-testid="filter-shift-type"]');
    await shiftTypeFilter.tap();
    await page.waitForTimeout(300);
    // Expected Result: Filter selection works smoothly
    await expect(page.locator('[data-testid="schedule-grid"]')).toBeVisible();
  });

  test('Test touch interaction on mobile devices - Gestures and Scrolling', async ({ page }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Navigate to schedule interface and log in
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('**/schedule');
    
    // Perform a swipe gesture left or right on the schedule (if supported)
    const scheduleGrid = page.locator('[data-testid="schedule-grid"]');
    const boundingBox = await scheduleGrid.boundingBox();
    
    if (boundingBox) {
      // Swipe right to left
      await page.touchscreen.tap(boundingBox.x + boundingBox.width - 50, boundingBox.y + 50);
      await page.touchscreen.tap(boundingBox.x + 50, boundingBox.y + 50);
      await page.waitForTimeout(300);
    }
    
    // Perform a vertical scroll gesture to view more schedule entries
    await page.evaluate(() => window.scrollTo(0, 300));
    await page.waitForTimeout(300);
    const scrollY = await page.evaluate(() => window.scrollY);
    expect(scrollY).toBeGreaterThan(0);
    
    // Tap on any dropdown menus or selection controls
    const dropdown = page.locator('[data-testid="filter-dropdown"]');
    if (await dropdown.isVisible()) {
      await dropdown.tap();
      await page.waitForTimeout(300);
      await expect(page.locator('[data-testid="dropdown-options"]')).toBeVisible();
    }
  });

  test('Test touch interaction on mobile devices - Rapid Taps and Stress Test', async ({ page }) => {
    // Set mobile viewport
    await page.setViewportSize({ width: 375, height: 667 });
    
    // Navigate to schedule interface and log in
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', VALID_USERNAME);
    await page.fill('[data-testid="password-input"]', VALID_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await page.waitForURL('**/schedule');
    
    // Rapidly tap on navigation buttons multiple times
    const nextDayButton = page.locator('[data-testid="next-day-button"]');
    
    for (let i = 0; i < 5; i++) {
      await nextDayButton.tap();
      await page.waitForTimeout(100);
    }
    
    // Expected Result: Navigation responds smoothly without errors or crashes
    await expect(page.locator('[data-testid="schedule-grid"]')).toBeVisible();
    
    // Verify no error messages appeared
    const errorMessage = page.locator('[data-testid="error-message"]');
    await expect(errorMessage).not.toBeVisible();
    
    // Test touch interactions with different areas (simulating thumb usage)
    const prevWeekButton = page.locator('[data-testid="prev-week-button"]');
    const buttonBox = await prevWeekButton.boundingBox();
    
    if (buttonBox) {
      // Tap at different points within the button (simulating different finger sizes)
      await page.touchscreen.tap(buttonBox.x + 10, buttonBox.y + 10);
      await page.waitForTimeout(200);
      await page.touchscreen.tap(buttonBox.x + buttonBox.width - 10, buttonBox.y + buttonBox.height - 10);
      await page.waitForTimeout(200);
    }
    
    // Expected Result: All touch interactions work smoothly
    await expect(page.locator('[data-testid="schedule-grid"]')).toBeVisible();
  });
});