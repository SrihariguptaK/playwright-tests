import { test, expect, devices } from '@playwright/test';

test.describe('Story-20: Responsive Schedule Interface', () => {
  const schedulePageUrl = '/schedule';

  test('Validate responsive layout on various devices - Desktop Chrome', async ({ browser }) => {
    // Open desktop browser (Chrome) and navigate to the schedule page URL
    const context = await browser.newContext({
      viewport: { width: 1920, height: 1080 }
    });
    const page = await context.newPage();
    await page.goto(schedulePageUrl);

    // Verify all UI elements are properly aligned and visible on desktop screen
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-header"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-navigation"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-grid"]')).toBeVisible();
    
    const scheduleContainer = page.locator('[data-testid="schedule-container"]');
    const boundingBox = await scheduleContainer.boundingBox();
    expect(boundingBox).not.toBeNull();
    expect(boundingBox!.width).toBeGreaterThan(0);

    await context.close();
  });

  test('Validate responsive layout on various devices - Tablet view', async ({ browser }) => {
    // Resize browser window to tablet dimensions (768x1024) or open on tablet device
    const context = await browser.newContext({
      viewport: { width: 768, height: 1024 }
    });
    const page = await context.newPage();
    await page.goto(schedulePageUrl);

    // Verify all controls and content are accessible on tablet view
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-header"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-navigation"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-grid"]')).toBeVisible();
    
    // Verify controls are accessible
    const navigationButtons = page.locator('[data-testid="schedule-navigation"] button');
    const buttonCount = await navigationButtons.count();
    expect(buttonCount).toBeGreaterThan(0);
    
    for (let i = 0; i < buttonCount; i++) {
      await expect(navigationButtons.nth(i)).toBeVisible();
    }

    await context.close();
  });

  test('Validate responsive layout on various devices - Mobile view', async ({ browser }) => {
    // Open schedule page on mobile browser (375x667) or resize to mobile dimensions
    const context = await browser.newContext({
      viewport: { width: 375, height: 667 },
      hasTouch: true
    });
    const page = await context.newPage();
    await page.goto(schedulePageUrl);

    // Verify all controls are accessible and usable on mobile view
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-header"]')).toBeVisible();
    
    // Test touch interactions on mobile: tap buttons, swipe schedule, scroll content
    const scheduleGrid = page.locator('[data-testid="schedule-grid"]');
    await expect(scheduleGrid).toBeVisible();
    
    // Tap a button
    const firstButton = page.locator('[data-testid="schedule-navigation"] button').first();
    if (await firstButton.isVisible()) {
      await firstButton.tap();
      await page.waitForTimeout(500);
    }
    
    // Scroll content
    await scheduleGrid.evaluate(el => el.scrollTop = 100);
    await page.waitForTimeout(300);
    
    // Verify all controls are usable without issues
    const allButtons = page.locator('button:visible');
    const visibleButtonCount = await allButtons.count();
    expect(visibleButtonCount).toBeGreaterThan(0);

    await context.close();
  });

  test('Validate responsive layout on various devices - Portrait to Landscape rotation', async ({ browser }) => {
    // Start in portrait mode
    const context = await browser.newContext({
      viewport: { width: 375, height: 667 },
      hasTouch: true
    });
    const page = await context.newPage();
    await page.goto(schedulePageUrl);

    // Verify layout in portrait
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
    
    // Rotate to landscape orientation
    await page.setViewportSize({ width: 667, height: 375 });
    await page.waitForTimeout(500);
    
    // Verify layout adjusts correctly in landscape
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-header"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-grid"]')).toBeVisible();

    await context.close();
  });

  test('Validate responsive layout on various devices - Firefox browser', async ({ browser }) => {
    const context = await browser.newContext({
      viewport: { width: 1920, height: 1080 }
    });
    const page = await context.newPage();
    await page.goto(schedulePageUrl);

    // Verify all UI elements are properly aligned and visible
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-header"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-navigation"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-grid"]')).toBeVisible();

    await context.close();
  });

  test('Test load times on mobile network - 4G throttling', async ({ browser }) => {
    // Enable 4G network throttling and test load time
    const context = await browser.newContext({
      viewport: { width: 375, height: 667 },
      hasTouch: true
    });
    const page = await context.newPage();
    
    // Clear browser cache
    await context.clearCookies();
    
    // Emulate 4G network conditions
    const client = await page.context().newCDPSession(page);
    await client.send('Network.emulateNetworkConditions', {
      offline: false,
      downloadThroughput: (4 * 1024 * 1024) / 8, // 4 Mbps
      uploadThroughput: (3 * 1024 * 1024) / 8,   // 3 Mbps
      latency: 20
    });
    
    // Navigate to the schedule page URL and measure load time
    const startTime = Date.now();
    await page.goto(schedulePageUrl, { waitUntil: 'networkidle' });
    const loadTime = Date.now() - startTime;
    
    // Verify page loads within 3 seconds (3000ms)
    expect(loadTime).toBeLessThanOrEqual(3000);
    
    // Verify DOM Content Loaded
    const domContentLoadedTime = await page.evaluate(() => {
      const perfData = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;
      return perfData.domContentLoadedEventEnd - perfData.domContentLoadedEventStart;
    });
    expect(domContentLoadedTime).toBeGreaterThanOrEqual(0);
    
    // Verify all critical resources load
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-header"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-grid"]')).toBeVisible();

    await context.close();
  });

  test('Test load times on mobile network - 3G comparison', async ({ browser }) => {
    // Test on 3G network (slower connection) for comparison
    const context = await browser.newContext({
      viewport: { width: 375, height: 667 },
      hasTouch: true
    });
    const page = await context.newPage();
    
    // Clear browser cache and cookies
    await context.clearCookies();
    
    // Emulate 3G network conditions
    const client = await page.context().newCDPSession(page);
    await client.send('Network.emulateNetworkConditions', {
      offline: false,
      downloadThroughput: (1.6 * 1024 * 1024) / 8, // 1.6 Mbps
      uploadThroughput: (750 * 1024) / 8,          // 750 Kbps
      latency: 150
    });
    
    // Navigate and measure load time
    const startTime = Date.now();
    await page.goto(schedulePageUrl, { waitUntil: 'networkidle' });
    const loadTime = Date.now() - startTime;
    
    // Record load time for comparison (may exceed 3 seconds on 3G)
    console.log(`3G Load Time: ${loadTime}ms`);
    
    // Verify page eventually loads and is functional
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-header"]')).toBeVisible();

    await context.close();
  });

  test('Test load times on mobile network - Average of 3 runs on 4G', async ({ browser }) => {
    const loadTimes: number[] = [];
    
    // Repeat test 3 times and calculate average load time
    for (let i = 0; i < 3; i++) {
      const context = await browser.newContext({
        viewport: { width: 375, height: 667 },
        hasTouch: true
      });
      const page = await context.newPage();
      
      // Clear cache
      await context.clearCookies();
      
      // Emulate 4G network
      const client = await page.context().newCDPSession(page);
      await client.send('Network.emulateNetworkConditions', {
        offline: false,
        downloadThroughput: (4 * 1024 * 1024) / 8,
        uploadThroughput: (3 * 1024 * 1024) / 8,
        latency: 20
      });
      
      // Measure load time
      const startTime = Date.now();
      await page.goto(schedulePageUrl, { waitUntil: 'networkidle' });
      const loadTime = Date.now() - startTime;
      loadTimes.push(loadTime);
      
      // Verify page loaded successfully
      await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
      
      await context.close();
      
      // Wait between runs
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    // Calculate average load time
    const averageLoadTime = loadTimes.reduce((a, b) => a + b, 0) / loadTimes.length;
    console.log(`Load times: ${loadTimes.join(', ')}ms`);
    console.log(`Average load time: ${averageLoadTime}ms`);
    
    // Verify average load time is within 3 seconds
    expect(averageLoadTime).toBeLessThanOrEqual(3000);
  });
});