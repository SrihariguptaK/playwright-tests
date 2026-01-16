import { test, expect } from '@playwright/test';

test.describe('Schedule Interface Performance', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const SCHEDULE_PAGE_LOAD_THRESHOLD = 3000; // 3 seconds
  const API_RESPONSE_THRESHOLD = 2000; // 2 seconds

  test.beforeEach(async ({ page }) => {
    // Login as employee before each test
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate schedule page load times under normal conditions', async ({ page }) => {
    // Start performance timer
    const startTime = Date.now();

    // Employee navigates to the schedule page
    await page.click('[data-testid="schedule-menu-link"]');
    
    // Wait for schedule page to load completely
    await page.waitForSelector('[data-testid="schedule-container"]', { state: 'visible' });
    await page.waitForLoadState('networkidle');
    
    const loadTime = Date.now() - startTime;
    
    // Verify page loads within 3 seconds
    expect(loadTime).toBeLessThan(SCHEDULE_PAGE_LOAD_THRESHOLD);
    
    // Verify all schedule elements are rendered correctly
    await expect(page.locator('[data-testid="schedule-dates"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-shifts"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-assignments"]')).toBeVisible();
    
    // Employee interacts with schedule view - scrolling
    const scheduleContainer = page.locator('[data-testid="schedule-container"]');
    await scheduleContainer.evaluate(el => el.scrollTop = 200);
    
    // No noticeable delays - verify content is still visible
    await expect(page.locator('[data-testid="schedule-shifts"]')).toBeVisible();
    
    // Click on a date
    const interactionStartTime = Date.now();
    await page.click('[data-testid="schedule-date-cell"]:first-child');
    await page.waitForLoadState('networkidle');
    const interactionTime = Date.now() - interactionStartTime;
    
    // Verify no noticeable lag (under 1 second for interaction)
    expect(interactionTime).toBeLessThan(1000);
    
    // Switch views
    await page.click('[data-testid="schedule-view-toggle"]');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
    
    // Navigate to next week
    await page.click('[data-testid="schedule-next-week-button"]');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
    
    // Navigate to previous week
    await page.click('[data-testid="schedule-previous-week-button"]');
    await page.waitForLoadState('networkidle');
    await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
  });

  test('Verify backend API response times', async ({ page, request }) => {
    // Navigate to schedule page to get valid session
    await page.goto(`${BASE_URL}/schedule`);
    await page.waitForLoadState('networkidle');
    
    // Get authentication cookies/tokens from the page context
    const cookies = await page.context().cookies();
    
    const responseTimes: number[] = [];
    
    // Repeat API request 5 times to ensure consistent performance
    for (let i = 0; i < 5; i++) {
      const startTime = Date.now();
      
      // Send schedule data request to backend API endpoint
      const response = await request.get(`${BASE_URL}/api/schedule`, {
        headers: {
          'Cookie': cookies.map(c => `${c.name}=${c.value}`).join('; ')
        }
      });
      
      const responseTime = Date.now() - startTime;
      responseTimes.push(responseTime);
      
      // Verify response received within 2 seconds
      expect(responseTime).toBeLessThan(API_RESPONSE_THRESHOLD);
      
      // Verify the response contains complete and valid schedule data
      expect(response.ok()).toBeTruthy();
      const responseData = await response.json();
      expect(responseData).toHaveProperty('schedules');
      expect(Array.isArray(responseData.schedules)).toBeTruthy();
      expect(responseData.schedules.length).toBeGreaterThan(0);
      
      // Verify schedule data structure
      const firstSchedule = responseData.schedules[0];
      expect(firstSchedule).toHaveProperty('date');
      expect(firstSchedule).toHaveProperty('shift');
      expect(firstSchedule).toHaveProperty('assignment');
      
      // Small delay between requests
      await page.waitForTimeout(100);
    }
    
    // Calculate average response time
    const avgResponseTime = responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length;
    console.log(`Average API response time: ${avgResponseTime}ms`);
    
    // Verify consistent performance (average should be under threshold)
    expect(avgResponseTime).toBeLessThan(API_RESPONSE_THRESHOLD);
  });

  test('Ensure system handles concurrent users without degradation', async ({ browser }) => {
    const CONCURRENT_USERS = 50;
    const responseTimes: number[] = [];
    const errors: string[] = [];
    
    // Create array of concurrent user sessions
    const userSessions = Array.from({ length: CONCURRENT_USERS }, (_, i) => i);
    
    // Simulate multiple concurrent employee requests
    const concurrentRequests = userSessions.map(async (userIndex) => {
      const context = await browser.newContext();
      const page = await context.newPage();
      
      try {
        // Login
        await page.goto(`${BASE_URL}/login`);
        await page.fill('[data-testid="username-input"]', `employee${userIndex}@company.com`);
        await page.fill('[data-testid="password-input"]', 'password123');
        await page.click('[data-testid="login-button"]');
        
        // Navigate to schedule page and measure load time
        const startTime = Date.now();
        await page.click('[data-testid="schedule-menu-link"]');
        await page.waitForSelector('[data-testid="schedule-container"]', { state: 'visible', timeout: 5000 });
        await page.waitForLoadState('networkidle');
        const loadTime = Date.now() - startTime;
        
        responseTimes.push(loadTime);
        
        // Verify page loaded successfully
        await expect(page.locator('[data-testid="schedule-container"]')).toBeVisible();
        
      } catch (error) {
        errors.push(`User ${userIndex}: ${error.message}`);
      } finally {
        await context.close();
      }
    });
    
    // Execute all concurrent requests
    await Promise.all(concurrentRequests);
    
    // Verify all requests processed within performance thresholds
    const successfulRequests = responseTimes.length;
    const failedRequests = errors.length;
    
    console.log(`Successful requests: ${successfulRequests}/${CONCURRENT_USERS}`);
    console.log(`Failed requests: ${failedRequests}`);
    
    // At least 95% success rate
    expect(successfulRequests).toBeGreaterThanOrEqual(CONCURRENT_USERS * 0.95);
    
    // Calculate performance metrics
    const avgLoadTime = responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length;
    const maxLoadTime = Math.max(...responseTimes);
    const minLoadTime = Math.min(...responseTimes);
    
    console.log(`Average load time: ${avgLoadTime}ms`);
    console.log(`Max load time: ${maxLoadTime}ms`);
    console.log(`Min load time: ${minLoadTime}ms`);
    
    // Verify average load time is within threshold
    expect(avgLoadTime).toBeLessThan(SCHEDULE_PAGE_LOAD_THRESHOLD);
    
    // Verify 95th percentile is within acceptable range (4 seconds with some tolerance)
    const sortedTimes = responseTimes.sort((a, b) => a - b);
    const p95Index = Math.floor(sortedTimes.length * 0.95);
    const p95LoadTime = sortedTimes[p95Index];
    
    console.log(`95th percentile load time: ${p95LoadTime}ms`);
    expect(p95LoadTime).toBeLessThan(4000);
    
    // Log any errors for debugging
    if (errors.length > 0) {
      console.log('Errors encountered:', errors);
    }
  });
});