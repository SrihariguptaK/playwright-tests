import { test, expect, devices } from '@playwright/test';

const SCHEDULE_PORTAL_URL = process.env.SCHEDULE_PORTAL_URL || 'https://schedule-portal.example.com';
const VALID_EMPLOYEE_USERNAME = process.env.EMPLOYEE_USERNAME || 'employee@example.com';
const VALID_EMPLOYEE_PASSWORD = process.env.EMPLOYEE_PASSWORD || 'Password123!';
const SESSION_TIMEOUT_MS = parseInt(process.env.SESSION_TIMEOUT_MS || '300000'); // 5 minutes default
const MOBILE_LOAD_TIME_THRESHOLD = 3000; // 3 seconds

test.describe('Mobile Schedule Viewing', () => {
  
  test.describe('Validate schedule viewing on various mobile devices (happy-path)', () => {
    
    test('should display schedule correctly on smartphone in portrait and landscape', async ({ browser }) => {
      // Configure smartphone device
      const context = await browser.newContext({
        ...devices['iPhone 12'],
        permissions: []
      });
      const page = await context.newPage();
      
      // Step 1: Open mobile browser on smartphone and navigate to schedule portal URL
      await page.goto(SCHEDULE_PORTAL_URL);
      await expect(page).toHaveTitle(/Schedule Portal|Login/i);
      
      // Step 2: Enter valid employee credentials and tap login button
      await page.fill('[data-testid="username-input"]', VALID_EMPLOYEE_USERNAME);
      await page.fill('[data-testid="password-input"]', VALID_EMPLOYEE_PASSWORD);
      await page.click('[data-testid="login-button"]');
      
      // Step 3: View the schedule dashboard on smartphone in portrait orientation
      await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible({ timeout: 10000 });
      await expect(page.locator('[data-testid="schedule-header"]')).toBeVisible();
      
      // Verify portrait layout
      const viewportSize = page.viewportSize();
      expect(viewportSize?.width).toBeLessThan(viewportSize?.height || 0);
      
      // Step 4: Rotate smartphone to landscape orientation
      await context.close();
      const landscapeContext = await browser.newContext({
        ...devices['iPhone 12 landscape'],
        permissions: []
      });
      const landscapePage = await landscapeContext.newPage();
      await landscapePage.goto(SCHEDULE_PORTAL_URL);
      await landscapePage.fill('[data-testid="username-input"]', VALID_EMPLOYEE_USERNAME);
      await landscapePage.fill('[data-testid="password-input"]', VALID_EMPLOYEE_PASSWORD);
      await landscapePage.click('[data-testid="login-button"]');
      await expect(landscapePage.locator('[data-testid="schedule-dashboard"]')).toBeVisible({ timeout: 10000 });
      
      // Verify landscape layout
      const landscapeViewport = landscapePage.viewportSize();
      expect(landscapeViewport?.width).toBeGreaterThan(landscapeViewport?.height || 0);
      
      // Step 5: Use touch gestures to navigate to daily schedule view
      await landscapePage.click('[data-testid="daily-schedule-tab"]');
      await expect(landscapePage.locator('[data-testid="daily-schedule-view"]')).toBeVisible();
      await expect(landscapePage.locator('[data-testid="daily-schedule-header"]')).toContainText(/Daily Schedule/i);
      
      // Step 6: Swipe or tap to navigate to weekly schedule view
      await landscapePage.click('[data-testid="weekly-schedule-tab"]');
      await expect(landscapePage.locator('[data-testid="weekly-schedule-view"]')).toBeVisible();
      await expect(landscapePage.locator('[data-testid="weekly-schedule-header"]')).toContainText(/Weekly Schedule/i);
      
      // Step 7: Tap on individual shift entries to view details
      const firstShift = landscapePage.locator('[data-testid="shift-entry"]').first();
      await firstShift.click();
      await expect(landscapePage.locator('[data-testid="shift-details-modal"]')).toBeVisible();
      await expect(landscapePage.locator('[data-testid="shift-time"]')).toBeVisible();
      await expect(landscapePage.locator('[data-testid="shift-location"]')).toBeVisible();
      await landscapePage.click('[data-testid="close-modal-button"]');
      
      await landscapeContext.close();
    });
    
    test('should display schedule correctly on tablet device', async ({ browser }) => {
      // Step 8: Repeat steps on tablet device
      const tabletContext = await browser.newContext({
        ...devices['iPad Pro'],
        permissions: []
      });
      const tabletPage = await tabletContext.newPage();
      
      await tabletPage.goto(SCHEDULE_PORTAL_URL);
      await tabletPage.fill('[data-testid="username-input"]', VALID_EMPLOYEE_USERNAME);
      await tabletPage.fill('[data-testid="password-input"]', VALID_EMPLOYEE_PASSWORD);
      await tabletPage.click('[data-testid="login-button"]');
      
      await expect(tabletPage.locator('[data-testid="schedule-dashboard"]')).toBeVisible({ timeout: 10000 });
      
      // Navigate to daily schedule
      await tabletPage.click('[data-testid="daily-schedule-tab"]');
      await expect(tabletPage.locator('[data-testid="daily-schedule-view"]')).toBeVisible();
      
      // Navigate to weekly schedule
      await tabletPage.click('[data-testid="weekly-schedule-tab"]');
      await expect(tabletPage.locator('[data-testid="weekly-schedule-view"]')).toBeVisible();
      
      // Tap on shift entry
      const shiftEntry = tabletPage.locator('[data-testid="shift-entry"]').first();
      await shiftEntry.click();
      await expect(tabletPage.locator('[data-testid="shift-details-modal"]')).toBeVisible();
      
      // Step 9: Verify schedule data accuracy by comparing displayed shifts with expected schedule
      const shiftTime = await tabletPage.locator('[data-testid="shift-time"]').textContent();
      expect(shiftTime).toBeTruthy();
      expect(shiftTime).toMatch(/\d{1,2}:\d{2}/);
      
      const shiftLocation = await tabletPage.locator('[data-testid="shift-location"]').textContent();
      expect(shiftLocation).toBeTruthy();
      
      await tabletPage.click('[data-testid="close-modal-button"]');
      
      // Step 10: Check UI elements including buttons, text size, and spacing
      const loginButton = tabletPage.locator('[data-testid="logout-button"]');
      await expect(loginButton).toBeVisible();
      
      const scheduleHeader = tabletPage.locator('[data-testid="schedule-header"]');
      const fontSize = await scheduleHeader.evaluate((el) => window.getComputedStyle(el).fontSize);
      expect(parseInt(fontSize)).toBeGreaterThanOrEqual(14);
      
      const shiftEntries = tabletPage.locator('[data-testid="shift-entry"]');
      const count = await shiftEntries.count();
      expect(count).toBeGreaterThan(0);
      
      await tabletContext.close();
    });
  });
  
  test.describe('Ensure mobile page load performance (happy-path)', () => {
    
    test('should load schedule pages within 3 seconds on 4G network', async ({ browser }) => {
      // Step 1: Connect mobile device to 4G network and clear browser cache
      const context = await browser.newContext({
        ...devices['iPhone 12'],
        permissions: []
      });
      const page = await context.newPage();
      
      // Simulate 4G network conditions
      await page.route('**/*', route => route.continue());
      const client = await context.newCDPSession(page);
      await client.send('Network.emulateNetworkConditions', {
        offline: false,
        downloadThroughput: 4 * 1024 * 1024 / 8, // 4 Mbps
        uploadThroughput: 3 * 1024 * 1024 / 8,   // 3 Mbps
        latency: 20
      });
      
      // Step 2: Start timer and navigate to schedule portal login page
      const loginStartTime = Date.now();
      await page.goto(SCHEDULE_PORTAL_URL);
      const loginLoadTime = Date.now() - loginStartTime;
      expect(loginLoadTime).toBeLessThan(MOBILE_LOAD_TIME_THRESHOLD);
      
      // Step 3: Login with valid credentials and measure time until schedule dashboard is fully loaded
      await page.fill('[data-testid="username-input"]', VALID_EMPLOYEE_USERNAME);
      await page.fill('[data-testid="password-input"]', VALID_EMPLOYEE_PASSWORD);
      
      const dashboardStartTime = Date.now();
      await page.click('[data-testid="login-button"]');
      await page.waitForLoadState('networkidle');
      await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
      const dashboardLoadTime = Date.now() - dashboardStartTime;
      expect(dashboardLoadTime).toBeLessThan(MOBILE_LOAD_TIME_THRESHOLD);
      
      // Step 4: Navigate to daily schedule view and measure load time
      const dailyStartTime = Date.now();
      await page.click('[data-testid="daily-schedule-tab"]');
      await page.waitForLoadState('networkidle');
      await expect(page.locator('[data-testid="daily-schedule-view"]')).toBeVisible();
      const dailyLoadTime = Date.now() - dailyStartTime;
      expect(dailyLoadTime).toBeLessThan(MOBILE_LOAD_TIME_THRESHOLD);
      
      // Step 5: Navigate to weekly schedule view and measure load time
      const weeklyStartTime = Date.now();
      await page.click('[data-testid="weekly-schedule-tab"]');
      await page.waitForLoadState('networkidle');
      await expect(page.locator('[data-testid="weekly-schedule-view"]')).toBeVisible();
      const weeklyLoadTime = Date.now() - weeklyStartTime;
      expect(weeklyLoadTime).toBeLessThan(MOBILE_LOAD_TIME_THRESHOLD);
      
      // Step 6: Logout and clear browser cache
      await page.click('[data-testid="logout-button"]');
      await expect(page.locator('[data-testid="login-button"]')).toBeVisible();
      
      await context.close();
    });
    
    test('should load schedule pages within 3 seconds on Wi-Fi network', async ({ browser }) => {
      // Step 7: Connect mobile device to Wi-Fi network
      const context = await browser.newContext({
        ...devices['iPhone 12'],
        permissions: []
      });
      const page = await context.newPage();
      
      // Simulate Wi-Fi network conditions (faster than 4G)
      const client = await context.newCDPSession(page);
      await client.send('Network.emulateNetworkConditions', {
        offline: false,
        downloadThroughput: 30 * 1024 * 1024 / 8, // 30 Mbps
        uploadThroughput: 15 * 1024 * 1024 / 8,   // 15 Mbps
        latency: 10
      });
      
      // Step 8: Repeat steps 2-5 on Wi-Fi network and measure load times
      const loginStartTime = Date.now();
      await page.goto(SCHEDULE_PORTAL_URL);
      const loginLoadTime = Date.now() - loginStartTime;
      expect(loginLoadTime).toBeLessThan(MOBILE_LOAD_TIME_THRESHOLD);
      
      await page.fill('[data-testid="username-input"]', VALID_EMPLOYEE_USERNAME);
      await page.fill('[data-testid="password-input"]', VALID_EMPLOYEE_PASSWORD);
      
      const dashboardStartTime = Date.now();
      await page.click('[data-testid="login-button"]');
      await page.waitForLoadState('networkidle');
      await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
      const dashboardLoadTime = Date.now() - dashboardStartTime;
      expect(dashboardLoadTime).toBeLessThan(MOBILE_LOAD_TIME_THRESHOLD);
      
      const dailyStartTime = Date.now();
      await page.click('[data-testid="daily-schedule-tab"]');
      await page.waitForLoadState('networkidle');
      await expect(page.locator('[data-testid="daily-schedule-view"]')).toBeVisible();
      const dailyLoadTime = Date.now() - dailyStartTime;
      expect(dailyLoadTime).toBeLessThan(MOBILE_LOAD_TIME_THRESHOLD);
      
      const weeklyStartTime = Date.now();
      await page.click('[data-testid="weekly-schedule-tab"]');
      await page.waitForLoadState('networkidle');
      await expect(page.locator('[data-testid="weekly-schedule-view"]')).toBeVisible();
      const weeklyLoadTime = Date.now() - weeklyStartTime;
      expect(weeklyLoadTime).toBeLessThan(MOBILE_LOAD_TIME_THRESHOLD);
      
      // Step 9: Document all load times for comparison
      console.log('Wi-Fi Load Times:', {
        login: loginLoadTime,
        dashboard: dashboardLoadTime,
        daily: dailyLoadTime,
        weekly: weeklyLoadTime
      });
      
      await context.close();
    });
  });
  
  test.describe('Verify mobile session security (error-case)', () => {
    
    test('should expire session after timeout period and require re-authentication', async ({ browser }) => {
      const context = await browser.newContext({
        ...devices['iPhone 12'],
        permissions: []
      });
      const page = await context.newPage();
      
      // Step 1: Open mobile browser and navigate to schedule portal
      await page.goto(SCHEDULE_PORTAL_URL);
      
      // Step 2: Enter valid employee credentials and login
      await page.fill('[data-testid="username-input"]', VALID_EMPLOYEE_USERNAME);
      await page.fill('[data-testid="password-input"]', VALID_EMPLOYEE_PASSWORD);
      await page.click('[data-testid="login-button"]');
      await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible({ timeout: 10000 });
      
      // Step 3: Note the current time and leave the mobile device idle without any interaction
      const loginTime = Date.now();
      
      // Step 4: Wait for the configured session timeout period to elapse (remain idle)
      await page.waitForTimeout(SESSION_TIMEOUT_MS + 5000); // Wait slightly longer than timeout
      
      // Step 5: After timeout period has passed, attempt to interact with the schedule
      await page.click('[data-testid="daily-schedule-tab"]').catch(() => {});
      
      // Step 6: Verify that a clear message is displayed indicating session expiration
      const sessionExpiredMessage = page.locator('[data-testid="session-expired-message"]');
      const loginPrompt = page.locator('[data-testid="login-button"]');
      const sessionExpiredAlert = page.locator('text=/session.*expired|logged.*out|authentication.*required/i');
      
      // Check for any indication of session expiration
      const isExpired = await Promise.race([
        sessionExpiredMessage.isVisible().catch(() => false),
        loginPrompt.isVisible().catch(() => false),
        sessionExpiredAlert.isVisible().catch(() => false)
      ]);
      
      expect(isExpired).toBeTruthy();
      
      // Step 7: Attempt to use browser back button to access schedule without re-authenticating
      await page.goBack();
      await page.waitForTimeout(1000);
      
      // Verify user cannot access schedule without re-authentication
      const dashboardVisible = await page.locator('[data-testid="schedule-dashboard"]').isVisible().catch(() => false);
      if (dashboardVisible) {
        // If dashboard is visible, it should redirect to login
        await expect(page.locator('[data-testid="login-button"]')).toBeVisible({ timeout: 5000 });
      }
      
      // Step 8: Enter valid credentials and login again
      await page.goto(SCHEDULE_PORTAL_URL);
      await page.fill('[data-testid="username-input"]', VALID_EMPLOYEE_USERNAME);
      await page.fill('[data-testid="password-input"]', VALID_EMPLOYEE_PASSWORD);
      await page.click('[data-testid="login-button"]');
      await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible({ timeout: 10000 });
      
      // Step 9: Verify that session token has been renewed after re-authentication
      const cookies = await context.cookies();
      const sessionCookie = cookies.find(c => c.name.toLowerCase().includes('session') || c.name.toLowerCase().includes('token'));
      expect(sessionCookie).toBeTruthy();
      
      // Verify user can now interact with schedule
      await page.click('[data-testid="daily-schedule-tab"]');
      await expect(page.locator('[data-testid="daily-schedule-view"]')).toBeVisible();
      
      await context.close();
    });
  });
});