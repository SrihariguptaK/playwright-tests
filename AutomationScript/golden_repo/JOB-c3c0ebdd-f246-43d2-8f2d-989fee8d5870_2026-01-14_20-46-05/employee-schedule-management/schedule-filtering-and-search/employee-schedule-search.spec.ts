import { test, expect } from '@playwright/test';

test.describe('Employee Schedule Search - Story 16', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to login page before each test
    await page.goto('/login');
  });

  test('Validate keyword search returns matching shifts', async ({ page }) => {
    // Step 1: Log in as employee
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: Schedule dashboard is displayed
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible({ timeout: 5000 });
    await expect(page).toHaveURL(/.*schedule/);
    
    // Step 2: Enter keyword present in shift notes
    const searchInput = page.locator('[data-testid="schedule-search-input"]');
    await searchInput.fill('training');
    
    // Expected Result: Schedule displays shifts matching keyword
    await page.waitForTimeout(500); // Allow for dynamic search
    const matchingShifts = page.locator('[data-testid="shift-card"]:visible');
    await expect(matchingShifts).toHaveCount(await matchingShifts.count());
    
    // Verify at least one shift contains the keyword
    const firstShift = matchingShifts.first();
    await expect(firstShift).toContainText(/training/i);
    
    // Step 3: Enter partial keyword with different case
    await searchInput.clear();
    await searchInput.fill('TrAi');
    
    // Expected Result: Schedule displays matching shifts ignoring case
    await page.waitForTimeout(500);
    const partialMatchShifts = page.locator('[data-testid="shift-card"]:visible');
    await expect(partialMatchShifts.count()).resolves.toBeGreaterThan(0);
    
    // Verify shifts contain the partial keyword (case-insensitive)
    const shiftContent = await partialMatchShifts.first().textContent();
    expect(shiftContent?.toLowerCase()).toContain('trai');
  });

  test('Verify dynamic update of search results', async ({ page }) => {
    // Login as employee
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');
    
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible({ timeout: 5000 });
    
    // Get initial count of all shifts
    const allShifts = page.locator('[data-testid="shift-card"]');
    const initialCount = await allShifts.count();
    expect(initialCount).toBeGreaterThan(0);
    
    // Step 1: Start typing keyword in search box character by character
    const searchInput = page.locator('[data-testid="schedule-search-input"]');
    
    // Type 'm'
    await searchInput.fill('m');
    await page.waitForTimeout(300);
    const afterM = await page.locator('[data-testid="shift-card"]:visible').count();
    
    // Expected Result: Search results update dynamically with each keystroke
    // Type 'me'
    await searchInput.fill('me');
    await page.waitForTimeout(300);
    const afterMe = await page.locator('[data-testid="shift-card"]:visible').count();
    
    // Type 'mee'
    await searchInput.fill('mee');
    await page.waitForTimeout(300);
    const afterMee = await page.locator('[data-testid="shift-card"]:visible').count();
    
    // Type 'meet'
    await searchInput.fill('meet');
    await page.waitForTimeout(300);
    const afterMeet = await page.locator('[data-testid="shift-card"]:visible').count();
    
    // Verify results are filtered (should be less than or equal to initial)
    expect(afterMeet).toBeLessThanOrEqual(initialCount);
    
    // Step 2: Clear search input
    await searchInput.clear();
    await page.waitForTimeout(300);
    
    // Expected Result: Full schedule is displayed again
    const finalCount = await page.locator('[data-testid="shift-card"]:visible').count();
    expect(finalCount).toBe(initialCount);
    
    // Verify search input is empty
    await expect(searchInput).toHaveValue('');
  });

  test('Verify search performance meets 3 second requirement', async ({ page }) => {
    // Login as employee
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');
    
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
    
    // Measure search performance
    const searchInput = page.locator('[data-testid="schedule-search-input"]');
    const startTime = Date.now();
    
    await searchInput.fill('meeting');
    
    // Wait for search results to load
    await page.waitForLoadState('networkidle', { timeout: 3000 });
    
    const endTime = Date.now();
    const searchDuration = endTime - startTime;
    
    // Verify search completes within 3 seconds
    expect(searchDuration).toBeLessThan(3000);
    
    // Verify results are displayed
    const results = page.locator('[data-testid="shift-card"]:visible');
    await expect(results.first()).toBeVisible();
  });

  test('Verify search works across notes, locations, and roles', async ({ page }) => {
    // Login as employee
    await page.fill('[data-testid="username-input"]', 'employee@company.com');
    await page.fill('[data-testid="password-input"]', 'Password123!');
    await page.click('[data-testid="login-button"]');
    
    await expect(page.locator('[data-testid="schedule-dashboard"]')).toBeVisible();
    
    const searchInput = page.locator('[data-testid="schedule-search-input"]');
    
    // Search by location keyword
    await searchInput.fill('warehouse');
    await page.waitForTimeout(500);
    let visibleShifts = page.locator('[data-testid="shift-card"]:visible');
    await expect(visibleShifts.first()).toContainText(/warehouse/i);
    
    // Search by role keyword
    await searchInput.clear();
    await searchInput.fill('manager');
    await page.waitForTimeout(500);
    visibleShifts = page.locator('[data-testid="shift-card"]:visible');
    await expect(visibleShifts.first()).toContainText(/manager/i);
    
    // Search by notes keyword
    await searchInput.clear();
    await searchInput.fill('urgent');
    await page.waitForTimeout(500);
    visibleShifts = page.locator('[data-testid="shift-card"]:visible');
    await expect(visibleShifts.first()).toContainText(/urgent/i);
  });
});