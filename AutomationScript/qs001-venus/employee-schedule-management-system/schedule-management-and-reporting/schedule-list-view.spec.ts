import { test, expect } from '@playwright/test';

test.describe('Schedule List View - Story 9', () => {
  test.beforeEach(async ({ page }) => {
    // Login as Scheduler user before each test
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'scheduler@example.com');
    await page.fill('[data-testid="password-input"]', 'SchedulerPass123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="user-role"]')).toContainText('Scheduler');
  });

  test('Validate schedule list displays and filters correctly', async ({ page }) => {
    // Step 1: Navigate to schedule list page
    await page.click('[data-testid="schedules-menu"]');
    await page.click('[data-testid="list-view-option"]');
    
    // Expected Result: Schedule list is displayed
    await expect(page.locator('[data-testid="schedule-list-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="schedule-list-table"]')).toBeVisible();
    
    // Verify initial display without filters
    const initialRowCount = await page.locator('[data-testid="schedule-row"]').count();
    expect(initialRowCount).toBeGreaterThan(0);
    
    // Step 2: Apply filters for employee and date
    await page.click('[data-testid="employee-filter-dropdown"]');
    await page.click('[data-testid="employee-option-john-doe"]');
    await page.click('[data-testid="apply-filter-button"]');
    
    // Expected Result: List updates to show filtered schedules
    await page.waitForLoadState('networkidle');
    const filteredByEmployeeCount = await page.locator('[data-testid="schedule-row"]').count();
    expect(filteredByEmployeeCount).toBeLessThanOrEqual(initialRowCount);
    await expect(page.locator('[data-testid="schedule-row"]').first()).toContainText('John Doe');
    
    // Apply date filter
    await page.click('[data-testid="date-filter"]');
    await page.fill('[data-testid="date-range-start"]', '2024-01-01');
    await page.fill('[data-testid="date-range-end"]', '2024-01-31');
    await page.click('[data-testid="apply-filter-button"]');
    
    // Verify both filters are applied
    await page.waitForLoadState('networkidle');
    const filteredByBothCount = await page.locator('[data-testid="schedule-row"]').count();
    expect(filteredByBothCount).toBeLessThanOrEqual(filteredByEmployeeCount);
    
    // Step 3: Search schedules by keyword
    await page.fill('[data-testid="schedule-search-box"]', 'Morning Shift');
    await page.press('[data-testid="schedule-search-box"]', 'Enter');
    
    // Expected Result: Search results are accurate and relevant
    await page.waitForLoadState('networkidle');
    const searchResultsCount = await page.locator('[data-testid="schedule-row"]').count();
    const displayedCount = await page.locator('[data-testid="results-count"]').textContent();
    expect(displayedCount).toContain(searchResultsCount.toString());
    
    // Verify search results contain the keyword
    const firstResult = page.locator('[data-testid="schedule-row"]').first();
    await expect(firstResult).toContainText('Morning Shift');
  });

  test('Verify sorting and selection of schedules', async ({ page }) => {
    // Navigate to schedule list page
    await page.click('[data-testid="schedules-menu"]');
    await page.click('[data-testid="list-view-option"]');
    await expect(page.locator('[data-testid="schedule-list-table"]')).toBeVisible();
    
    // Step 1: Sort schedule list by date
    await page.click('[data-testid="date-column-header"]');
    
    // Expected Result: List is sorted correctly (ascending)
    await page.waitForLoadState('networkidle');
    const firstDateAsc = await page.locator('[data-testid="schedule-row"]').first().locator('[data-testid="schedule-date"]').textContent();
    const lastDateAsc = await page.locator('[data-testid="schedule-row"]').last().locator('[data-testid="schedule-date"]').textContent();
    
    // Click again to reverse sort order
    await page.click('[data-testid="date-column-header"]');
    await page.waitForLoadState('networkidle');
    
    const firstDateDesc = await page.locator('[data-testid="schedule-row"]').first().locator('[data-testid="schedule-date"]').textContent();
    const lastDateDesc = await page.locator('[data-testid="schedule-row"]').last().locator('[data-testid="schedule-date"]').textContent();
    
    // Verify sorting reversed
    expect(firstDateDesc).toBe(lastDateAsc);
    expect(lastDateDesc).toBe(firstDateAsc);
    
    // Sort by Employee Name
    await page.click('[data-testid="employee-name-column-header"]');
    await page.waitForLoadState('networkidle');
    
    const firstEmployeeName = await page.locator('[data-testid="schedule-row"]').first().locator('[data-testid="employee-name"]').textContent();
    const secondEmployeeName = await page.locator('[data-testid="schedule-row"]').nth(1).locator('[data-testid="employee-name"]').textContent();
    
    // Verify alphabetical sorting
    expect(firstEmployeeName?.localeCompare(secondEmployeeName || '')).toBeLessThanOrEqual(0);
    
    // Step 2: Select multiple schedules
    await page.click('[data-testid="schedule-row"]').first().locator('[data-testid="schedule-checkbox"]');
    await expect(page.locator('[data-testid="schedule-row"]').first().locator('[data-testid="schedule-checkbox"]')).toBeChecked();
    
    // Select two additional schedules
    await page.locator('[data-testid="schedule-row"]').nth(1).locator('[data-testid="schedule-checkbox"]').click();
    await page.locator('[data-testid="schedule-row"]').nth(2).locator('[data-testid="schedule-checkbox"]').click();
    
    const selectedCount = await page.locator('[data-testid="schedule-checkbox"]:checked').count();
    expect(selectedCount).toBe(3);
    
    // Click Select All checkbox
    await page.click('[data-testid="select-all-checkbox"]');
    
    // Expected Result: Schedules are selected for bulk actions
    const totalRows = await page.locator('[data-testid="schedule-row"]').count();
    const allSelectedCount = await page.locator('[data-testid="schedule-checkbox"]:checked').count();
    expect(allSelectedCount).toBe(totalRows);
    
    // Verify bulk action buttons are enabled
    await expect(page.locator('[data-testid="bulk-delete-button"]')).toBeEnabled();
    await expect(page.locator('[data-testid="bulk-export-button"]')).toBeEnabled();
    await expect(page.locator('[data-testid="bulk-modify-button"]')).toBeEnabled();
    
    // Deselect all schedules
    await page.click('[data-testid="select-all-checkbox"]');
    const deselectedCount = await page.locator('[data-testid="schedule-checkbox"]:checked').count();
    expect(deselectedCount).toBe(0);
  });

  test('Ensure unauthorized users cannot access schedule list', async ({ page }) => {
    // Logout from Scheduler account
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Step 1: Navigate to login page and login as non-Scheduler user
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'employee@example.com');
    await page.fill('[data-testid="password-input"]', 'EmployeePass123');
    await page.click('[data-testid="login-button"]');
    
    // Expected Result: User is logged in with Employee role
    await expect(page.locator('[data-testid="user-role"]')).toContainText('Employee');
    await expect(page.locator('[data-testid="user-role"]')).not.toContainText('Scheduler');
    
    // Step 2: Verify Schedules menu or List View option is not accessible
    const schedulesMenuVisible = await page.locator('[data-testid="schedules-menu"]').isVisible().catch(() => false);
    const listViewVisible = await page.locator('[data-testid="list-view-option"]').isVisible().catch(() => false);
    
    expect(schedulesMenuVisible).toBe(false);
    expect(listViewVisible).toBe(false);
    
    // Step 3: Attempt to directly access schedule list page by URL
    await page.goto('/schedules/list');
    
    // Expected Result: Access is denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access Denied');
    
    // Verify no schedule data is displayed
    const scheduleTableVisible = await page.locator('[data-testid="schedule-list-table"]').isVisible().catch(() => false);
    expect(scheduleTableVisible).toBe(false);
    
    // Verify schedule rows are not present
    const scheduleRowCount = await page.locator('[data-testid="schedule-row"]').count();
    expect(scheduleRowCount).toBe(0);
    
    // Check for error or redirect
    const currentUrl = page.url();
    const isOnScheduleList = currentUrl.includes('/schedules/list');
    const isOnAccessDenied = currentUrl.includes('/access-denied') || currentUrl.includes('/unauthorized');
    
    expect(isOnScheduleList && scheduleTableVisible || isOnAccessDenied).toBeTruthy();
    
    // Logout
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    
    // Step 4: Attempt to access without authentication
    await page.goto('/schedules/list');
    
    // Expected Result: Redirected to login or access denied
    const finalUrl = page.url();
    const isRedirectedToLogin = finalUrl.includes('/login');
    const isAccessDeniedPage = finalUrl.includes('/access-denied') || finalUrl.includes('/unauthorized');
    
    expect(isRedirectedToLogin || isAccessDeniedPage).toBeTruthy();
    
    // Verify no schedule data accessible
    const unauthScheduleTable = await page.locator('[data-testid="schedule-list-table"]').isVisible().catch(() => false);
    expect(unauthScheduleTable).toBe(false);
  });
});