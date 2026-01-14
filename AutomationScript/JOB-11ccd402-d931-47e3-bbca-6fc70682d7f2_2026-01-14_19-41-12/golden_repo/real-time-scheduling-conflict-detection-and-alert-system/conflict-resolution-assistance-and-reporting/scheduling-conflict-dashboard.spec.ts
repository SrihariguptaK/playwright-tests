import { test, expect } from '@playwright/test';

test.describe('Scheduling Conflict Dashboard - Story 15', () => {
  const DASHBOARD_URL = '/scheduling/conflicts/dashboard';
  const DASHBOARD_REFRESH_TIMEOUT = 2000;

  test.beforeEach(async ({ page }) => {
    // Navigate to the scheduling conflict dashboard
    await page.goto(DASHBOARD_URL);
    // Wait for dashboard to load
    await page.waitForSelector('[data-testid="conflict-dashboard"]', { timeout: 5000 });
  });

  test('Verify dashboard displays active conflicts with details (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the scheduling conflict dashboard from the main menu
    await page.goto('/');
    await page.click('[data-testid="main-menu"]');
    await page.click('text=Scheduling Conflicts');
    
    // Expected Result: Dashboard shows list of active conflicts with details
    await expect(page.locator('[data-testid="conflict-dashboard"]')).toBeVisible();
    const conflictList = page.locator('[data-testid="conflict-list"]');
    await expect(conflictList).toBeVisible();
    
    // Verify conflicts are displayed
    const conflictItems = page.locator('[data-testid="conflict-item"]');
    const conflictCount = await conflictItems.count();
    expect(conflictCount).toBeGreaterThan(0);
    
    // Step 2: Select a specific conflict from the displayed list by clicking on it
    const firstConflict = conflictItems.first();
    const conflictId = await firstConflict.getAttribute('data-conflict-id');
    await firstConflict.click();
    
    // Expected Result: Detailed conflict information is displayed
    await expect(page.locator('[data-testid="conflict-details-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-detail-id"]')).toContainText(conflictId || '');
    await expect(page.locator('[data-testid="conflict-detail-resource"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-detail-time"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-detail-severity"]')).toBeVisible();
    await expect(page.locator('[data-testid="conflict-detail-description"]')).toBeVisible();
    
    // Step 3: Compare the displayed conflict data with the backend conflict records
    const displayedResource = await page.locator('[data-testid="conflict-detail-resource"]').textContent();
    const displayedTime = await page.locator('[data-testid="conflict-detail-time"]').textContent();
    const displayedSeverity = await page.locator('[data-testid="conflict-detail-severity"]').textContent();
    
    // Make API call to verify data accuracy
    const response = await page.request.get(`/api/conflicts/${conflictId}`);
    expect(response.ok()).toBeTruthy();
    const backendData = await response.json();
    
    // Expected Result: Displayed data matches backend conflict data
    expect(displayedResource).toContain(backendData.resource);
    expect(displayedTime).toContain(backendData.time);
    expect(displayedSeverity).toContain(backendData.severity);
  });

  test('Test filtering and sorting functionality on dashboard (happy-path)', async ({ page }) => {
    // Step 1: Click on the resource filter dropdown and select a specific resource
    await page.click('[data-testid="filter-resource-dropdown"]');
    await page.waitForSelector('[data-testid="resource-option"]');
    
    // Select 'Conference Room A'
    await page.click('text=Conference Room A');
    
    // Expected Result: Dashboard shows conflicts only for selected resource
    await page.waitForTimeout(500); // Allow filter to apply
    const filteredConflicts = page.locator('[data-testid="conflict-item"]');
    const filteredCount = await filteredConflicts.count();
    
    // Verify all displayed conflicts are for Conference Room A
    for (let i = 0; i < filteredCount; i++) {
      const resourceText = await filteredConflicts.nth(i).locator('[data-testid="conflict-resource"]').textContent();
      expect(resourceText).toContain('Conference Room A');
    }
    
    // Step 2: Click on the 'Priority' column header to sort conflicts by priority
    await page.click('[data-testid="sort-priority-header"]');
    await page.waitForTimeout(500); // Allow sorting to apply
    
    // Expected Result: Conflicts are ordered by priority correctly (descending)
    const priorityValues: string[] = [];
    const conflictItems = page.locator('[data-testid="conflict-item"]');
    const itemCount = await conflictItems.count();
    
    for (let i = 0; i < itemCount; i++) {
      const priority = await conflictItems.nth(i).locator('[data-testid="conflict-priority"]').textContent();
      if (priority) priorityValues.push(priority.trim());
    }
    
    // Verify descending order (High > Medium > Low)
    const priorityOrder = { 'High': 3, 'Medium': 2, 'Low': 1 };
    for (let i = 0; i < priorityValues.length - 1; i++) {
      const currentPriority = priorityOrder[priorityValues[i] as keyof typeof priorityOrder] || 0;
      const nextPriority = priorityOrder[priorityValues[i + 1] as keyof typeof priorityOrder] || 0;
      expect(currentPriority).toBeGreaterThanOrEqual(nextPriority);
    }
    
    // Step 3: Click the 'Clear Filters' button to remove all applied filters and sorting
    await page.click('[data-testid="clear-filters-button"]');
    await page.waitForTimeout(500);
    
    // Expected Result: Dashboard returns to full conflict list
    const allConflicts = page.locator('[data-testid="conflict-item"]');
    const totalCount = await allConflicts.count();
    expect(totalCount).toBeGreaterThanOrEqual(filteredCount);
    
    // Verify filter dropdown is reset
    const filterDropdown = page.locator('[data-testid="filter-resource-dropdown"]');
    await expect(filterDropdown).toContainText('All Resources');
  });

  test('Ensure dashboard refreshes data within 2 seconds (happy-path)', async ({ page }) => {
    // Get initial conflict count
    const initialConflicts = page.locator('[data-testid="conflict-item"]');
    const initialCount = await initialConflicts.count();
    
    // Step 1: Create a new scheduling conflict through API while monitoring dashboard
    const startTime = Date.now();
    
    // Create new conflict via API
    const newConflict = {
      resource: 'Test Room B',
      startTime: '2024-01-15T10:00:00Z',
      endTime: '2024-01-15T11:00:00Z',
      severity: 'High',
      description: 'Test conflict for dashboard refresh'
    };
    
    const createResponse = await page.request.post('/api/conflicts', {
      data: newConflict
    });
    expect(createResponse.ok()).toBeTruthy();
    const createdConflict = await createResponse.json();
    const conflictId = createdConflict.id;
    
    // Wait for dashboard to update and measure time
    await page.waitForSelector(`[data-conflict-id="${conflictId}"]`, { timeout: DASHBOARD_REFRESH_TIMEOUT });
    const refreshTime = Date.now() - startTime;
    
    // Expected Result: Dashboard updates to show new conflict within 2 seconds
    expect(refreshTime).toBeLessThanOrEqual(DASHBOARD_REFRESH_TIMEOUT);
    
    const updatedConflicts = page.locator('[data-testid="conflict-item"]');
    const updatedCount = await updatedConflicts.count();
    expect(updatedCount).toBe(initialCount + 1);
    
    // Verify new conflict is displayed
    const newConflictElement = page.locator(`[data-conflict-id="${conflictId}"]`);
    await expect(newConflictElement).toBeVisible();
    await expect(newConflictElement.locator('[data-testid="conflict-resource"]')).toContainText('Test Room B');
    
    // Step 2: Resolve an existing conflict and monitor dashboard refresh time
    const resolveStartTime = Date.now();
    
    // Click on the newly created conflict to select it
    await newConflictElement.click();
    await expect(page.locator('[data-testid="conflict-details-panel"]')).toBeVisible();
    
    // Resolve the conflict
    await page.click('[data-testid="resolve-conflict-button"]');
    await page.click('[data-testid="confirm-resolution-button"]');
    
    // Wait for conflict to be removed from dashboard
    await page.waitForSelector(`[data-conflict-id="${conflictId}"]`, { state: 'detached', timeout: DASHBOARD_REFRESH_TIMEOUT });
    const resolveRefreshTime = Date.now() - resolveStartTime;
    
    // Expected Result: Dashboard removes resolved conflict within 2 seconds
    expect(resolveRefreshTime).toBeLessThanOrEqual(DASHBOARD_REFRESH_TIMEOUT);
    
    const finalConflicts = page.locator('[data-testid="conflict-item"]');
    const finalCount = await finalConflicts.count();
    expect(finalCount).toBe(initialCount);
    
    // Step 3: Verify no stale data displayed
    // Check last refresh timestamp
    const lastRefreshTimestamp = await page.locator('[data-testid="last-refresh-timestamp"]').textContent();
    expect(lastRefreshTimestamp).toBeTruthy();
    
    // Verify dashboard data matches current backend state
    const dashboardResponse = await page.request.get('/api/conflicts/dashboard');
    expect(dashboardResponse.ok()).toBeTruthy();
    const backendConflicts = await dashboardResponse.json();
    
    // Expected Result: Dashboard data is current and accurate
    expect(finalCount).toBe(backendConflicts.length);
    
    // Verify resolved conflict is not in backend data
    const resolvedConflictExists = backendConflicts.some((conflict: any) => conflict.id === conflictId);
    expect(resolvedConflictExists).toBe(false);
  });
});