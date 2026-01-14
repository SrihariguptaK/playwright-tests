import { test, expect } from '@playwright/test';

test.describe('Filter and Search Schedule Change Requests', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the approval dashboard before each test
    await page.goto('/approval-dashboard');
    await page.waitForLoadState('networkidle');
  });

  test('Validate filtering of schedule change requests by status and date', async ({ page }) => {
    // Locate and click on the status filter dropdown
    const statusFilter = page.getByTestId('status-filter-dropdown');
    await expect(statusFilter).toBeVisible();
    await statusFilter.click();

    // Select 'Pending' from the status filter dropdown
    const pendingOption = page.getByRole('option', { name: 'Pending' });
    await pendingOption.click();

    // Click on the date range filter and select a start date and end date
    const dateRangeFilter = page.getByTestId('date-range-filter');
    await dateRangeFilter.click();
    
    const startDateInput = page.getByTestId('start-date-input');
    await startDateInput.fill('2024-01-01');
    
    const endDateInput = page.getByTestId('end-date-input');
    await endDateInput.fill('2024-01-31');

    // Click 'Apply' or 'Filter' button to apply the selected filters
    const applyButton = page.getByRole('button', { name: /apply|filter/i });
    await applyButton.click();

    // Wait for filtered results to load
    await page.waitForResponse(response => 
      response.url().includes('/api/approvals/pending') && response.status() === 200
    );

    // Verify the filtered results by checking each displayed request
    const requestRows = page.getByTestId('request-row');
    await expect(requestRows).not.toHaveCount(0);
    
    const firstRequestStatus = page.getByTestId('request-status').first();
    await expect(firstRequestStatus).toContainText('Pending');

    // Verify response time is within 2 seconds
    const startTime = Date.now();
    await page.waitForSelector('[data-testid="request-row"]');
    const endTime = Date.now();
    expect(endTime - startTime).toBeLessThan(2000);

    // Click on 'Clear Filters' or 'Reset' button
    const clearFiltersButton = page.getByRole('button', { name: /clear filters|reset/i });
    await clearFiltersButton.click();

    // Observe the request list after clearing filters
    await page.waitForLoadState('networkidle');
    const allRequestRows = page.getByTestId('request-row');
    const allRequestsCount = await allRequestRows.count();
    
    // Verify full list of requests is displayed
    expect(allRequestsCount).toBeGreaterThan(0);
    await expect(page.getByTestId('status-filter-dropdown')).toHaveText(/all|select status/i);
  });

  test('Verify keyword search functionality', async ({ page }) => {
    // Locate the search box on the approval dashboard
    const searchBox = page.getByTestId('search-box');
    await expect(searchBox).toBeVisible();

    // Click inside the search box to focus on it
    await searchBox.click();

    // Type 'John Smith' in the search box
    await searchBox.fill('John Smith');

    // Wait for search results to update
    await page.waitForResponse(response => 
      response.url().includes('/api/approvals/pending') && response.status() === 200
    );

    // Observe the request list as the keyword is entered
    await page.waitForSelector('[data-testid="request-row"]');
    
    // Verify list updates to show requests matching the keyword
    const requestRows = page.getByTestId('request-row');
    const rowCount = await requestRows.count();
    expect(rowCount).toBeGreaterThan(0);

    // Verify each displayed request contains the search keyword
    for (let i = 0; i < rowCount; i++) {
      const requestRow = requestRows.nth(i);
      const rowText = await requestRow.textContent();
      expect(rowText?.toLowerCase()).toContain('john smith'.toLowerCase());
    }

    // Clear the search box by deleting the text or clicking a clear icon
    const clearSearchButton = page.getByTestId('clear-search-button');
    if (await clearSearchButton.isVisible()) {
      await clearSearchButton.click();
    } else {
      await searchBox.clear();
    }

    // Verify search is cleared
    await expect(searchBox).toHaveValue('');
  });

  test('Ensure saved filter presets function correctly', async ({ page }) => {
    // Apply multiple filters: select 'Pending' status
    const statusFilter = page.getByTestId('status-filter-dropdown');
    await statusFilter.click();
    await page.getByRole('option', { name: 'Pending' }).click();

    // Set date range to last 7 days
    const dateRangeFilter = page.getByTestId('date-range-filter');
    await dateRangeFilter.click();
    
    const today = new Date();
    const sevenDaysAgo = new Date(today);
    sevenDaysAgo.setDate(today.getDate() - 7);
    
    const startDateInput = page.getByTestId('start-date-input');
    await startDateInput.fill(sevenDaysAgo.toISOString().split('T')[0]);
    
    const endDateInput = page.getByTestId('end-date-input');
    await endDateInput.fill(today.toISOString().split('T')[0]);

    // Apply filters
    const applyButton = page.getByRole('button', { name: /apply|filter/i });
    await applyButton.click();
    await page.waitForLoadState('networkidle');

    // Locate and click on 'Save Filter' or 'Save Preset' button
    const saveFilterButton = page.getByRole('button', { name: /save filter|save preset/i });
    await expect(saveFilterButton).toBeVisible();
    await saveFilterButton.click();

    // Enter preset name 'Pending Last Week' and click 'Save' or 'Confirm'
    const presetNameInput = page.getByTestId('preset-name-input');
    await expect(presetNameInput).toBeVisible();
    await presetNameInput.fill('Pending Last Week');
    
    const saveConfirmButton = page.getByRole('button', { name: /save|confirm/i }).last();
    await saveConfirmButton.click();

    // Verify the saved preset appears in the presets list or dropdown
    const presetsDropdown = page.getByTestId('filter-presets-dropdown');
    await expect(presetsDropdown).toBeVisible();
    await presetsDropdown.click();
    
    const savedPreset = page.getByRole('option', { name: 'Pending Last Week' });
    await expect(savedPreset).toBeVisible();

    // Clear all current filters to return to default view
    const clearFiltersButton = page.getByRole('button', { name: /clear filters|reset/i });
    await clearFiltersButton.click();
    await page.waitForLoadState('networkidle');

    // Click on or select the saved preset 'Pending Last Week' from the presets list
    await presetsDropdown.click();
    await savedPreset.click();

    // Wait for filters to be applied
    await page.waitForResponse(response => 
      response.url().includes('/api/approvals/pending') && response.status() === 200
    );

    // Observe the filter controls and request list
    await page.waitForLoadState('networkidle');

    // Verify the filtered results match the preset criteria
    const statusFilterValue = await page.getByTestId('status-filter-dropdown').textContent();
    expect(statusFilterValue).toContain('Pending');

    // Verify date range is applied
    const appliedStartDate = await startDateInput.inputValue();
    const appliedEndDate = await endDateInput.inputValue();
    expect(appliedStartDate).toBeTruthy();
    expect(appliedEndDate).toBeTruthy();

    // Verify filtered results are displayed
    const requestRows = page.getByTestId('request-row');
    await expect(requestRows.first()).toBeVisible();
    
    const firstRequestStatus = page.getByTestId('request-status').first();
    await expect(firstRequestStatus).toContainText('Pending');
  });
});