import { test, expect } from '@playwright/test';

test.describe('Schedule Report Team Filtering', () => {
  test.beforeEach(async ({ page }) => {
    // Login as Project Manager
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'project.manager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Filter schedule report by valid team (happy-path)', async ({ page }) => {
    // Step 1: Navigate to Schedule Reporting section from the main dashboard
    await page.click('[data-testid="schedule-reporting-link"]');
    
    // Expected Result: Schedule report UI is displayed
    await expect(page.locator('[data-testid="schedule-report-container"]')).toBeVisible();
    await expect(page.locator('[data-testid="team-filter-dropdown"]')).toBeVisible();
    await expect(page.locator('[data-testid="generate-report-button"]')).toBeVisible();

    // Step 2: Click on the team filter dropdown to view available teams
    await page.click('[data-testid="team-filter-dropdown"]');
    await expect(page.locator('[data-testid="team-filter-options"]')).toBeVisible();

    // Step 3: Select a valid team from the filter dropdown
    await page.click('[data-testid="team-option-development-team-a"]');
    
    // Expected Result: Team filter is applied
    await expect(page.locator('[data-testid="team-filter-dropdown"]')).toContainText('Development Team A');
    const selectedTeamValue = await page.locator('[data-testid="team-filter-dropdown"]').getAttribute('data-selected-team');
    expect(selectedTeamValue).toBe('development-team-a');

    // Step 4: Click the 'Generate Report' button to create the filtered report
    await page.click('[data-testid="generate-report-button"]');

    // Step 5: Wait for report generation to complete (within 5 seconds)
    await expect(page.locator('[data-testid="report-loading-indicator"]')).toBeVisible({ timeout: 1000 });
    await expect(page.locator('[data-testid="report-loading-indicator"]')).toBeHidden({ timeout: 5000 });
    
    // Expected Result: Report displays schedule data only for selected team
    await expect(page.locator('[data-testid="schedule-report-results"]')).toBeVisible();
    
    // Step 6: Verify that all activities and schedules displayed belong only to the selected team
    const reportRows = page.locator('[data-testid="schedule-report-row"]');
    await expect(reportRows).toHaveCountGreaterThan(0);
    
    const rowCount = await reportRows.count();
    for (let i = 0; i < rowCount; i++) {
      const teamCell = reportRows.nth(i).locator('[data-testid="row-team-name"]');
      await expect(teamCell).toContainText('Development Team A');
    }

    // Step 7: Check that resource assignments shown in the report are members of the selected team
    const resourceAssignments = page.locator('[data-testid="resource-assignment"]');
    const assignmentCount = await resourceAssignments.count();
    for (let i = 0; i < assignmentCount; i++) {
      const teamAttribute = await resourceAssignments.nth(i).getAttribute('data-team');
      expect(teamAttribute).toBe('development-team-a');
    }

    // Step 8: Verify the report header or filter summary indicates the team filter is active
    await expect(page.locator('[data-testid="report-header-filter-summary"]')).toContainText('Team: Development Team A');
    await expect(page.locator('[data-testid="active-filter-badge"]')).toBeVisible();
  });

  test('Handle invalid team filter input (error-case)', async ({ page }) => {
    // Step 1: Navigate to Schedule Reporting section from the main dashboard
    await page.click('[data-testid="schedule-reporting-link"]');
    await expect(page.locator('[data-testid="schedule-report-container"]')).toBeVisible();

    // Step 2: Enter an invalid team identifier in the team filter field
    await page.click('[data-testid="team-filter-dropdown"]');
    const filterInput = page.locator('[data-testid="team-filter-input"]');
    await filterInput.fill('INVALID_TEAM_999');

    // Step 3: Tab out of the field or trigger validation by clicking elsewhere
    await page.keyboard.press('Tab');
    await page.waitForTimeout(500);

    // Expected Result: System displays validation error
    await expect(page.locator('[data-testid="team-filter-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="team-filter-error"]')).toContainText(/invalid team|team not found|please select a valid team/i);

    // Step 4: Verify the error message is clearly visible and describes the validation issue
    const errorMessage = await page.locator('[data-testid="team-filter-error"]').textContent();
    expect(errorMessage).toBeTruthy();
    expect(errorMessage!.length).toBeGreaterThan(10);

    // Step 5: Attempt to click the 'Generate Report' button with the invalid team filter
    await page.click('[data-testid="generate-report-button"]');

    // Expected Result: Report generation is blocked until valid input is provided
    await expect(page.locator('[data-testid="schedule-report-results"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="team-filter-error"]')).toBeVisible();
    
    // Verify the generate button is disabled or shows validation message
    const generateButton = page.locator('[data-testid="generate-report-button"]');
    const isDisabled = await generateButton.isDisabled();
    if (!isDisabled) {
      await expect(page.locator('[data-testid="validation-message"]')).toBeVisible();
    }

    // Step 6: Verify that no report is generated with invalid team filter
    await expect(page.locator('[data-testid="schedule-report-results"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="report-header-filter-summary"]')).not.toBeVisible();

    // Step 7: Clear the invalid team filter input and select a valid team from the dropdown
    await filterInput.clear();
    await expect(page.locator('[data-testid="team-filter-error"]')).not.toBeVisible();
    
    await page.click('[data-testid="team-filter-dropdown"]');
    await page.click('[data-testid="team-option-development-team-a"]');
    await expect(page.locator('[data-testid="team-filter-dropdown"]')).toContainText('Development Team A');

    // Step 8: Click 'Generate Report' with the valid team filter
    await page.click('[data-testid="generate-report-button"]');
    
    // Verify successful report generation
    await expect(page.locator('[data-testid="report-loading-indicator"]')).toBeVisible({ timeout: 1000 });
    await expect(page.locator('[data-testid="report-loading-indicator"]')).toBeHidden({ timeout: 5000 });
    await expect(page.locator('[data-testid="schedule-report-results"]')).toBeVisible();
    await expect(page.locator('[data-testid="team-filter-error"]')).not.toBeVisible();
  });

  test('Filter schedule report by valid team - API validation', async ({ page }) => {
    // Navigate to Schedule Reporting section
    await page.click('[data-testid="schedule-reporting-link"]');
    await expect(page.locator('[data-testid="schedule-report-container"]')).toBeVisible();

    // Set up API response listener
    const responsePromise = page.waitForResponse(
      response => response.url().includes('/api/reports/schedule') && response.status() === 200
    );

    // Select a valid team from filter dropdown
    await page.click('[data-testid="team-filter-dropdown"]');
    await page.click('[data-testid="team-option-development-team-a"]');

    // Generate report
    await page.click('[data-testid="generate-report-button"]');

    // Wait for and validate API response
    const response = await responsePromise;
    expect(response.url()).toContain('team=');
    expect(response.status()).toBe(200);

    // Verify report displays filtered data
    await expect(page.locator('[data-testid="schedule-report-results"]')).toBeVisible({ timeout: 5000 });
  });

  test('Export filtered schedule report correctly', async ({ page }) => {
    // Navigate to Schedule Reporting section
    await page.click('[data-testid="schedule-reporting-link"]');
    await expect(page.locator('[data-testid="schedule-report-container"]')).toBeVisible();

    // Select team filter and generate report
    await page.click('[data-testid="team-filter-dropdown"]');
    await page.click('[data-testid="team-option-development-team-a"]');
    await page.click('[data-testid="generate-report-button"]');
    
    await expect(page.locator('[data-testid="schedule-report-results"]')).toBeVisible({ timeout: 5000 });

    // Set up download listener
    const downloadPromise = page.waitForEvent('download');

    // Click export button
    await page.click('[data-testid="export-report-button"]');

    // Wait for download and verify
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/schedule.*report.*development.*team.*a/i);
  });
});