import { test, expect } from '@playwright/test';

test.describe('Story-18: Analyze Attendance Trends for Workforce Management', () => {
  test.beforeEach(async ({ page }) => {
    // Login as manager before each test
    await page.goto('/login');
    await page.fill('[data-testid="email-input"]', 'manager@company.com');
    await page.fill('[data-testid="password-input"]', 'Manager@123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate successful attendance trend visualization (happy-path)', async ({ page }) => {
    // Step 1: Manager navigates to analytics dashboard
    await page.click('[data-testid="analytics-menu"]');
    await expect(page).toHaveURL(/.*analytics/);
    await expect(page.locator('[data-testid="analytics-dashboard"]')).toBeVisible();
    await expect(page.locator('h1, h2').filter({ hasText: /analytics|dashboard/i })).toBeVisible();

    // Step 2: Manager selects desired metrics to analyze
    await page.click('[data-testid="metrics-dropdown"]');
    await page.click('[data-testid="metric-daily-attendance"]');
    await expect(page.locator('[data-testid="selected-metrics"]')).toContainText('Daily Attendance');
    
    // Add weekly trends metric
    await page.click('[data-testid="metrics-dropdown"]');
    await page.click('[data-testid="metric-weekly-trends"]');
    await expect(page.locator('[data-testid="selected-metrics"]')).toContainText('Weekly Trends');

    // Step 3: Manager selects a time period for trend analysis
    await page.click('[data-testid="time-period-selector"]');
    await page.click('[data-testid="period-last-30-days"]');
    await expect(page.locator('[data-testid="selected-period"]')).toContainText('Last 30 Days');

    // Step 4: Manager views the attendance trends displayed in visual format
    await page.waitForSelector('[data-testid="attendance-chart"]', { state: 'visible', timeout: 3000 });
    await expect(page.locator('[data-testid="attendance-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="trend-visualization"]')).toBeVisible();
    
    // Verify chart elements are present
    const chartCanvas = page.locator('canvas[data-testid="chart-canvas"], svg[data-testid="chart-svg"]');
    await expect(chartCanvas).toBeVisible();

    // Step 5: Manager hovers over or clicks on specific data points
    await page.hover('[data-testid="data-point-0"]');
    await expect(page.locator('[data-testid="tooltip"]')).toBeVisible();
    await expect(page.locator('[data-testid="tooltip"]')).toContainText(/attendance|date|value/i);
    
    // Click on a data point for detailed view
    await page.click('[data-testid="data-point-5"]');
    await expect(page.locator('[data-testid="data-details"]')).toBeVisible();
    
    // Verify trends are displayed accurately
    await expect(page.locator('[data-testid="trend-summary"]')).toBeVisible();
    await expect(page.locator('[data-testid="trend-accuracy-indicator"]')).toHaveAttribute('data-accuracy', '100');
  });

  test('Verify insights into absenteeism rates (happy-path)', async ({ page }) => {
    // Step 1: Manager navigates to analytics dashboard
    await page.click('[data-testid="analytics-menu"]');
    await expect(page).toHaveURL(/.*analytics/);
    await expect(page.locator('[data-testid="analytics-dashboard"]')).toBeVisible();
    await expect(page.locator('h1, h2').filter({ hasText: /analytics|dashboard/i })).toBeVisible();

    // Step 2: Manager selects absenteeism metrics from the available metrics list
    await page.click('[data-testid="metrics-dropdown"]');
    await expect(page.locator('[data-testid="metrics-list"]')).toBeVisible();
    
    await page.click('[data-testid="metric-absenteeism-rate"]');
    await expect(page.locator('[data-testid="selected-metrics"]')).toContainText('Absenteeism Rate');
    
    // Add absence frequency metric
    await page.click('[data-testid="metrics-dropdown"]');
    await page.click('[data-testid="metric-absence-frequency"]');
    await expect(page.locator('[data-testid="selected-metrics"]')).toContainText('Absence Frequency');
    
    // Add absence patterns metric
    await page.click('[data-testid="metrics-dropdown"]');
    await page.click('[data-testid="metric-absence-patterns"]');
    await expect(page.locator('[data-testid="selected-metrics"]')).toContainText('Absence Patterns');

    // Step 3: Manager selects the time period for absenteeism analysis
    await page.click('[data-testid="time-period-selector"]');
    await page.click('[data-testid="period-last-quarter"]');
    await expect(page.locator('[data-testid="selected-period"]')).toContainText('Last Quarter');

    // Step 4: Manager views the absenteeism insights displayed on the dashboard
    await page.waitForSelector('[data-testid="absenteeism-insights"]', { state: 'visible', timeout: 3000 });
    await expect(page.locator('[data-testid="absenteeism-insights"]')).toBeVisible();
    await expect(page.locator('[data-testid="absenteeism-chart"]')).toBeVisible();
    
    // Verify absenteeism rate is displayed
    await expect(page.locator('[data-testid="absenteeism-rate-value"]')).toBeVisible();
    const absenteeismRate = await page.locator('[data-testid="absenteeism-rate-value"]').textContent();
    expect(absenteeismRate).toMatch(/\d+\.?\d*%/);
    
    // Verify insights are displayed accurately
    await expect(page.locator('[data-testid="insights-summary"]')).toBeVisible();

    // Step 5: Manager reviews detailed absenteeism breakdown
    await page.click('[data-testid="absenteeism-breakdown-section"]');
    await expect(page.locator('[data-testid="detailed-breakdown"]')).toBeVisible();
    
    // Click on specific data points for more details
    await page.click('[data-testid="breakdown-data-point-0"]');
    await expect(page.locator('[data-testid="breakdown-details"]')).toBeVisible();
    await expect(page.locator('[data-testid="breakdown-details"]')).toContainText(/employee|department|date/i);

    // Step 6: Manager examines punctuality insights
    await page.click('[data-testid="punctuality-insights-tab"]');
    await expect(page.locator('[data-testid="punctuality-insights"]')).toBeVisible();
    await expect(page.locator('[data-testid="punctuality-chart"]')).toBeVisible();
    
    // Verify punctuality metrics are displayed
    await expect(page.locator('[data-testid="punctuality-rate"]')).toBeVisible();
    await expect(page.locator('[data-testid="late-arrivals-count"]')).toBeVisible();
    
    // Verify insights accuracy
    const insightsAccuracy = await page.locator('[data-testid="insights-accuracy"]').getAttribute('data-accuracy');
    expect(parseInt(insightsAccuracy || '0')).toBeGreaterThanOrEqual(100);
  });

  test('Verify team comparison functionality', async ({ page }) => {
    // Navigate to analytics dashboard
    await page.click('[data-testid="analytics-menu"]');
    await expect(page.locator('[data-testid="analytics-dashboard"]')).toBeVisible();

    // Select comparison view
    await page.click('[data-testid="view-mode-selector"]');
    await page.click('[data-testid="view-mode-comparison"]');
    
    // Select teams to compare
    await page.click('[data-testid="team-selector"]');
    await page.click('[data-testid="team-engineering"]');
    await page.click('[data-testid="team-selector"]');
    await page.click('[data-testid="team-sales"]');
    
    // Verify comparison chart is displayed
    await expect(page.locator('[data-testid="team-comparison-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="comparison-legend"]')).toContainText('Engineering');
    await expect(page.locator('[data-testid="comparison-legend"]')).toContainText('Sales');
    
    // Verify comparison data accuracy
    await expect(page.locator('[data-testid="comparison-summary"]')).toBeVisible();
  });

  test('Verify analytics dashboard performance', async ({ page }) => {
    // Navigate to analytics dashboard and measure load time
    const startTime = Date.now();
    
    await page.click('[data-testid="analytics-menu"]');
    await page.click('[data-testid="metrics-dropdown"]');
    await page.click('[data-testid="metric-daily-attendance"]');
    await page.click('[data-testid="time-period-selector"]');
    await page.click('[data-testid="period-last-30-days"]');
    
    // Wait for visualization to load
    await page.waitForSelector('[data-testid="attendance-chart"]', { state: 'visible' });
    
    const loadTime = Date.now() - startTime;
    
    // Verify performance requirement: Data visualization under 3 seconds
    expect(loadTime).toBeLessThan(3000);
    
    // Verify chart is fully rendered
    await expect(page.locator('[data-testid="attendance-chart"]')).toBeVisible();
    await expect(page.locator('[data-testid="chart-loaded-indicator"]')).toHaveAttribute('data-loaded', 'true');
  });
});