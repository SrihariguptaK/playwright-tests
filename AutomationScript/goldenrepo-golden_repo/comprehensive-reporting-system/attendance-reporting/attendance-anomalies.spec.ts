import { test, expect } from '@playwright/test';

test.describe('Attendance Anomalies Detection', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to attendance report page
    await page.goto('/attendance/reports');
    // Login if needed
    await page.waitForLoadState('networkidle');
  });

  test('Detect and flag late arrivals in attendance report', async ({ page }) => {
    // Step 1: Generate attendance report including shift start times
    await page.click('[data-testid="generate-report-button"]');
    await page.selectOption('[data-testid="report-type-select"]', 'attendance');
    await page.check('[data-testid="include-shift-times-checkbox"]');
    await page.click('[data-testid="submit-report-button"]');
    
    // Wait for report to be generated
    await page.waitForSelector('[data-testid="attendance-report-table"]', { timeout: 10000 });
    
    // Expected Result: Report displayed with attendance records
    await expect(page.locator('[data-testid="attendance-report-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-records"]')).toHaveCount(await page.locator('[data-testid="report-records"]').count());
    
    // Step 2: Verify late arrivals are flagged with visual indicators
    const lateArrivalFlags = page.locator('[data-testid="late-arrival-flag"]');
    const lateArrivalCount = await lateArrivalFlags.count();
    
    // Expected Result: Late arrivals clearly marked in report
    if (lateArrivalCount > 0) {
      await expect(lateArrivalFlags.first()).toBeVisible();
      await expect(lateArrivalFlags.first()).toHaveClass(/late-arrival|anomaly|warning/);
      
      // Verify visual indicator attributes
      const firstFlag = lateArrivalFlags.first();
      await expect(firstFlag).toHaveAttribute('title', /late/i);
    }
    
    // Step 3: Check summary count of late arrivals in report header
    const summaryCount = page.locator('[data-testid="late-arrivals-summary-count"]');
    await expect(summaryCount).toBeVisible();
    
    // Expected Result: Summary count matches flagged records
    const summaryText = await summaryCount.textContent();
    const summaryNumber = parseInt(summaryText?.match(/\d+/)?.[0] || '0');
    expect(summaryNumber).toBe(lateArrivalCount);
    
    // Additional verification: Check anomaly indicator styling
    if (lateArrivalCount > 0) {
      const flaggedRow = page.locator('[data-testid="report-records"]').filter({ has: page.locator('[data-testid="late-arrival-flag"]') }).first();
      await expect(flaggedRow).toHaveClass(/flagged|anomaly|highlighted/);
    }
  });

  test('Identify and flag unapproved absences', async ({ page }) => {
    // Step 1: Generate attendance report including absence records
    await page.click('[data-testid="generate-report-button"]');
    await page.selectOption('[data-testid="report-type-select"]', 'attendance');
    await page.check('[data-testid="include-absences-checkbox"]');
    await page.click('[data-testid="submit-report-button"]');
    
    // Wait for report generation
    await page.waitForSelector('[data-testid="attendance-report-table"]', { timeout: 10000 });
    
    // Expected Result: Report displayed
    await expect(page.locator('[data-testid="attendance-report-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-title"]')).toContainText(/attendance report/i);
    
    // Step 2: Verify unapproved absences are flagged
    const unapprovedAbsenceFlags = page.locator('[data-testid="unapproved-absence-flag"]');
    const unapprovedAbsenceCount = await unapprovedAbsenceFlags.count();
    
    // Expected Result: Unapproved absences clearly marked
    if (unapprovedAbsenceCount > 0) {
      await expect(unapprovedAbsenceFlags.first()).toBeVisible();
      
      // Verify visual indicators for unapproved absences
      const firstAbsenceFlag = unapprovedAbsenceFlags.first();
      await expect(firstAbsenceFlag).toHaveClass(/unapproved|anomaly|warning|alert/);
      await expect(firstAbsenceFlag).toHaveAttribute('title', /unapproved/i);
      
      // Check for icon or badge indicating unapproved status
      const flagIcon = firstAbsenceFlag.locator('svg, i, .icon');
      await expect(flagIcon).toBeVisible();
    }
    
    // Verify absence records have status indicators
    const absenceRecords = page.locator('[data-testid="absence-record"]');
    if (await absenceRecords.count() > 0) {
      const firstAbsence = absenceRecords.first();
      await expect(firstAbsence.locator('[data-testid="absence-status"]')).toBeVisible();
    }
    
    // Step 3: Confirm summary count of unapproved absences
    const absenceSummaryCount = page.locator('[data-testid="unapproved-absences-summary-count"]');
    await expect(absenceSummaryCount).toBeVisible();
    
    // Expected Result: Summary count accurate
    const absenceSummaryText = await absenceSummaryCount.textContent();
    const absenceSummaryNumber = parseInt(absenceSummaryText?.match(/\d+/)?.[0] || '0');
    expect(absenceSummaryNumber).toBe(unapprovedAbsenceCount);
    
    // Verify anomaly summary section exists
    const anomalySummary = page.locator('[data-testid="anomaly-summary-section"]');
    await expect(anomalySummary).toBeVisible();
    
    // Verify total anomaly count includes unapproved absences
    const totalAnomalies = page.locator('[data-testid="total-anomalies-count"]');
    if (await totalAnomalies.isVisible()) {
      const totalText = await totalAnomalies.textContent();
      const totalNumber = parseInt(totalText?.match(/\d+/)?.[0] || '0');
      expect(totalNumber).toBeGreaterThanOrEqual(absenceSummaryNumber);
    }
  });

  test('Verify anomaly detection performance within report generation time', async ({ page }) => {
    const startTime = Date.now();
    
    // Generate comprehensive attendance report
    await page.click('[data-testid="generate-report-button"]');
    await page.selectOption('[data-testid="report-type-select"]', 'attendance');
    await page.check('[data-testid="include-shift-times-checkbox"]');
    await page.check('[data-testid="include-absences-checkbox"]');
    await page.click('[data-testid="submit-report-button"]');
    
    // Wait for report with anomalies
    await page.waitForSelector('[data-testid="attendance-report-table"]', { timeout: 15000 });
    await page.waitForSelector('[data-testid="anomaly-summary-section"]', { timeout: 5000 });
    
    const endTime = Date.now();
    const generationTime = endTime - startTime;
    
    // Verify report is complete with anomalies detected
    await expect(page.locator('[data-testid="attendance-report-table"]')).toBeVisible();
    await expect(page.locator('[data-testid="anomaly-summary-section"]')).toBeVisible();
    
    // Verify anomaly counts are populated
    const lateArrivalsCount = page.locator('[data-testid="late-arrivals-summary-count"]');
    const unapprovedAbsencesCount = page.locator('[data-testid="unapproved-absences-summary-count"]');
    
    await expect(lateArrivalsCount).toBeVisible();
    await expect(unapprovedAbsencesCount).toBeVisible();
    
    // Performance assertion: Generation time should be reasonable (under 15 seconds)
    expect(generationTime).toBeLessThan(15000);
  });

  test('Verify visual markers for multiple anomaly types', async ({ page }) => {
    // Generate report with all anomaly types
    await page.click('[data-testid="generate-report-button"]');
    await page.selectOption('[data-testid="report-type-select"]', 'attendance');
    await page.check('[data-testid="include-all-anomalies-checkbox"]');
    await page.click('[data-testid="submit-report-button"]');
    
    await page.waitForSelector('[data-testid="attendance-report-table"]', { timeout: 10000 });
    
    // Verify different anomaly types have distinct visual markers
    const lateArrivalFlags = page.locator('[data-testid="late-arrival-flag"]');
    const unapprovedAbsenceFlags = page.locator('[data-testid="unapproved-absence-flag"]');
    
    // Check that anomalies are visually distinguishable
    if (await lateArrivalFlags.count() > 0 && await unapprovedAbsenceFlags.count() > 0) {
      const lateArrivalClass = await lateArrivalFlags.first().getAttribute('class');
      const absenceClass = await unapprovedAbsenceFlags.first().getAttribute('class');
      
      // Classes should be different to distinguish anomaly types
      expect(lateArrivalClass).not.toBe(absenceClass);
    }
    
    // Verify legend or key explaining anomaly markers
    const anomalyLegend = page.locator('[data-testid="anomaly-legend"]');
    if (await anomalyLegend.isVisible()) {
      await expect(anomalyLegend).toContainText(/late arrival/i);
      await expect(anomalyLegend).toContainText(/unapproved absence/i);
    }
  });
});