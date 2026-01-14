import { test, expect } from '@playwright/test';

test.describe('Conflict Reports - Story 15', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login if required
    await page.goto(BASE_URL);
    // Assuming user is already authenticated or add login steps here
  });

  test('Generate conflict summary report with valid parameters (happy-path)', async ({ page }) => {
    // Navigate to the reporting section from the main menu or dashboard
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="reporting-section"]');
    expect(await page.isVisible('[data-testid="report-ui"]')).toBeTruthy();
    
    // Select 'Conflict Reports' or 'Scheduling Conflicts' option
    await page.click('[data-testid="conflict-reports-option"]');
    expect(await page.isVisible('[data-testid="conflict-report-form"]')).toBeTruthy();
    
    // Enter a valid start date (e.g., first day of current month)
    const today = new Date();
    const firstDay = new Date(today.getFullYear(), today.getMonth(), 1);
    const lastDay = new Date(today.getFullYear(), today.getMonth() + 1, 0);
    const startDate = firstDay.toISOString().split('T')[0];
    const endDate = lastDay.toISOString().split('T')[0];
    
    await page.fill('[data-testid="from-date-field"]', startDate);
    expect(await page.inputValue('[data-testid="from-date-field"]')).toBe(startDate);
    
    // Enter a valid end date (e.g., last day of current month)
    await page.fill('[data-testid="to-date-field"]', endDate);
    expect(await page.inputValue('[data-testid="to-date-field"]')).toBe(endDate);
    
    // Select filter options such as conflict type or affected resources if available
    if (await page.isVisible('[data-testid="conflict-type-filter"]')) {
      await page.selectOption('[data-testid="conflict-type-filter"]', { index: 1 });
    }
    
    // Note the current time and click the 'Generate Report' button
    const startTime = Date.now();
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report to be generated
    await page.waitForSelector('[data-testid="report-content"]', { timeout: 10000 });
    const endTime = Date.now();
    const generationTime = (endTime - startTime) / 1000;
    
    // Verify report generation completes within 5 seconds
    expect(generationTime).toBeLessThanOrEqual(5);
    
    // Review the generated report for conflict summary data including frequency metrics
    expect(await page.isVisible('[data-testid="report-content"]')).toBeTruthy();
    
    // Verify that the report includes metrics on conflict frequency
    expect(await page.isVisible('[data-testid="conflict-frequency-metrics"]')).toBeTruthy();
    
    // Verify that conflict types are categorized and counted in the report
    expect(await page.isVisible('[data-testid="conflict-types-summary"]')).toBeTruthy();
    const conflictTypesText = await page.textContent('[data-testid="conflict-types-summary"]');
    expect(conflictTypesText).toBeTruthy();
  });

  test('Export report in PDF and Excel formats (happy-path)', async ({ page }) => {
    // Navigate to the conflict reports section and generate a report with valid parameters
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="reporting-section"]');
    await page.click('[data-testid="conflict-reports-option"]');
    
    // Set date range for last 30 days
    const today = new Date();
    const thirtyDaysAgo = new Date(today);
    thirtyDaysAgo.setDate(today.getDate() - 30);
    const startDate = thirtyDaysAgo.toISOString().split('T')[0];
    const endDate = today.toISOString().split('T')[0];
    
    await page.fill('[data-testid="from-date-field"]', startDate);
    await page.fill('[data-testid="to-date-field"]', endDate);
    await page.click('[data-testid="generate-report-button"]');
    
    // Wait for report to be displayed
    await page.waitForSelector('[data-testid="report-content"]', { timeout: 10000 });
    
    // Verify that the report contains data including conflict summaries, metrics, and details
    expect(await page.isVisible('[data-testid="report-content"]')).toBeTruthy();
    expect(await page.isVisible('[data-testid="conflict-frequency-metrics"]')).toBeTruthy();
    
    // Locate and click the 'Export' or 'Download' button/dropdown menu
    await page.click('[data-testid="export-button"]');
    expect(await page.isVisible('[data-testid="export-menu"]')).toBeTruthy();
    
    // Select 'Export as PDF' option from the menu
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-pdf-option"]')
    ]);
    
    // Verify the PDF download completion
    expect(pdfDownload.suggestedFilename()).toContain('.pdf');
    const pdfPath = await pdfDownload.path();
    expect(pdfPath).toBeTruthy();
    
    // Return to the report view and click the 'Export' button again
    await page.click('[data-testid="export-button"]');
    expect(await page.isVisible('[data-testid="export-menu"]')).toBeTruthy();
    
    // Select 'Export as Excel' or 'Export as XLSX' option from the menu
    const [excelDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-excel-option"]')
    ]);
    
    // Verify the Excel download completion
    const excelFilename = excelDownload.suggestedFilename();
    expect(excelFilename.endsWith('.xlsx') || excelFilename.endsWith('.xls')).toBeTruthy();
    const excelPath = await excelDownload.path();
    expect(excelPath).toBeTruthy();
  });

  test('Handle invalid report parameters gracefully (error-case)', async ({ page }) => {
    // Navigate to the conflict reports section
    await page.click('[data-testid="main-menu"]');
    await page.click('[data-testid="reporting-section"]');
    await page.click('[data-testid="conflict-reports-option"]');
    
    // Enter an end date that is earlier than the start date
    await page.fill('[data-testid="from-date-field"]', '2024-01-31');
    await page.fill('[data-testid="to-date-field"]', '2024-01-01');
    
    // Attempt to generate the report by clicking 'Generate Report' button
    await page.click('[data-testid="generate-report-button"]');
    
    // Verify that the error message is clearly visible and user-friendly
    await page.waitForSelector('[data-testid="validation-error"]', { timeout: 5000 });
    expect(await page.isVisible('[data-testid="validation-error"]')).toBeTruthy();
    const errorText = await page.textContent('[data-testid="validation-error"]');
    expect(errorText).toContain('date');
    
    // Verify report generation is blocked
    expect(await page.isVisible('[data-testid="report-content"]')).toBeFalsy();
    
    // Clear the date fields and enter a future date range
    await page.fill('[data-testid="from-date-field"]', '');
    await page.fill('[data-testid="to-date-field"]', '');
    const futureDate = new Date();
    futureDate.setFullYear(futureDate.getFullYear() + 1);
    const futureDateStr = futureDate.toISOString().split('T')[0];
    await page.fill('[data-testid="from-date-field"]', futureDateStr);
    await page.fill('[data-testid="to-date-field"]', futureDateStr);
    
    // Attempt to generate the report
    await page.click('[data-testid="generate-report-button"]');
    await page.waitForSelector('[data-testid="validation-error"]', { timeout: 5000 });
    expect(await page.isVisible('[data-testid="validation-error"]')).toBeTruthy();
    
    // Clear the date fields and leave the start date empty while entering only an end date
    await page.fill('[data-testid="from-date-field"]', '');
    await page.fill('[data-testid="to-date-field"]', '2024-01-31');
    
    // Attempt to generate the report
    await page.click('[data-testid="generate-report-button"]');
    await page.waitForSelector('[data-testid="validation-error"]', { timeout: 5000 });
    expect(await page.isVisible('[data-testid="validation-error"]')).toBeTruthy();
    
    // Enter a valid start date but leave the end date empty
    await page.fill('[data-testid="from-date-field"]', '2024-01-01');
    await page.fill('[data-testid="to-date-field"]', '');
    
    // Attempt to generate the report
    await page.click('[data-testid="generate-report-button"]');
    await page.waitForSelector('[data-testid="validation-error"]', { timeout: 5000 });
    expect(await page.isVisible('[data-testid="validation-error"]')).toBeTruthy();
    
    // Enter an excessively large date range (e.g., 10 years)
    const tenYearsAgo = new Date();
    tenYearsAgo.setFullYear(tenYearsAgo.getFullYear() - 10);
    await page.fill('[data-testid="from-date-field"]', tenYearsAgo.toISOString().split('T')[0]);
    await page.fill('[data-testid="to-date-field"]', new Date().toISOString().split('T')[0]);
    
    // Attempt to generate the report
    await page.click('[data-testid="generate-report-button"]');
    // May show warning or error depending on system limits
    const hasError = await page.isVisible('[data-testid="validation-error"]');
    const hasWarning = await page.isVisible('[data-testid="validation-warning"]');
    expect(hasError || hasWarning).toBeTruthy();
    
    // Correct all validation errors by entering a valid date range (last 30 days)
    const today = new Date();
    const thirtyDaysAgo = new Date(today);
    thirtyDaysAgo.setDate(today.getDate() - 30);
    await page.fill('[data-testid="from-date-field"]', thirtyDaysAgo.toISOString().split('T')[0]);
    await page.fill('[data-testid="to-date-field"]', today.toISOString().split('T')[0]);
    
    // Click 'Generate Report' button
    await page.click('[data-testid="generate-report-button"]');
    
    // Verify report is generated successfully
    await page.waitForSelector('[data-testid="report-content"]', { timeout: 10000 });
    expect(await page.isVisible('[data-testid="report-content"]')).toBeTruthy();
    expect(await page.isVisible('[data-testid="validation-error"]')).toBeFalsy();
  });
});