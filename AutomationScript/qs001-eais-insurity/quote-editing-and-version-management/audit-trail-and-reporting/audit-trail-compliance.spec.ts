import { test, expect } from '@playwright/test';

test.describe('Audit Trail Compliance - Story 13', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const QUOTE_MANAGER_EMAIL = 'quote.manager@company.com';
  const QUOTE_MANAGER_PASSWORD = 'QuoteManager123!';
  const COMPLIANCE_OFFICER_EMAIL = 'compliance.officer@company.com';
  const COMPLIANCE_OFFICER_PASSWORD = 'Compliance123!';
  const UNAUTHORIZED_USER_EMAIL = 'regular.user@company.com';
  const UNAUTHORIZED_USER_PASSWORD = 'RegularUser123!';
  const TEST_QUOTE_ID = 'Q-2024-001';

  let editTimestamp: string;
  let quoteManagerUserId: string;

  test('Validate audit log creation for quote edits (happy-path)', async ({ page }) => {
    // Step 1: Log into the system as Quote Manager user
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', QUOTE_MANAGER_EMAIL);
    await page.fill('[data-testid="password-input"]', QUOTE_MANAGER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="user-profile"]')).toBeVisible();

    // Step 2: Navigate to an existing quote and open it for editing
    await page.goto(`${BASE_URL}/quotes`);
    await page.fill('[data-testid="quote-search-input"]', TEST_QUOTE_ID);
    await page.click('[data-testid="search-button"]');
    await page.click(`[data-testid="quote-row-${TEST_QUOTE_ID}"]`);
    await expect(page.locator('[data-testid="quote-details-header"]')).toBeVisible();
    await page.click('[data-testid="edit-quote-button"]');

    // Step 3: Make a change to the quote
    const originalPrice = await page.locator('[data-testid="quote-price-input"]').inputValue();
    const newPrice = (parseFloat(originalPrice) + 100).toFixed(2);
    await page.fill('[data-testid="quote-price-input"]', newPrice);
    await page.fill('[data-testid="quote-terms-textarea"]', 'Updated terms for audit trail testing');
    
    // Step 4: Note the current timestamp and Quote Manager user ID
    editTimestamp = new Date().toISOString();
    quoteManagerUserId = await page.locator('[data-testid="user-id"]').textContent() || 'QM-001';
    
    await page.click('[data-testid="save-quote-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Quote updated successfully');

    // Step 5: Log out as Quote Manager
    await page.click('[data-testid="user-profile"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Step 6: Log in as Compliance Officer
    await page.fill('[data-testid="email-input"]', COMPLIANCE_OFFICER_EMAIL);
    await page.fill('[data-testid="password-input"]', COMPLIANCE_OFFICER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="user-profile"]')).toBeVisible();

    // Step 7: Navigate to the audit trail search interface
    await page.goto(`${BASE_URL}/audit-trail`);
    await expect(page.locator('[data-testid="audit-trail-header"]')).toBeVisible();

    // Step 8: Enter search filters
    await page.fill('[data-testid="audit-quote-id-filter"]', TEST_QUOTE_ID);
    await page.fill('[data-testid="audit-user-id-filter"]', quoteManagerUserId);
    
    const startDate = new Date(editTimestamp);
    startDate.setHours(startDate.getHours() - 1);
    const endDate = new Date(editTimestamp);
    endDate.setHours(endDate.getHours() + 1);
    
    await page.fill('[data-testid="audit-start-date-filter"]', startDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="audit-end-date-filter"]', endDate.toISOString().split('T')[0]);

    // Step 9: Start timer and submit the search query
    const searchStartTime = Date.now();
    await page.click('[data-testid="audit-search-button"]');
    await page.waitForSelector('[data-testid="audit-results-table"]');
    const searchEndTime = Date.now();
    const searchDuration = searchEndTime - searchStartTime;

    // Verify search results returned within 3 seconds
    expect(searchDuration).toBeLessThan(3000);

    // Step 10: Verify the audit log entry contains correct information
    const auditRow = page.locator('[data-testid="audit-row"]').first();
    await expect(auditRow.locator('[data-testid="audit-user-id"]')).toContainText(quoteManagerUserId);
    await expect(auditRow.locator('[data-testid="audit-quote-id"]')).toContainText(TEST_QUOTE_ID);
    await expect(auditRow.locator('[data-testid="audit-action"]')).toContainText('Quote Updated');
    
    const auditTimestamp = await auditRow.locator('[data-testid="audit-timestamp"]').textContent();
    expect(auditTimestamp).toBeTruthy();
    
    await auditRow.click();
    await expect(page.locator('[data-testid="audit-detail-panel"]')).toBeVisible();
    await expect(page.locator('[data-testid="audit-change-details"]')).toContainText('price');
    await expect(page.locator('[data-testid="audit-change-details"]')).toContainText(newPrice);

    // Step 11: Log out as Compliance Officer
    await page.click('[data-testid="user-profile"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Step 12: Log in as unauthorized user
    await page.fill('[data-testid="email-input"]', UNAUTHORIZED_USER_EMAIL);
    await page.fill('[data-testid="password-input"]', UNAUTHORIZED_USER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="user-profile"]')).toBeVisible();

    // Step 13: Attempt to navigate to the audit trail interface
    await page.goto(`${BASE_URL}/audit-trail`);
    
    // Verify access denied message is displayed
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('not authorized');
  });

  test('Verify audit report export functionality (happy-path)', async ({ page }) => {
    // Step 1: Log into the system as Compliance Officer
    await page.goto(`${BASE_URL}/login`);
    await page.fill('[data-testid="email-input"]', COMPLIANCE_OFFICER_EMAIL);
    await page.fill('[data-testid="password-input"]', COMPLIANCE_OFFICER_PASSWORD);
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="user-profile"]')).toBeVisible();

    // Step 2: Navigate to the audit trail search interface
    await page.goto(`${BASE_URL}/audit-trail`);
    await expect(page.locator('[data-testid="audit-trail-header"]')).toBeVisible();

    // Step 3: Apply filters to generate a specific audit report
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - 7);
    
    await page.fill('[data-testid="audit-start-date-filter"]', startDate.toISOString().split('T')[0]);
    await page.fill('[data-testid="audit-end-date-filter"]', endDate.toISOString().split('T')[0]);

    // Step 4: Click the search or generate report button
    await page.click('[data-testid="audit-search-button"]');
    await page.waitForSelector('[data-testid="audit-results-table"]');

    // Step 5: Review the displayed report for accuracy
    await expect(page.locator('[data-testid="audit-column-user-id"]')).toBeVisible();
    await expect(page.locator('[data-testid="audit-column-timestamp"]')).toBeVisible();
    await expect(page.locator('[data-testid="audit-column-quote-id"]')).toBeVisible();
    await expect(page.locator('[data-testid="audit-column-action"]')).toBeVisible();
    await expect(page.locator('[data-testid="audit-column-changes"]')).toBeVisible();

    // Step 6: Count the number of records displayed
    const displayedRecords = await page.locator('[data-testid="audit-row"]').count();
    expect(displayedRecords).toBeGreaterThan(0);

    // Collect sample data for verification
    const firstRowUserId = await page.locator('[data-testid="audit-row"]').first().locator('[data-testid="audit-user-id"]').textContent();
    const firstRowQuoteId = await page.locator('[data-testid="audit-row"]').first().locator('[data-testid="audit-quote-id"]').textContent();

    // Step 7: Click the 'Export as PDF' button
    const [pdfDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-pdf-button"]')
    ]);

    // Step 8: Verify PDF download
    expect(pdfDownload.suggestedFilename()).toMatch(/audit.*\.pdf$/i);
    const pdfPath = await pdfDownload.path();
    expect(pdfPath).toBeTruthy();

    // Step 9: Verify PDF content (basic validation)
    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible({ timeout: 5000 });

    // Step 10: Return to the audit trail interface and click 'Export as CSV'
    const [csvDownload] = await Promise.all([
      page.waitForEvent('download'),
      page.click('[data-testid="export-csv-button"]')
    ]);

    // Step 11: Verify CSV download
    expect(csvDownload.suggestedFilename()).toMatch(/audit.*\.csv$/i);
    const csvPath = await csvDownload.path();
    expect(csvPath).toBeTruthy();

    // Step 12: Verify CSV content
    const fs = require('fs');
    const csvContent = fs.readFileSync(csvPath, 'utf-8');
    
    // Verify CSV headers
    expect(csvContent).toContain('User ID');
    expect(csvContent).toContain('Timestamp');
    expect(csvContent).toContain('Quote ID');
    expect(csvContent).toContain('Action');
    expect(csvContent).toContain('Changes');

    // Verify sample data is present in CSV
    if (firstRowUserId) {
      expect(csvContent).toContain(firstRowUserId);
    }
    if (firstRowQuoteId) {
      expect(csvContent).toContain(firstRowQuoteId);
    }

    // Verify number of data rows in CSV matches displayed records
    const csvLines = csvContent.split('\n').filter(line => line.trim().length > 0);
    const csvDataRows = csvLines.length - 1; // Subtract header row
    expect(csvDataRows).toBe(displayedRecords);

    await expect(page.locator('[data-testid="export-success-message"]')).toBeVisible();
  });
});