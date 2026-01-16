import { test, expect } from '@playwright/test';

test.describe('Quote Version History Management', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const API_URL = process.env.API_URL || 'http://localhost:3000/api';

  test.beforeEach(async ({ page }) => {
    // Navigate to quotes list page
    await page.goto(`${BASE_URL}/quotes`);
    await page.waitForLoadState('networkidle');
  });

  test('Verify new version creation on quote edit (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the quotes list and select an existing quote to edit
    await page.waitForSelector('[data-testid="quotes-list"]');
    const firstQuote = page.locator('[data-testid="quote-item"]').first();
    const quoteId = await firstQuote.getAttribute('data-quote-id');
    await firstQuote.click();
    
    // Wait for quote details to load
    await page.waitForSelector('[data-testid="quote-details"]');
    
    // Click edit button
    await page.click('[data-testid="edit-quote-button"]');
    await page.waitForSelector('[data-testid="quote-edit-form"]');
    
    // Get initial version number
    const initialVersionResponse = await page.request.get(`${API_URL}/quotes/${quoteId}/versions`);
    expect(initialVersionResponse.ok()).toBeTruthy();
    const initialVersions = await initialVersionResponse.json();
    const initialVersionCount = initialVersions.length;
    const expectedNewVersion = initialVersionCount + 1;
    
    // Step 2: Modify one or more fields in the quote
    await page.fill('[data-testid="quote-price-input"]', '15000');
    await page.fill('[data-testid="quote-description-input"]', 'Updated quote description for version testing');
    await page.fill('[data-testid="quote-terms-input"]', 'Net 45 days payment terms');
    
    // Step 3: Click the 'Save' or 'Submit' button to save the changes
    await page.click('[data-testid="save-quote-button"]');
    
    // Wait for success confirmation
    await page.waitForSelector('[data-testid="save-success-message"]', { timeout: 5000 });
    const successMessage = await page.locator('[data-testid="save-success-message"]').textContent();
    expect(successMessage).toContain('successfully');
    
    // Step 4: Verify that a new version record is created with an incremented version number
    await page.waitForTimeout(500); // Allow backend processing
    const newVersionResponse = await page.request.get(`${API_URL}/quotes/${quoteId}/versions`);
    expect(newVersionResponse.ok()).toBeTruthy();
    const newVersions = await newVersionResponse.json();
    
    expect(newVersions.length).toBe(initialVersionCount + 1);
    const latestVersion = newVersions[newVersions.length - 1];
    expect(latestVersion.versionNumber).toBe(expectedNewVersion);
    expect(latestVersion.price).toBe('15000');
    expect(latestVersion.description).toContain('Updated quote description');
    
    // Step 5: Navigate to the version history section
    await page.click('[data-testid="version-history-tab"]');
    await page.waitForSelector('[data-testid="version-history-list"]');
    
    // Step 6: Retrieve version history and verify all versions are listed with correct timestamps
    const versionItems = page.locator('[data-testid="version-item"]');
    const versionCount = await versionItems.count();
    expect(versionCount).toBe(initialVersionCount + 1);
    
    // Verify timestamps exist for all versions
    for (let i = 0; i < versionCount; i++) {
      const versionItem = versionItems.nth(i);
      const timestamp = await versionItem.locator('[data-testid="version-timestamp"]').textContent();
      expect(timestamp).toBeTruthy();
      expect(timestamp).toMatch(/\d{4}-\d{2}-\d{2}|\d{1,2}\/\d{1,2}\/\d{4}/);
    }
    
    // Step 7: Select a previous version record from the version history
    const previousVersion = versionItems.first();
    await previousVersion.click();
    await page.waitForSelector('[data-testid="version-details"]');
    
    // Step 8: Attempt to edit any field in the previous version record
    const editButton = page.locator('[data-testid="edit-version-button"]');
    
    // Verify edit button is disabled or not present for previous versions
    if (await editButton.count() > 0) {
      await expect(editButton).toBeDisabled();
    }
    
    // Attempt to modify input fields directly
    const priceInput = page.locator('[data-testid="version-price-input"]');
    if (await priceInput.count() > 0) {
      await expect(priceInput).toBeDisabled();
      await expect(priceInput).toHaveAttribute('readonly', '');
    }
    
    // Verify read-only message is displayed
    const readOnlyMessage = page.locator('[data-testid="read-only-warning"]');
    if (await readOnlyMessage.count() > 0) {
      const message = await readOnlyMessage.textContent();
      expect(message).toMatch(/read-only|cannot be edited|historical version/i);
    }
  });

  test('Ensure version creation latency is within SLA (boundary)', async ({ page }) => {
    // Step 1: Navigate to an existing quote and open it for editing
    await page.waitForSelector('[data-testid="quotes-list"]');
    const firstQuote = page.locator('[data-testid="quote-item"]').first();
    const quoteId = await firstQuote.getAttribute('data-quote-id');
    await firstQuote.click();
    
    await page.waitForSelector('[data-testid="quote-details"]');
    await page.click('[data-testid="edit-quote-button"]');
    await page.waitForSelector('[data-testid="quote-edit-form"]');
    
    // Step 2: Make a modification to one or more fields in the quote
    const timestamp = Date.now();
    await page.fill('[data-testid="quote-price-input"]', `${12000 + timestamp % 1000}`);
    await page.fill('[data-testid="quote-description-input"]', `Performance test description ${timestamp}`);
    
    // Step 3: Start a timer and click 'Save' or 'Submit' to submit the quote edit
    const startTime = Date.now();
    
    await page.click('[data-testid="save-quote-button"]');
    
    // Step 4: Monitor the time taken from submission until the system confirms version creation completion
    await page.waitForSelector('[data-testid="save-success-message"]', { timeout: 5000 });
    
    const endTime = Date.now();
    const latency = endTime - startTime;
    
    // Verify version creation latency is within 1 second (1000ms) SLA
    expect(latency).toBeLessThanOrEqual(1000);
    
    // Step 5: Verify that the new version record is successfully created in the database
    const versionResponse = await page.request.get(`${API_URL}/quotes/${quoteId}/versions`);
    expect(versionResponse.ok()).toBeTruthy();
    const versions = await versionResponse.json();
    
    // Verify latest version exists
    expect(versions.length).toBeGreaterThan(0);
    const latestVersion = versions[versions.length - 1];
    
    // Verify version has required fields
    expect(latestVersion.versionNumber).toBeDefined();
    expect(latestVersion.userId).toBeDefined();
    expect(latestVersion.timestamp).toBeDefined();
    expect(latestVersion.price).toBeDefined();
    
    // Verify timestamp is recent (within last 5 seconds)
    const versionTimestamp = new Date(latestVersion.timestamp).getTime();
    const timeDifference = Date.now() - versionTimestamp;
    expect(timeDifference).toBeLessThan(5000);
    
    // Log performance metrics for monitoring
    console.log(`Version creation latency: ${latency}ms (SLA: 1000ms)`);
    console.log(`Version created successfully with version number: ${latestVersion.versionNumber}`);
  });
});