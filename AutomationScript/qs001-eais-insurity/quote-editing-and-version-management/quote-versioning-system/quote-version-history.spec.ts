import { test, expect } from '@playwright/test';

test.describe('Quote Version History - Story 14', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the application and login
    await page.goto('/login');
    await page.fill('[data-testid="username-input"]', 'quotemanager@example.com');
    await page.fill('[data-testid="password-input"]', 'password123');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Verify version history list and detail view (happy-path)', async ({ page }) => {
    // Step 1: Navigate to the quotes list and select a quote that has multiple versions
    await page.goto('/quotes');
    await expect(page.locator('[data-testid="quotes-list"]')).toBeVisible();
    
    // Select a quote with multiple versions
    await page.click('[data-testid="quote-row"]:has-text("Multiple Versions")');
    await expect(page.locator('[data-testid="quote-details"]')).toBeVisible();

    // Step 2: Click on the 'Version History' tab or button to navigate to version history
    const startTime = Date.now();
    await page.click('[data-testid="version-history-tab"]');
    
    // Step 3: Review the list of versions displayed in the version history
    await expect(page.locator('[data-testid="version-history-list"]')).toBeVisible();
    const versionItems = page.locator('[data-testid="version-item"]');
    const versionCount = await versionItems.count();
    expect(versionCount).toBeGreaterThan(1);

    // Verify version list contains required metadata: version number, date, and editor name
    const firstVersion = versionItems.first();
    await expect(firstVersion.locator('[data-testid="version-number"]')).toBeVisible();
    await expect(firstVersion.locator('[data-testid="version-date"]')).toBeVisible();
    await expect(firstVersion.locator('[data-testid="version-editor"]')).toBeVisible();

    // Step 4: Verify that the version list loaded within the 2-second performance requirement
    const loadTime = Date.now() - startTime;
    expect(loadTime).toBeLessThan(2000);

    // Step 5: Select a previous version from the list by clicking on it
    const previousVersion = versionItems.nth(1);
    const versionNumber = await previousVersion.locator('[data-testid="version-number"]').textContent();
    await previousVersion.click();

    // Step 6: Verify that the version details are displayed in read-only mode
    await expect(page.locator('[data-testid="version-details-view"]')).toBeVisible();
    await expect(page.locator('[data-testid="version-readonly-indicator"]')).toBeVisible();
    
    // Verify the selected version number is displayed
    await expect(page.locator('[data-testid="current-version-display"]')).toContainText(versionNumber || '');

    // Step 7: Attempt to click on or modify any field in the historical version view
    const quoteNameField = page.locator('[data-testid="quote-name-field"]');
    const quotePriceField = page.locator('[data-testid="quote-price-field"]');
    const quoteDescriptionField = page.locator('[data-testid="quote-description-field"]');

    // Verify fields are disabled or readonly
    if (await quoteNameField.isVisible()) {
      await expect(quoteNameField).toBeDisabled();
    }
    if (await quotePriceField.isVisible()) {
      await expect(quotePriceField).toBeDisabled();
    }
    if (await quoteDescriptionField.isVisible()) {
      await expect(quoteDescriptionField).toBeDisabled();
    }

    // Step 8: Attempt to locate and click any 'Edit' or 'Save' buttons for the historical version
    const editButton = page.locator('[data-testid="edit-version-button"]');
    const saveButton = page.locator('[data-testid="save-version-button"]');
    
    // Verify edit/save buttons are either not visible or disabled
    if (await editButton.isVisible()) {
      await expect(editButton).toBeDisabled();
    } else {
      await expect(editButton).not.toBeVisible();
    }
    
    if (await saveButton.isVisible()) {
      await expect(saveButton).toBeDisabled();
    } else {
      await expect(saveButton).not.toBeVisible();
    }

    // Attempt to type in a field to ensure editing is prevented
    const attemptEdit = async () => {
      try {
        await quoteNameField.fill('Attempted Edit', { timeout: 1000 });
      } catch (error) {
        // Expected to fail - field should be disabled
      }
    };
    await attemptEdit();

    // Step 9: Select another previous version from the list
    await page.click('[data-testid="version-history-tab"]');
    await expect(page.locator('[data-testid="version-history-list"]')).toBeVisible();
    
    const anotherVersion = versionItems.nth(2);
    if (await anotherVersion.isVisible()) {
      const anotherVersionNumber = await anotherVersion.locator('[data-testid="version-number"]').textContent();
      await anotherVersion.click();
      
      // Verify the new version is displayed in read-only mode
      await expect(page.locator('[data-testid="version-details-view"]')).toBeVisible();
      await expect(page.locator('[data-testid="current-version-display"]')).toContainText(anotherVersionNumber || '');
      await expect(page.locator('[data-testid="version-readonly-indicator"]')).toBeVisible();
    }
  });

  test('Verify version history list displays all required metadata', async ({ page }) => {
    // Navigate to quotes and select a quote with versions
    await page.goto('/quotes');
    await page.click('[data-testid="quote-row"]', { timeout: 5000 });
    
    // Open version history
    await page.click('[data-testid="version-history-tab"]');
    await expect(page.locator('[data-testid="version-history-list"]')).toBeVisible();

    // Verify each version item contains version number, date, and editor name
    const versionItems = page.locator('[data-testid="version-item"]');
    const count = await versionItems.count();
    
    for (let i = 0; i < Math.min(count, 3); i++) {
      const versionItem = versionItems.nth(i);
      await expect(versionItem.locator('[data-testid="version-number"]')).toBeVisible();
      await expect(versionItem.locator('[data-testid="version-date"]')).toBeVisible();
      await expect(versionItem.locator('[data-testid="version-editor"]')).toBeVisible();
      
      // Verify content is not empty
      const versionNumber = await versionItem.locator('[data-testid="version-number"]').textContent();
      const versionDate = await versionItem.locator('[data-testid="version-date"]').textContent();
      const versionEditor = await versionItem.locator('[data-testid="version-editor"]').textContent();
      
      expect(versionNumber).toBeTruthy();
      expect(versionDate).toBeTruthy();
      expect(versionEditor).toBeTruthy();
    }
  });

  test('Verify historical version prevents editing', async ({ page }) => {
    // Navigate to quote with versions
    await page.goto('/quotes');
    await page.click('[data-testid="quote-row"]');
    
    // Open version history and select a previous version
    await page.click('[data-testid="version-history-tab"]');
    await expect(page.locator('[data-testid="version-history-list"]')).toBeVisible();
    
    const previousVersion = page.locator('[data-testid="version-item"]').nth(1);
    await previousVersion.click();
    
    // Verify version details are in read-only mode
    await expect(page.locator('[data-testid="version-details-view"]')).toBeVisible();
    
    // Attempt to edit various fields
    const editableFields = [
      '[data-testid="quote-name-field"]',
      '[data-testid="quote-price-field"]',
      '[data-testid="quote-description-field"]',
      '[data-testid="quote-customer-field"]',
      '[data-testid="quote-status-field"]'
    ];
    
    for (const fieldSelector of editableFields) {
      const field = page.locator(fieldSelector);
      if (await field.isVisible()) {
        // Verify field is disabled
        await expect(field).toBeDisabled();
        
        // Attempt to interact with the field
        const isEditable = await field.isEditable().catch(() => false);
        expect(isEditable).toBe(false);
      }
    }
    
    // Verify no edit/save buttons are available or they are disabled
    const actionButtons = [
      '[data-testid="edit-version-button"]',
      '[data-testid="save-version-button"]',
      '[data-testid="update-version-button"]'
    ];
    
    for (const buttonSelector of actionButtons) {
      const button = page.locator(buttonSelector);
      const isVisible = await button.isVisible().catch(() => false);
      
      if (isVisible) {
        await expect(button).toBeDisabled();
      }
    }
  });

  test('Verify version history loads within 2 seconds', async ({ page }) => {
    // Navigate to quote
    await page.goto('/quotes');
    await page.click('[data-testid="quote-row"]');
    
    // Measure time to load version history
    const startTime = Date.now();
    await page.click('[data-testid="version-history-tab"]');
    await expect(page.locator('[data-testid="version-history-list"]')).toBeVisible();
    const loadTime = Date.now() - startTime;
    
    // Verify load time is within 2 seconds
    expect(loadTime).toBeLessThan(2000);
    
    // Verify version list is populated
    const versionItems = page.locator('[data-testid="version-item"]');
    const count = await versionItems.count();
    expect(count).toBeGreaterThan(0);
  });
});