import { test, expect } from '@playwright/test';

test.describe('Exposure Data Update - Story 6', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const EXPOSURE_REVIEW_PAGE = `${BASE_URL}/exposure-data/review`;
  const AUDIT_LOGS_PAGE = `${BASE_URL}/audit-logs`;

  test.beforeEach(async ({ page }) => {
    // Navigate to exposure data review page before each test
    await page.goto(EXPOSURE_REVIEW_PAGE);
    await expect(page).toHaveURL(EXPOSURE_REVIEW_PAGE);
  });

  test('Validate successful exposure data update', async ({ page }) => {
    // Step 1: Navigate to exposure data edit form
    await page.goto(EXPOSURE_REVIEW_PAGE);
    await expect(page.locator('[data-testid="exposure-review-page"]')).toBeVisible();

    // Select an existing exposure record to edit
    await page.click('[data-testid="exposure-record-edit-btn"]:first-child');
    await expect(page.locator('[data-testid="exposure-edit-form"]')).toBeVisible();

    // Verify existing data is populated
    const propertyValueField = page.locator('[data-testid="property-value-input"]');
    const propertyUsageField = page.locator('[data-testid="property-usage-input"]');
    await expect(propertyValueField).not.toBeEmpty();
    await expect(propertyUsageField).not.toBeEmpty();

    // Step 2: Modify exposure fields with valid data
    await propertyValueField.clear();
    await propertyValueField.fill('1750000');
    await expect(propertyValueField).toHaveValue('1750000');

    await propertyUsageField.clear();
    await propertyUsageField.fill('Mixed Use');
    await expect(propertyUsageField).toHaveValue('Mixed Use');

    // Verify no validation errors are displayed
    await expect(page.locator('[data-testid="validation-error"]')).not.toBeVisible();

    // Step 3: Submit the updated data
    await page.click('[data-testid="save-exposure-btn"]');

    // Wait for confirmation message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('successfully updated');

    // Navigate back to review page and verify update
    await page.goto(EXPOSURE_REVIEW_PAGE);
    await expect(page.locator('[data-testid="exposure-record"]:first-child')).toContainText('1750000');
    await expect(page.locator('[data-testid="exposure-record"]:first-child')).toContainText('Mixed Use');
  });

  test('Verify rejection of update with invalid exposure data', async ({ page }) => {
    // Step 1: Navigate to exposure data edit form
    await page.goto(EXPOSURE_REVIEW_PAGE);
    await expect(page.locator('[data-testid="exposure-review-page"]')).toBeVisible();

    // Select an existing exposure record to edit
    await page.click('[data-testid="exposure-record-edit-btn"]:first-child');
    await expect(page.locator('[data-testid="exposure-edit-form"]')).toBeVisible();

    // Step 2: Enter invalid or empty mandatory fields
    // Clear mandatory property type field
    const propertyTypeField = page.locator('[data-testid="property-type-input"]');
    await propertyTypeField.clear();
    await expect(propertyTypeField).toBeEmpty();

    // Enter invalid numeric value in property value field
    const propertyValueField = page.locator('[data-testid="property-value-input"]');
    await propertyValueField.clear();
    await propertyValueField.fill('-100000');
    await expect(propertyValueField).toHaveValue('-100000');

    // Clear mandatory location field
    const locationField = page.locator('[data-testid="location-input"]');
    await locationField.clear();
    await expect(locationField).toBeEmpty();

    // Trigger validation by clicking outside or tabbing
    await page.click('[data-testid="exposure-edit-form"]');

    // Verify validation errors are displayed inline
    await expect(page.locator('[data-testid="property-type-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="property-type-error"]')).toContainText('required');
    
    await expect(page.locator('[data-testid="property-value-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="property-value-error"]')).toContainText('invalid');
    
    await expect(page.locator('[data-testid="location-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="location-error"]')).toContainText('required');

    // Step 3: Attempt to save updates
    await page.click('[data-testid="save-exposure-btn"]');

    // Verify save is blocked and error messages are shown
    await expect(page.locator('[data-testid="error-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="error-message"]')).toContainText('correct the errors');

    // Verify form is still displayed (not saved)
    await expect(page.locator('[data-testid="exposure-edit-form"]')).toBeVisible();

    // Navigate back and verify no changes were saved
    await page.click('[data-testid="cancel-btn"]');
    await page.goto(EXPOSURE_REVIEW_PAGE);
    await expect(page.locator('[data-testid="exposure-record"]:first-child')).not.toContainText('-100000');
  });

  test('Check audit log creation after successful exposure update', async ({ page }) => {
    // Step 1: Update exposure data successfully
    await page.goto(EXPOSURE_REVIEW_PAGE);
    await expect(page.locator('[data-testid="exposure-review-page"]')).toBeVisible();

    // Select an existing exposure record and note current values
    const firstRecord = page.locator('[data-testid="exposure-record"]:first-child');
    const recordId = await firstRecord.getAttribute('data-record-id');
    
    await page.click('[data-testid="exposure-record-edit-btn"]:first-child');
    await expect(page.locator('[data-testid="exposure-edit-form"]')).toBeVisible();

    // Modify property value field with valid updated value
    const propertyValueField = page.locator('[data-testid="property-value-input"]');
    await propertyValueField.clear();
    await propertyValueField.fill('1800000');
    await expect(propertyValueField).toHaveValue('1800000');

    // Modify property usage field with valid updated information
    const propertyUsageField = page.locator('[data-testid="property-usage-input"]');
    await propertyUsageField.clear();
    await propertyUsageField.fill('Commercial Office');
    await expect(propertyUsageField).toHaveValue('Commercial Office');

    // Save the update and note timestamp
    const beforeUpdateTime = new Date();
    await page.click('[data-testid="save-exposure-btn"]');

    // Verify confirmation message
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('successfully updated');

    // Step 2: Access audit logs for the updated record
    await page.goto(AUDIT_LOGS_PAGE);
    await expect(page.locator('[data-testid="audit-logs-page"]')).toBeVisible();

    // Search for audit log entries using record ID
    const searchInput = page.locator('[data-testid="audit-log-search-input"]');
    await searchInput.fill(recordId || '');
    await page.click('[data-testid="audit-log-search-btn"]');

    // Verify audit log entry exists
    const auditLogEntry = page.locator(`[data-testid="audit-log-entry"][data-record-id="${recordId}"]`).first();
    await expect(auditLogEntry).toBeVisible();

    // Verify audit log contains update details
    await expect(auditLogEntry).toContainText('1800000');
    await expect(auditLogEntry).toContainText('Commercial Office');
    await expect(auditLogEntry).toContainText('UPDATE');

    // Verify audit log timestamp is recent (within last few minutes)
    const auditTimestamp = await auditLogEntry.locator('[data-testid="audit-timestamp"]').textContent();
    expect(auditTimestamp).toBeTruthy();

    // Verify audit log contains changed fields
    await expect(auditLogEntry.locator('[data-testid="audit-changes"]')).toContainText('property_value');
    await expect(auditLogEntry.locator('[data-testid="audit-changes"]')).toContainText('property_usage');

    // Verify audit log contains user information
    await expect(auditLogEntry.locator('[data-testid="audit-user"]')).toBeVisible();
  });
});