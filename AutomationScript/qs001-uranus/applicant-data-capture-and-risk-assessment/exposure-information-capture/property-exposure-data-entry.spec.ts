import { test, expect } from '@playwright/test';

test.describe('Property Exposure Data Entry', () => {
  const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
  const PROPERTY_EXPOSURE_URL = `${BASE_URL}/exposures/property`;

  test.beforeEach(async ({ page }) => {
    // Navigate to property exposure data entry form before each test
    await page.goto(PROPERTY_EXPOSURE_URL);
    // Wait for form to be fully loaded
    await page.waitForLoadState('networkidle');
  });

  test('Validate successful property exposure data submission (happy-path)', async ({ page }) => {
    // Step 1: Verify form is displayed with all mandatory fields
    await expect(page.locator('[data-testid="property-exposure-form"]')).toBeVisible();
    await expect(page.locator('[data-testid="property-type-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="location-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="property-value-field"]')).toBeVisible();
    await expect(page.locator('[data-testid="property-usage-field"]')).toBeVisible();

    // Step 2: Enter valid property type
    await page.locator('[data-testid="property-type-field"]').click();
    await page.locator('[data-testid="property-type-option-commercial-building"]').click();
    await expect(page.locator('[data-testid="property-type-field"]')).toContainText('Commercial Building');

    // Enter valid location details
    await page.locator('[data-testid="location-field"]').fill('123 Main Street, New York, NY 10001');
    await expect(page.locator('[data-testid="location-field"]')).toHaveValue('123 Main Street, New York, NY 10001');

    // Enter valid property value
    await page.locator('[data-testid="property-value-field"]').fill('1500000');
    await expect(page.locator('[data-testid="property-value-field"]')).toHaveValue('1500000');
    // Verify no validation errors for valid numeric input
    await expect(page.locator('[data-testid="property-value-error"]')).not.toBeVisible();

    // Enter valid property usage
    await page.locator('[data-testid="property-usage-field"]').click();
    await page.locator('[data-testid="property-usage-option-office-space"]').click();
    await expect(page.locator('[data-testid="property-usage-field"]')).toContainText('Office Space');

    // Step 3: Click on document attachment button and select valid supporting documents
    const fileInput = page.locator('[data-testid="document-upload-input"]');
    await fileInput.setInputFiles({
      name: 'property-document.pdf',
      mimeType: 'application/pdf',
      buffer: Buffer.from('Mock PDF content for testing purposes')
    });

    // Verify file appears in attachment list
    await expect(page.locator('[data-testid="attached-file-property-document.pdf"]')).toBeVisible();
    await expect(page.locator('[data-testid="attached-file-property-document.pdf"]')).toContainText('property-document.pdf');

    // Review all entered data for accuracy
    await expect(page.locator('[data-testid="property-type-field"]')).toContainText('Commercial Building');
    await expect(page.locator('[data-testid="location-field"]')).toHaveValue('123 Main Street, New York, NY 10001');
    await expect(page.locator('[data-testid="property-value-field"]')).toHaveValue('1500000');
    await expect(page.locator('[data-testid="property-usage-field"]')).toContainText('Office Space');

    // Click the Submit button
    await page.locator('[data-testid="submit-exposure-button"]').click();

    // Verify the confirmation message details
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Property exposure data saved successfully');
    
    // Verify data was saved by checking for confirmation details
    await expect(page.locator('[data-testid="confirmation-property-type"]')).toContainText('Commercial Building');
    await expect(page.locator('[data-testid="confirmation-location"]')).toContainText('123 Main Street, New York, NY 10001');
    await expect(page.locator('[data-testid="confirmation-value"]')).toContainText('1500000');
  });

  test('Verify rejection of submission with invalid exposure data (error-case)', async ({ page }) => {
    // Step 1: Verify form is displayed
    await expect(page.locator('[data-testid="property-exposure-form"]')).toBeVisible();

    // Step 2: Leave property type field empty (skip filling it)
    // Verify property type is empty or has placeholder
    const propertyTypeField = page.locator('[data-testid="property-type-field"]');
    await expect(propertyTypeField).toBeVisible();

    // Enter invalid numeric value in property value field (alphabetic characters)
    await page.locator('[data-testid="property-value-field"]').fill('invalid-value');
    await page.locator('[data-testid="property-value-field"]').blur();
    
    // Verify validation error for invalid numeric input
    await expect(page.locator('[data-testid="property-value-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="property-value-error"]')).toContainText(/invalid|numeric|number/i);

    // Clear and enter negative value
    await page.locator('[data-testid="property-value-field"]').clear();
    await page.locator('[data-testid="property-value-field"]').fill('-50000');
    await page.locator('[data-testid="property-value-field"]').blur();
    
    // Verify validation error for negative value
    await expect(page.locator('[data-testid="property-value-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="property-value-error"]')).toContainText(/positive|greater than zero/i);

    // Leave location field empty (skip filling it)
    const locationField = page.locator('[data-testid="location-field"]');
    await expect(locationField).toHaveValue('');

    // Enter property value exceeding maximum allowed range
    await page.locator('[data-testid="property-value-field"]').clear();
    await page.locator('[data-testid="property-value-field"]').fill('999999999999');
    await page.locator('[data-testid="property-value-field"]').blur();
    
    // Verify validation error for exceeding maximum range
    await expect(page.locator('[data-testid="property-value-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="property-value-error"]')).toContainText(/maximum|exceeds|range/i);

    // Step 3: Click the Submit button
    await page.locator('[data-testid="submit-exposure-button"]').click();

    // Verify error messages displayed on the form
    await expect(page.locator('[data-testid="property-type-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="property-type-error"]')).toContainText(/required|mandatory/i);
    
    await expect(page.locator('[data-testid="location-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="location-error"]')).toContainText(/required|mandatory/i);
    
    await expect(page.locator('[data-testid="property-value-error"]')).toBeVisible();

    // Verify that submission was blocked (no success message)
    await expect(page.locator('[data-testid="success-message"]')).not.toBeVisible();
    
    // Verify form is still displayed (not navigated away)
    await expect(page.locator('[data-testid="property-exposure-form"]')).toBeVisible();
  });

  test('Test document attachment restrictions (boundary)', async ({ page }) => {
    // Step 1: Verify form is displayed
    await expect(page.locator('[data-testid="property-exposure-form"]')).toBeVisible();

    // Step 2: Click on document attachment button and select a file exceeding size limit (15MB PDF)
    const fileInput = page.locator('[data-testid="document-upload-input"]');
    
    // Create a large file buffer (15MB)
    const largeFileBuffer = Buffer.alloc(15 * 1024 * 1024, 'a');
    await fileInput.setInputFiles({
      name: 'large-document.pdf',
      mimeType: 'application/pdf',
      buffer: largeFileBuffer
    });

    // Verify the file is not added to the attachment list
    await expect(page.locator('[data-testid="file-size-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="file-size-error"]')).toContainText(/size limit|maximum size|too large/i);
    await expect(page.locator('[data-testid="attached-file-large-document.pdf"]')).not.toBeVisible();

    // Step 3: Click on document attachment button and select an unsupported file format (.exe file)
    await fileInput.setInputFiles({
      name: 'malicious-file.exe',
      mimeType: 'application/x-msdownload',
      buffer: Buffer.from('Mock executable content')
    });

    // Verify the unsupported file is not added to the attachment list
    await expect(page.locator('[data-testid="file-type-error"]')).toBeVisible();
    await expect(page.locator('[data-testid="file-type-error"]')).toContainText(/unsupported|invalid format|file type/i);
    await expect(page.locator('[data-testid="attached-file-malicious-file.exe"]')).not.toBeVisible();

    // Step 4: Click on document attachment button and select a valid file (2MB PDF)
    const validFileBuffer = Buffer.alloc(2 * 1024 * 1024, 'b');
    await fileInput.setInputFiles({
      name: 'valid-property-document.pdf',
      mimeType: 'application/pdf',
      buffer: validFileBuffer
    });

    // Verify the valid file appears in the attachment list
    await expect(page.locator('[data-testid="attached-file-valid-property-document.pdf"]')).toBeVisible();
    await expect(page.locator('[data-testid="attached-file-valid-property-document.pdf"]')).toContainText('valid-property-document.pdf');
    
    // Verify no error messages for valid file
    await expect(page.locator('[data-testid="file-size-error"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="file-type-error"]')).not.toBeVisible();

    // Step 5: Fill in all mandatory property exposure fields with valid data
    await page.locator('[data-testid="property-type-field"]').click();
    await page.locator('[data-testid="property-type-option-commercial-building"]').click();
    
    await page.locator('[data-testid="location-field"]').fill('456 Business Ave, Los Angeles, CA 90001');
    
    await page.locator('[data-testid="property-value-field"]').fill('2000000');
    
    await page.locator('[data-testid="property-usage-field"]').click();
    await page.locator('[data-testid="property-usage-option-office-space"]').click();

    // Step 6: Click the Submit button
    await page.locator('[data-testid="submit-exposure-button"]').click();

    // Verify the valid file is saved with the property exposure data
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Property exposure data saved successfully');
    
    // Verify attached document is confirmed in the submission
    await expect(page.locator('[data-testid="confirmation-attachments"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-attachments"]')).toContainText('valid-property-document.pdf');
  });
});