import { test, expect } from '@playwright/test';

test.describe('Story-21: Report Schedule Issues', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to schedule page and ensure employee is authenticated
    await page.goto('/schedule');
    // Wait for schedule page to load
    await expect(page).toHaveURL(/.*schedule/);
  });

  test('Validate successful issue report submission (happy-path)', async ({ page }) => {
    // Step 1: Locate and click the 'Report Issue' button on the schedule page
    const reportIssueButton = page.getByRole('button', { name: /report issue/i });
    await expect(reportIssueButton).toBeVisible();
    await reportIssueButton.click();

    // Step 2: Verify all form fields are present including required field indicators
    await expect(page.getByRole('dialog')).toBeVisible();
    const issueDescriptionField = page.getByLabel(/issue description/i);
    await expect(issueDescriptionField).toBeVisible();
    
    // Verify required field indicators are present
    const requiredIndicator = page.locator('label:has-text("*"), [required]');
    await expect(requiredIndicator.first()).toBeVisible();

    // Step 3: Fill in all required fields with valid test data
    await issueDescriptionField.fill('Schedule not displaying correct shift times');
    
    // Check if there are other required fields and fill them
    const issueTypeField = page.getByLabel(/issue type/i);
    if (await issueTypeField.isVisible()) {
      await issueTypeField.selectOption('Display Issue');
    }

    // Step 4: Optionally attach a screenshot file
    const fileInput = page.locator('input[type="file"]');
    if (await fileInput.isVisible()) {
      await fileInput.setInputFiles({
        name: 'screenshot.png',
        mimeType: 'image/png',
        buffer: Buffer.from('fake-image-data')
      });
    }

    // Step 5: Click the 'Submit' button on the issue report form
    const submitButton = page.getByRole('button', { name: /submit/i });
    await submitButton.click();

    // Step 6: Verify the confirmation message includes relevant details
    const confirmationMessage = page.getByText(/report submitted|ticket|confirmation/i);
    await expect(confirmationMessage).toBeVisible({ timeout: 10000 });
    
    // Verify ticket ID or reference number is displayed
    const ticketReference = page.locator('[data-testid="ticket-id"], [data-testid="reference-number"]');
    if (await ticketReference.isVisible()) {
      await expect(ticketReference).toContainText(/[A-Z0-9-]+/);
    }

    // Step 7: Close the confirmation message or form
    const closeButton = page.getByRole('button', { name: /close|ok|dismiss/i });
    if (await closeButton.isVisible()) {
      await closeButton.click();
    }

    // Verify form is closed
    await expect(page.getByRole('dialog')).not.toBeVisible();
  });

  test('Verify form validation for missing required fields (error-case)', async ({ page }) => {
    // Step 1: Click the 'Report Issue' button on the schedule page
    const reportIssueButton = page.getByRole('button', { name: /report issue/i });
    await reportIssueButton.click();
    await expect(page.getByRole('dialog')).toBeVisible();

    // Step 2: Leave all required fields empty
    // Do not enter any data in fields marked as required
    const issueDescriptionField = page.getByLabel(/issue description/i);
    await expect(issueDescriptionField).toBeVisible();
    await expect(issueDescriptionField).toBeEmpty();

    // Step 3: Click the 'Submit' button without filling any required fields
    const submitButton = page.getByRole('button', { name: /submit/i });
    await submitButton.click();

    // Step 4: Verify that validation error messages are clearly visible
    const validationError = page.locator('[data-testid="validation-error"], .error-message, [role="alert"]');
    await expect(validationError.first()).toBeVisible();
    
    // Verify error messages indicate which fields need to be completed
    const requiredFieldError = page.getByText(/required|must be filled|cannot be empty/i);
    await expect(requiredFieldError.first()).toBeVisible();

    // Step 5: Verify that the form remains open and no data is submitted
    await expect(page.getByRole('dialog')).toBeVisible();
    const confirmationMessage = page.getByText(/report submitted|confirmation/i);
    await expect(confirmationMessage).not.toBeVisible();

    // Step 6: Fill in only one required field and attempt to submit again
    await issueDescriptionField.fill('Partial data entry test');
    await submitButton.click();
    
    // Verify validation still occurs if other required fields exist
    const issueTypeField = page.getByLabel(/issue type/i);
    if (await issueTypeField.isVisible()) {
      const typeValidationError = page.locator('[data-testid="validation-error"], .error-message, [role="alert"]');
      await expect(typeValidationError.first()).toBeVisible();
    }

    // Step 7: Fill in all remaining required fields with valid data and submit the form
    if (await issueTypeField.isVisible()) {
      await issueTypeField.selectOption('Display Issue');
    }
    
    // Fill any other required fields
    const allRequiredFields = page.locator('[required]:not([type="hidden"])');
    const count = await allRequiredFields.count();
    for (let i = 0; i < count; i++) {
      const field = allRequiredFields.nth(i);
      const tagName = await field.evaluate(el => el.tagName.toLowerCase());
      const type = await field.getAttribute('type');
      
      if (tagName === 'textarea' || type === 'text') {
        if (await field.inputValue() === '') {
          await field.fill('Valid test data');
        }
      } else if (tagName === 'select') {
        await field.selectOption({ index: 1 });
      }
    }
    
    await submitButton.click();
    
    // Verify successful submission after all fields are filled
    const successConfirmation = page.getByText(/report submitted|confirmation|success/i);
    await expect(successConfirmation).toBeVisible({ timeout: 10000 });
  });
});