import { test, expect } from '@playwright/test';

test.describe('Demographic Data Draft Management', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  const draftData = {
    firstName: 'John',
    email: 'john.doe@example.com',
    lastName: 'Doe',
    phoneNumber: '555-123-4567',
    dateOfBirth: '1990-01-15'
  };

  test.beforeEach(async ({ page }) => {
    // Login as Applicant Data Entry Specialist
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', 'data.entry.specialist@example.com');
    await page.fill('[data-testid="password-input"]', 'SecurePassword123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);
  });

  test('Validate saving of demographic data draft', async ({ page }) => {
    // Navigate to the demographic data entry form
    await page.goto(`${baseURL}/applicants/demographics/new`);
    await expect(page.locator('[data-testid="demographics-form"]')).toBeVisible();

    // Enter partial demographic data including first name and email address only
    await page.fill('[data-testid="first-name-input"]', draftData.firstName);
    await page.fill('[data-testid="email-input"]', draftData.email);

    // Verify data entered without validation errors
    await expect(page.locator('[data-testid="first-name-input"]')).toHaveValue(draftData.firstName);
    await expect(page.locator('[data-testid="email-input"]')).toHaveValue(draftData.email);
    await expect(page.locator('.validation-error')).toHaveCount(0);

    // Leave other required fields empty (verify they are empty)
    await expect(page.locator('[data-testid="last-name-input"]')).toHaveValue('');
    await expect(page.locator('[data-testid="phone-number-input"]')).toHaveValue('');
    await expect(page.locator('[data-testid="date-of-birth-input"]')).toHaveValue('');

    // Click the 'Save Draft' button
    await page.click('[data-testid="save-draft-button"]');

    // Wait for the save operation to complete
    await page.waitForResponse(response => 
      response.url().includes('/api/applicants/demographics/drafts') && 
      response.status() === 200
    );

    // Draft saved and confirmation displayed
    await expect(page.locator('[data-testid="draft-save-confirmation"]')).toBeVisible();
    await expect(page.locator('[data-testid="draft-save-confirmation"]')).toContainText('Draft saved successfully');

    // Verify the confirmation notification details
    const confirmationMessage = await page.locator('[data-testid="draft-save-confirmation"]').textContent();
    expect(confirmationMessage).toBeTruthy();
    expect(confirmationMessage).toMatch(/saved|success/i);
  });

  test('Verify retrieval and editing of saved draft', async ({ page }) => {
    // First, create a draft to retrieve
    await page.goto(`${baseURL}/applicants/demographics/new`);
    await page.fill('[data-testid="first-name-input"]', draftData.firstName);
    await page.fill('[data-testid="email-input"]', draftData.email);
    await page.click('[data-testid="save-draft-button"]');
    await expect(page.locator('[data-testid="draft-save-confirmation"]')).toBeVisible();

    // Navigate to the drafts list
    await page.goto(`${baseURL}/applicants/demographics/drafts`);
    await expect(page.locator('[data-testid="drafts-list"]')).toBeVisible();

    // Select and click on the saved demographic draft to access it
    const draftItem = page.locator('[data-testid="draft-item"]').first();
    await expect(draftItem).toBeVisible();
    await draftItem.click();

    // Draft data loaded into form
    await expect(page.locator('[data-testid="demographics-form"]')).toBeVisible();

    // Verify that all previously entered data is accurately displayed in the form fields
    await expect(page.locator('[data-testid="first-name-input"]')).toHaveValue(draftData.firstName);
    await expect(page.locator('[data-testid="email-input"]')).toHaveValue(draftData.email);

    // Add additional demographic information to the draft
    await page.fill('[data-testid="last-name-input"]', draftData.lastName);
    await page.fill('[data-testid="phone-number-input"]', draftData.phoneNumber);

    // Modify existing draft data (update the email address)
    const updatedEmail = 'john.updated@example.com';
    await page.fill('[data-testid="email-input"]', updatedEmail);

    // Click the 'Save Draft' button again to save the updated draft
    await page.click('[data-testid="save-draft-button"]');

    // Updated draft saved successfully
    await expect(page.locator('[data-testid="draft-save-confirmation"]')).toBeVisible();
    await expect(page.locator('[data-testid="draft-save-confirmation"]')).toContainText('Draft saved successfully');

    // Navigate away from the form
    await page.goto(`${baseURL}/dashboard`);
    await expect(page).toHaveURL(/.*dashboard/);

    // Retrieve the draft again
    await page.goto(`${baseURL}/applicants/demographics/drafts`);
    await page.locator('[data-testid="draft-item"]').first().click();

    // Verify updated data persisted
    await expect(page.locator('[data-testid="first-name-input"]')).toHaveValue(draftData.firstName);
    await expect(page.locator('[data-testid="email-input"]')).toHaveValue(updatedEmail);
    await expect(page.locator('[data-testid="last-name-input"]')).toHaveValue(draftData.lastName);
    await expect(page.locator('[data-testid="phone-number-input"]')).toHaveValue(draftData.phoneNumber);
  });

  test('Test draft access restriction to authenticated users', async ({ page, context }) => {
    // First, create a draft while authenticated
    await page.goto(`${baseURL}/applicants/demographics/new`);
    await page.fill('[data-testid="first-name-input"]', draftData.firstName);
    await page.fill('[data-testid="email-input"]', draftData.email);
    await page.click('[data-testid="save-draft-button"]');
    await expect(page.locator('[data-testid="draft-save-confirmation"]')).toBeVisible();

    // Get the draft URL for later use
    const draftURL = page.url();

    // Ensure user is logged out
    await page.click('[data-testid="user-menu"]');
    await page.click('[data-testid="logout-button"]');
    await expect(page).toHaveURL(/.*login/);

    // Attempt to access the drafts list without authentication
    await page.goto(`${baseURL}/applicants/demographics/drafts`);

    // Access denied with appropriate error - verify redirect or error message
    const currentURL = page.url();
    const isRedirectedToLogin = currentURL.includes('/login');
    const hasAccessDeniedMessage = await page.locator('[data-testid="access-denied-message"]').isVisible().catch(() => false);

    expect(isRedirectedToLogin || hasAccessDeniedMessage).toBeTruthy();

    // Attempt to access a specific draft URL directly without authentication
    await page.goto(draftURL);

    // Verify the error response or redirect behavior
    const redirectedURL = page.url();
    expect(redirectedURL).toMatch(/login|unauthorized|access-denied/);

    // Attempt to access draft via API endpoint without authentication token
    const apiResponse = await page.request.post(`${baseURL}/api/applicants/demographics/drafts`, {
      data: {
        firstName: 'Test',
        email: 'test@example.com'
      }
    });

    // Verify unauthorized response
    expect(apiResponse.status()).toBe(401);

    // Log in with valid Applicant Data Entry Specialist credentials
    await page.goto(`${baseURL}/login`);
    await page.fill('[data-testid="username-input"]', 'data.entry.specialist@example.com');
    await page.fill('[data-testid="password-input"]', 'SecurePassword123!');
    await page.click('[data-testid="login-button"]');
    await expect(page).toHaveURL(/.*dashboard/);

    // Attempt to access the drafts list again after authentication
    await page.goto(`${baseURL}/applicants/demographics/drafts`);
    await expect(page.locator('[data-testid="drafts-list"]')).toBeVisible();

    // Verify successful access after authentication
    const draftsVisible = await page.locator('[data-testid="draft-item"]').count();
    expect(draftsVisible).toBeGreaterThanOrEqual(0);

    // Attempt to access a draft belonging to a different user by manipulating the draft ID
    const unauthorizedDraftId = '99999999-invalid-draft-id';
    const unauthorizedResponse = await page.goto(`${baseURL}/applicants/demographics/drafts/${unauthorizedDraftId}`);

    // Verify access is denied or error is shown for unauthorized draft access
    const statusCode = unauthorizedResponse?.status();
    const hasErrorMessage = await page.locator('[data-testid="error-message"]').isVisible().catch(() => false);
    const isNotFoundPage = page.url().includes('404') || await page.locator('text=/not found|access denied/i').isVisible().catch(() => false);

    expect(statusCode === 403 || statusCode === 404 || hasErrorMessage || isNotFoundPage).toBeTruthy();
  });
});