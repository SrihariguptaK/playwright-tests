import { test, expect } from '@playwright/test';

test.describe('Quote Draft Functionality - Story 6', () => {
  const baseURL = process.env.BASE_URL || 'http://localhost:3000';
  
  // Test data
  const partialQuoteData = {
    applicantName: 'John Doe',
    contactEmail: 'john.doe@example.com',
    coverageType: 'Auto Insurance'
  };
  
  const completeQuoteData = {
    applicantName: 'Jane Smith',
    contactEmail: 'jane.smith@example.com',
    contactPhone: '555-0123',
    address: '123 Main St, City, State 12345',
    coverageType: 'Home Insurance',
    coverageAmount: '500000',
    riskDetails: 'Single family home, built 2010'
  };
  
  const userACredentials = {
    username: 'agent_user_a',
    password: 'Password123!'
  };
  
  const userBCredentials = {
    username: 'agent_user_b',
    password: 'Password456!'
  };

  test.beforeEach(async ({ page }) => {
    await page.goto(`${baseURL}/login`);
  });

  test('Validate saving and retrieving quote drafts', async ({ page }) => {
    // Step 1: Enter partial quote data and save as draft
    await page.fill('[data-testid="username-input"]', userACredentials.username);
    await page.fill('[data-testid="password-input"]', userACredentials.password);
    await page.click('[data-testid="login-button"]');
    
    await page.waitForURL('**/dashboard');
    await page.click('[data-testid="new-quote-button"]');
    
    // Fill partial quote data
    await page.fill('[data-testid="applicant-name-input"]', partialQuoteData.applicantName);
    await page.fill('[data-testid="contact-email-input"]', partialQuoteData.contactEmail);
    await page.selectOption('[data-testid="coverage-type-select"]', partialQuoteData.coverageType);
    
    // Save as draft
    await page.click('[data-testid="save-draft-button"]');
    
    // Expected Result: Draft is saved with confirmation
    await expect(page.locator('[data-testid="draft-confirmation-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="draft-confirmation-message"]')).toContainText('Draft saved successfully');
    
    const draftId = await page.locator('[data-testid="draft-id"]').textContent();
    expect(draftId).toBeTruthy();
    
    // Step 2: Log out and log back in
    await page.click('[data-testid="user-menu-button"]');
    await page.click('[data-testid="logout-button"]');
    
    // Expected Result: User can access saved drafts
    await page.waitForURL('**/login');
    await page.fill('[data-testid="username-input"]', userACredentials.username);
    await page.fill('[data-testid="password-input"]', userACredentials.password);
    await page.click('[data-testid="login-button"]');
    
    await page.waitForURL('**/dashboard');
    await page.click('[data-testid="drafts-tab"]');
    
    await expect(page.locator('[data-testid="draft-list"]')).toBeVisible();
    await expect(page.locator(`[data-testid="draft-item-${draftId}"]`)).toBeVisible();
    
    // Step 3: Load draft and continue editing
    await page.click(`[data-testid="draft-item-${draftId}"]`);
    
    // Expected Result: Draft data is loaded correctly
    await expect(page.locator('[data-testid="applicant-name-input"]')).toHaveValue(partialQuoteData.applicantName);
    await expect(page.locator('[data-testid="contact-email-input"]')).toHaveValue(partialQuoteData.contactEmail);
    await expect(page.locator('[data-testid="coverage-type-select"]')).toHaveValue(partialQuoteData.coverageType);
  });

  test('Verify draft access restrictions', async ({ page, context }) => {
    // Step 1: User A saves a draft quote
    await page.fill('[data-testid="username-input"]', userACredentials.username);
    await page.fill('[data-testid="password-input"]', userACredentials.password);
    await page.click('[data-testid="login-button"]');
    
    await page.waitForURL('**/dashboard');
    await page.click('[data-testid="new-quote-button"]');
    
    // Fill partial quote data
    await page.fill('[data-testid="applicant-name-input"]', partialQuoteData.applicantName);
    await page.fill('[data-testid="contact-email-input"]', partialQuoteData.contactEmail);
    await page.selectOption('[data-testid="coverage-type-select"]', partialQuoteData.coverageType);
    
    // Save as draft
    await page.click('[data-testid="save-draft-button"]');
    
    // Expected Result: Draft saved successfully
    await expect(page.locator('[data-testid="draft-confirmation-message"]')).toBeVisible();
    const draftId = await page.locator('[data-testid="draft-id"]').textContent();
    expect(draftId).toBeTruthy();
    
    // Log out User A
    await page.click('[data-testid="user-menu-button"]');
    await page.click('[data-testid="logout-button"]');
    
    // Step 2: User B attempts to access User A's draft
    await page.waitForURL('**/login');
    await page.fill('[data-testid="username-input"]', userBCredentials.username);
    await page.fill('[data-testid="password-input"]', userBCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    await page.waitForURL('**/dashboard');
    
    // Attempt to access draft directly via URL
    await page.goto(`${baseURL}/quotes/draft/${draftId}`);
    
    // Expected Result: Access is denied
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toContainText('Access denied');
    
    // Verify draft is not in User B's draft list
    await page.goto(`${baseURL}/dashboard`);
    await page.click('[data-testid="drafts-tab"]');
    
    const draftItems = page.locator('[data-testid^="draft-item-"]');
    const count = await draftItems.count();
    
    for (let i = 0; i < count; i++) {
      const itemId = await draftItems.nth(i).getAttribute('data-testid');
      expect(itemId).not.toBe(`draft-item-${draftId}`);
    }
  });

  test('Ensure submission of completed draft quote', async ({ page }) => {
    // Create a draft first
    await page.fill('[data-testid="username-input"]', userACredentials.username);
    await page.fill('[data-testid="password-input"]', userACredentials.password);
    await page.click('[data-testid="login-button"]');
    
    await page.waitForURL('**/dashboard');
    await page.click('[data-testid="new-quote-button"]');
    
    // Fill partial quote data
    await page.fill('[data-testid="applicant-name-input"]', completeQuoteData.applicantName);
    await page.fill('[data-testid="contact-email-input"]', completeQuoteData.contactEmail);
    
    // Save as draft
    await page.click('[data-testid="save-draft-button"]');
    await expect(page.locator('[data-testid="draft-confirmation-message"]')).toBeVisible();
    const draftId = await page.locator('[data-testid="draft-id"]').textContent();
    
    // Step 1: Load a saved draft quote
    await page.click('[data-testid="drafts-tab"]');
    await page.click(`[data-testid="draft-item-${draftId}"]`);
    
    // Expected Result: Draft data is displayed
    await expect(page.locator('[data-testid="applicant-name-input"]')).toHaveValue(completeQuoteData.applicantName);
    await expect(page.locator('[data-testid="contact-email-input"]')).toHaveValue(completeQuoteData.contactEmail);
    
    // Step 2: Complete all mandatory fields and submit
    await page.fill('[data-testid="contact-phone-input"]', completeQuoteData.contactPhone);
    await page.fill('[data-testid="address-input"]', completeQuoteData.address);
    await page.selectOption('[data-testid="coverage-type-select"]', completeQuoteData.coverageType);
    await page.fill('[data-testid="coverage-amount-input"]', completeQuoteData.coverageAmount);
    await page.fill('[data-testid="risk-details-input"]', completeQuoteData.riskDetails);
    
    await page.click('[data-testid="submit-quote-button"]');
    
    // Expected Result: Quote is submitted successfully
    await expect(page.locator('[data-testid="quote-confirmation-screen"]')).toBeVisible();
    await expect(page.locator('[data-testid="quote-id"]')).toBeVisible();
    
    const quoteId = await page.locator('[data-testid="quote-id"]').textContent();
    expect(quoteId).toBeTruthy();
    expect(quoteId).not.toBe(draftId);
    
    // Verify submitted data is displayed
    await expect(page.locator('[data-testid="confirmation-applicant-name"]')).toContainText(completeQuoteData.applicantName);
    await expect(page.locator('[data-testid="confirmation-coverage-type"]')).toContainText(completeQuoteData.coverageType);
  });

  test('Validate display of quote initiation confirmation (happy-path)', async ({ page }) => {
    // Navigate to the quote initiation form
    await page.fill('[data-testid="username-input"]', userACredentials.username);
    await page.fill('[data-testid="password-input"]', userACredentials.password);
    await page.click('[data-testid="login-button"]');
    
    await page.waitForURL('**/dashboard');
    await page.click('[data-testid="new-quote-button"]');
    
    // Fill in all mandatory applicant information fields
    await page.fill('[data-testid="applicant-name-input"]', completeQuoteData.applicantName);
    await page.fill('[data-testid="contact-email-input"]', completeQuoteData.contactEmail);
    await page.fill('[data-testid="contact-phone-input"]', completeQuoteData.contactPhone);
    await page.fill('[data-testid="address-input"]', completeQuoteData.address);
    
    // Fill in all mandatory risk data fields
    await page.selectOption('[data-testid="coverage-type-select"]', completeQuoteData.coverageType);
    await page.fill('[data-testid="coverage-amount-input"]', completeQuoteData.coverageAmount);
    await page.fill('[data-testid="risk-details-input"]', completeQuoteData.riskDetails);
    
    // Click the Submit button to submit the completed quote
    await page.click('[data-testid="submit-quote-button"]');
    
    // Verify that a unique quote ID is displayed on the confirmation screen
    await expect(page.locator('[data-testid="quote-confirmation-screen"]')).toBeVisible();
    const quoteId = await page.locator('[data-testid="quote-id"]').textContent();
    expect(quoteId).toBeTruthy();
    expect(quoteId).toMatch(/^[A-Z0-9-]+$/);
    
    // Verify that the confirmation screen shows a summary of submitted applicant data
    await expect(page.locator('[data-testid="confirmation-applicant-summary"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-applicant-name"]')).toContainText(completeQuoteData.applicantName);
    await expect(page.locator('[data-testid="confirmation-contact-email"]')).toContainText(completeQuoteData.contactEmail);
    await expect(page.locator('[data-testid="confirmation-contact-phone"]')).toContainText(completeQuoteData.contactPhone);
    await expect(page.locator('[data-testid="confirmation-address"]')).toContainText(completeQuoteData.address);
    
    // Verify that the confirmation screen shows a summary of submitted risk data
    await expect(page.locator('[data-testid="confirmation-risk-summary"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-coverage-type"]')).toContainText(completeQuoteData.coverageType);
    await expect(page.locator('[data-testid="confirmation-coverage-amount"]')).toContainText(completeQuoteData.coverageAmount);
    await expect(page.locator('[data-testid="confirmation-risk-details"]')).toContainText(completeQuoteData.riskDetails);
    
    // Locate and click the Print option on the confirmation screen
    await expect(page.locator('[data-testid="print-button"]')).toBeVisible();
    
    // Set up dialog handler for print dialog
    page.on('dialog', async dialog => {
      await dialog.dismiss();
    });
    
    await page.click('[data-testid="print-button"]');
    
    // Locate and click the Save option on the confirmation screen
    await expect(page.locator('[data-testid="save-confirmation-button"]')).toBeVisible();
    
    const downloadPromise = page.waitForEvent('download');
    await page.click('[data-testid="save-confirmation-button"]');
    const download = await downloadPromise;
    
    expect(download.suggestedFilename()).toContain('quote');
  });

  test('Ensure confirmation is only visible to submitting user (error-case)', async ({ page, context }) => {
    // Log in to the system as User A
    await page.fill('[data-testid="username-input"]', userACredentials.username);
    await page.fill('[data-testid="password-input"]', userACredentials.password);
    await page.click('[data-testid="login-button"]');
    
    await page.waitForURL('**/dashboard');
    
    // Navigate to the quote initiation form as User A
    await page.click('[data-testid="new-quote-button"]');
    
    // Fill in all mandatory fields with valid applicant and risk data as User A
    await page.fill('[data-testid="applicant-name-input"]', completeQuoteData.applicantName);
    await page.fill('[data-testid="contact-email-input"]', completeQuoteData.contactEmail);
    await page.fill('[data-testid="contact-phone-input"]', completeQuoteData.contactPhone);
    await page.fill('[data-testid="address-input"]', completeQuoteData.address);
    await page.selectOption('[data-testid="coverage-type-select"]', completeQuoteData.coverageType);
    await page.fill('[data-testid="coverage-amount-input"]', completeQuoteData.coverageAmount);
    await page.fill('[data-testid="risk-details-input"]', completeQuoteData.riskDetails);
    
    // Submit the completed quote as User A
    await page.click('[data-testid="submit-quote-button"]');
    
    // Note the unique quote ID and confirmation URL displayed to User A
    await expect(page.locator('[data-testid="quote-confirmation-screen"]')).toBeVisible();
    const quoteId = await page.locator('[data-testid="quote-id"]').textContent();
    const confirmationURL = page.url();
    
    expect(quoteId).toBeTruthy();
    expect(confirmationURL).toContain('confirmation');
    
    // Verify that User A can view all confirmation details
    await expect(page.locator('[data-testid="quote-id"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-applicant-summary"]')).toBeVisible();
    await expect(page.locator('[data-testid="confirmation-risk-summary"]')).toBeVisible();
    
    // Log out User A from the system
    await page.click('[data-testid="user-menu-button"]');
    await page.click('[data-testid="logout-button"]');
    
    // Log in to the system as User B using different credentials
    await page.waitForURL('**/login');
    await page.fill('[data-testid="username-input"]', userBCredentials.username);
    await page.fill('[data-testid="password-input"]', userBCredentials.password);
    await page.click('[data-testid="login-button"]');
    
    await page.waitForURL('**/dashboard');
    
    // Attempt to access User A's confirmation screen by navigating to the confirmation URL
    await page.goto(confirmationURL);
    
    // Verify that User B cannot view any details of User A's quote confirmation
    await expect(page.locator('[data-testid="quote-confirmation-screen"]')).not.toBeVisible();
    await expect(page.locator('[data-testid="access-denied-message"]')).toBeVisible();
    
    // Verify that the system does not display sensitive information in the access denial message
    const denialMessage = await page.locator('[data-testid="access-denied-message"]').textContent();
    expect(denialMessage).not.toContain(completeQuoteData.applicantName);
    expect(denialMessage).not.toContain(completeQuoteData.contactEmail);
    expect(denialMessage).not.toContain(quoteId || '');
  });
});