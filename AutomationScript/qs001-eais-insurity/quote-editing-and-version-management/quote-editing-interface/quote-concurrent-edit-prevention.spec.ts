import { test, expect, Browser, BrowserContext, Page } from '@playwright/test';

test.describe('Quote Concurrent Edit Prevention', () => {
  let browser: Browser;
  let contextUserA: BrowserContext;
  let contextUserB: BrowserContext;
  let pageUserA: Page;
  let pageUserB: Page;
  const testQuoteId = 'QUOTE-12345';
  const baseUrl = process.env.BASE_URL || 'http://localhost:3000';

  test.beforeEach(async ({ browser }) => {
    // Create separate browser contexts for User A and User B to simulate different users
    contextUserA = await browser.newContext();
    contextUserB = await browser.newContext();
    pageUserA = await contextUserA.newPage();
    pageUserB = await contextUserB.newPage();

    // Login User A
    await pageUserA.goto(`${baseUrl}/login`);
    await pageUserA.fill('[data-testid="username-input"]', 'userA@example.com');
    await pageUserA.fill('[data-testid="password-input"]', 'password123');
    await pageUserA.click('[data-testid="login-button"]');
    await pageUserA.waitForURL('**/dashboard');

    // Login User B
    await pageUserB.goto(`${baseUrl}/login`);
    await pageUserB.fill('[data-testid="username-input"]', 'userB@example.com');
    await pageUserB.fill('[data-testid="password-input"]', 'password123');
    await pageUserB.click('[data-testid="login-button"]');
    await pageUserB.waitForURL('**/dashboard');
  });

  test.afterEach(async () => {
    await contextUserA.close();
    await contextUserB.close();
  });

  test('Verify quote locking prevents concurrent edits', async () => {
    // Step 1: User A navigates to the quote list and selects a specific quote to edit
    await pageUserA.goto(`${baseUrl}/quotes`);
    await pageUserA.waitForSelector('[data-testid="quotes-list"]');
    
    // Locate and click on the specific quote
    const quoteRowUserA = pageUserA.locator(`[data-testid="quote-row-${testQuoteId}"]`);
    await expect(quoteRowUserA).toBeVisible();
    await quoteRowUserA.click();
    
    // Step 2: User A clicks the 'Edit' button on the quote
    await pageUserA.waitForURL(`**/quotes/${testQuoteId}`);
    const editButtonUserA = pageUserA.locator('[data-testid="edit-quote-button"]');
    await expect(editButtonUserA).toBeVisible();
    await editButtonUserA.click();
    
    // Expected Result: Quote is locked for editing
    await pageUserA.waitForSelector('[data-testid="quote-edit-form"]');
    const lockIndicator = pageUserA.locator('[data-testid="quote-locked-indicator"]');
    await expect(lockIndicator).toContainText('Editing in progress');
    
    // Step 3: Verify lock status in the system (check for lock icon or status)
    const lockStatus = await pageUserA.locator('[data-testid="lock-status"]').getAttribute('data-locked');
    expect(lockStatus).toBe('true');
    
    // Step 4: User B navigates to the same quote and attempts to click the 'Edit' button
    await pageUserB.goto(`${baseUrl}/quotes`);
    await pageUserB.waitForSelector('[data-testid="quotes-list"]');
    
    const quoteRowUserB = pageUserB.locator(`[data-testid="quote-row-${testQuoteId}"]`);
    await expect(quoteRowUserB).toBeVisible();
    await quoteRowUserB.click();
    
    await pageUserB.waitForURL(`**/quotes/${testQuoteId}`);
    const editButtonUserB = pageUserB.locator('[data-testid="edit-quote-button"]');
    await expect(editButtonUserB).toBeVisible();
    await editButtonUserB.click();
    
    // Expected Result: User B receives notification that quote is locked and cannot edit
    const lockNotification = pageUserB.locator('[data-testid="quote-locked-notification"]');
    await expect(lockNotification).toBeVisible();
    await expect(lockNotification).toContainText('This quote is currently being edited by another user');
    
    // Step 5: User B verifies the quote remains in read-only mode
    const readOnlyIndicator = pageUserB.locator('[data-testid="read-only-mode"]');
    await expect(readOnlyIndicator).toBeVisible();
    
    // Verify edit form is not accessible for User B
    const editFormUserB = pageUserB.locator('[data-testid="quote-edit-form"]');
    await expect(editFormUserB).not.toBeVisible();
    
    // Step 6: User A makes changes to the quote fields
    await pageUserA.fill('[data-testid="quote-pricing-input"]', '15000');
    await pageUserA.fill('[data-testid="quote-terms-input"]', 'Net 30 days');
    
    // Add line item changes
    await pageUserA.click('[data-testid="add-line-item-button"]');
    await pageUserA.fill('[data-testid="line-item-description-0"]', 'Professional Services');
    await pageUserA.fill('[data-testid="line-item-quantity-0"]', '10');
    await pageUserA.fill('[data-testid="line-item-price-0"]', '1500');
    
    // Step 7: User A clicks the 'Save' button to save the changes
    const saveButton = pageUserA.locator('[data-testid="save-quote-button"]');
    await expect(saveButton).toBeEnabled();
    await saveButton.click();
    
    // Wait for save confirmation
    const saveConfirmation = pageUserA.locator('[data-testid="save-confirmation-message"]');
    await expect(saveConfirmation).toBeVisible();
    await expect(saveConfirmation).toContainText('Quote saved successfully');
    
    // Expected Result: Lock is released
    await pageUserA.waitForTimeout(1000); // Wait for lock release
    
    // Step 8: Verify lock status in the system after User A saves
    const lockStatusAfterSave = await pageUserA.locator('[data-testid="lock-status"]').getAttribute('data-locked');
    expect(lockStatusAfterSave).toBe('false');
    
    // Step 9: User B refreshes the quote page or attempts to edit the quote again
    await pageUserB.reload();
    await pageUserB.waitForSelector('[data-testid="edit-quote-button"]');
    
    const editButtonUserBRetry = pageUserB.locator('[data-testid="edit-quote-button"]');
    await expect(editButtonUserBRetry).toBeVisible();
    await expect(editButtonUserBRetry).toBeEnabled();
    await editButtonUserBRetry.click();
    
    // Expected Result: User B can now edit and quote is locked for their session
    await pageUserB.waitForSelector('[data-testid="quote-edit-form"]');
    const editFormUserBNow = pageUserB.locator('[data-testid="quote-edit-form"]');
    await expect(editFormUserBNow).toBeVisible();
    
    // Step 10: User B enters edit mode and verifies the quote is locked for their session
    const lockIndicatorUserB = pageUserB.locator('[data-testid="quote-locked-indicator"]');
    await expect(lockIndicatorUserB).toContainText('Editing in progress');
    
    const lockStatusUserB = await pageUserB.locator('[data-testid="lock-status"]').getAttribute('data-locked');
    expect(lockStatusUserB).toBe('true');
    
    // Verify User B can make edits
    const pricingInputUserB = pageUserB.locator('[data-testid="quote-pricing-input"]');
    await expect(pricingInputUserB).toBeEnabled();
    await pricingInputUserB.fill('16000');
    
    // Verify the updated value from User A is visible
    const termsInputUserB = pageUserB.locator('[data-testid="quote-terms-input"]');
    await expect(termsInputUserB).toHaveValue('Net 30 days');
  });
});