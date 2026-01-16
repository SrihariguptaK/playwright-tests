import { test, expect } from '@playwright/test';

test.describe('Story-13: Product-Specific Rating Algorithms', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the rating algorithm management system
    await page.goto('/rating-algorithms');
    // Login as Product Manager
    await page.fill('[data-testid="username-input"]', 'product.manager@insurance.com');
    await page.fill('[data-testid="password-input"]', 'SecurePass123');
    await page.click('[data-testid="login-button"]');
    await expect(page.locator('[data-testid="dashboard-header"]')).toBeVisible();
  });

  test('TC#1: Verify completeness of rating algorithm documentation - Review documentation repository for all products', async ({ page }) => {
    // Action: Review documentation repository for all products
    await page.click('[data-testid="documentation-repository-link"]');
    await page.waitForSelector('[data-testid="product-list"]');
    
    // Get list of all insurance products
    const products = ['Auto Insurance', 'Home Insurance', 'Life Insurance', 'Health Insurance', 'Commercial Insurance'];
    
    // Expected Result: All products have corresponding algorithm documents
    for (const product of products) {
      const productRow = page.locator(`[data-testid="product-row-${product.toLowerCase().replace(/\s+/g, '-')}"]`);
      await expect(productRow).toBeVisible({ timeout: 5000 });
      
      const algorithmDoc = productRow.locator('[data-testid="algorithm-document-link"]');
      await expect(algorithmDoc).toBeVisible();
      await expect(algorithmDoc).toHaveAttribute('href', /.+/);
    }
    
    // Verify count of documented products
    const documentedProducts = await page.locator('[data-testid^="product-row-"]').count();
    expect(documentedProducts).toBeGreaterThanOrEqual(products.length);
  });

  test('TC#1: Verify completeness of rating algorithm documentation - Check documents for defined factors and formulas', async ({ page }) => {
    // Action: Check documents for defined factors and formulas
    await page.click('[data-testid="documentation-repository-link"]');
    await page.waitForSelector('[data-testid="product-list"]');
    
    // Select first product to review
    await page.click('[data-testid="product-row-auto-insurance"]');
    await page.click('[data-testid="algorithm-document-link"]');
    await page.waitForSelector('[data-testid="algorithm-document-viewer"]');
    
    // Expected Result: Each document contains detailed rating criteria
    await expect(page.locator('[data-testid="rating-factors-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="rating-formulas-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="input-requirements-section"]')).toBeVisible();
    await expect(page.locator('[data-testid="validation-rules-section"]')).toBeVisible();
    
    // Verify rating factors are defined
    const ratingFactors = await page.locator('[data-testid="rating-factor-item"]').count();
    expect(ratingFactors).toBeGreaterThan(0);
    
    // Verify formulas are documented
    const formulas = await page.locator('[data-testid="formula-item"]').count();
    expect(formulas).toBeGreaterThan(0);
    
    // Check for completeness indicator
    const completenessStatus = page.locator('[data-testid="document-completeness-status"]');
    await expect(completenessStatus).toHaveText(/Complete|100%/);
  });

  test('TC#1: Verify completeness of rating algorithm documentation - Confirm version control is active', async ({ page }) => {
    // Action: Confirm version control is active
    await page.click('[data-testid="documentation-repository-link"]');
    await page.waitForSelector('[data-testid="product-list"]');
    
    // Open a product algorithm document
    await page.click('[data-testid="product-row-auto-insurance"]');
    await page.click('[data-testid="algorithm-document-link"]');
    await page.waitForSelector('[data-testid="algorithm-document-viewer"]');
    
    // Expected Result: Document history and versions are tracked
    await page.click('[data-testid="version-history-tab"]');
    await expect(page.locator('[data-testid="version-history-panel"]')).toBeVisible();
    
    // Verify version information is present
    const currentVersion = page.locator('[data-testid="current-version-number"]');
    await expect(currentVersion).toBeVisible();
    await expect(currentVersion).toHaveText(/v\d+\.\d+/);
    
    // Check version history entries
    const versionEntries = await page.locator('[data-testid="version-entry"]').count();
    expect(versionEntries).toBeGreaterThan(0);
    
    // Verify each version entry has required metadata
    const firstVersionEntry = page.locator('[data-testid="version-entry"]').first();
    await expect(firstVersionEntry.locator('[data-testid="version-number"]')).toBeVisible();
    await expect(firstVersionEntry.locator('[data-testid="version-author"]')).toBeVisible();
    await expect(firstVersionEntry.locator('[data-testid="version-date"]')).toBeVisible();
    await expect(firstVersionEntry.locator('[data-testid="version-changes"]')).toBeVisible();
    
    // Verify version control system indicator
    const versionControlStatus = page.locator('[data-testid="version-control-status"]');
    await expect(versionControlStatus).toHaveText(/Active|Enabled/);
  });

  test('TC#2: Confirm underwriting team approval of algorithms - Present algorithm documents to underwriting team', async ({ page }) => {
    // Action: Present algorithm documents to underwriting team
    await page.click('[data-testid="documentation-repository-link"]');
    await page.waitForSelector('[data-testid="product-list"]');
    
    // Select algorithm document for review
    await page.click('[data-testid="product-row-home-insurance"]');
    await page.click('[data-testid="algorithm-document-link"]');
    await page.waitForSelector('[data-testid="algorithm-document-viewer"]');
    
    // Submit for underwriting review
    await page.click('[data-testid="submit-for-review-button"]');
    await page.waitForSelector('[data-testid="review-submission-modal"]');
    
    // Select underwriting team as reviewers
    await page.click('[data-testid="reviewer-group-dropdown"]');
    await page.click('[data-testid="reviewer-option-underwriting-team"]');
    
    // Add review notes
    await page.fill('[data-testid="review-notes-textarea"]', 'Please review the updated rating algorithm for Home Insurance. Key changes include revised risk factors and updated premium calculation formulas.');
    
    // Submit review request
    await page.click('[data-testid="confirm-review-submission-button"]');
    
    // Expected Result: Team reviews and provides feedback
    await expect(page.locator('[data-testid="review-submitted-confirmation"]')).toBeVisible();
    await expect(page.locator('[data-testid="review-status"]')).toHaveText(/Pending Review|Under Review/);
    
    // Verify notification sent to underwriting team
    await page.click('[data-testid="notifications-icon"]');
    const notification = page.locator('[data-testid="notification-item"]').first();
    await expect(notification).toContainText('Review request sent to Underwriting Team');
    
    // Check review tracking
    await page.click('[data-testid="review-tracking-link"]');
    await expect(page.locator('[data-testid="review-request-entry"]')).toBeVisible();
    await expect(page.locator('[data-testid="reviewers-list"]')).toContainText('Underwriting Team');
  });

  test('TC#2: Confirm underwriting team approval of algorithms - Incorporate feedback and finalize documents', async ({ page }) => {
    // Setup: Navigate to document with feedback
    await page.click('[data-testid="documentation-repository-link"]');
    await page.waitForSelector('[data-testid="product-list"]');
    
    // Filter for documents with feedback
    await page.click('[data-testid="filter-dropdown"]');
    await page.click('[data-testid="filter-option-with-feedback"]');
    
    // Open document with underwriting feedback
    await page.click('[data-testid="product-row-life-insurance"]');
    await page.click('[data-testid="algorithm-document-link"]');
    await page.waitForSelector('[data-testid="algorithm-document-viewer"]');
    
    // Action: Incorporate feedback and finalize documents
    await page.click('[data-testid="view-feedback-button"]');
    await expect(page.locator('[data-testid="feedback-panel"]')).toBeVisible();
    
    // Review feedback items
    const feedbackItems = await page.locator('[data-testid="feedback-item"]').count();
    expect(feedbackItems).toBeGreaterThan(0);
    
    // Address each feedback item
    const firstFeedback = page.locator('[data-testid="feedback-item"]').first();
    await firstFeedback.click();
    
    // Make necessary changes based on feedback
    await page.click('[data-testid="edit-document-button"]');
    await page.fill('[data-testid="rating-factor-adjustment-input"]', '1.25');
    await page.click('[data-testid="save-changes-button"]');
    
    // Mark feedback as addressed
    await page.click('[data-testid="mark-feedback-addressed-button"]');
    await page.fill('[data-testid="resolution-notes-textarea"]', 'Updated rating factor based on underwriting team recommendation');
    await page.click('[data-testid="confirm-resolution-button"]');
    
    // Submit for final approval
    await page.click('[data-testid="submit-for-approval-button"]');
    await page.waitForSelector('[data-testid="approval-submission-modal"]');
    await page.click('[data-testid="confirm-approval-submission-button"]');
    
    // Expected Result: Documents approved and signed off
    await expect(page.locator('[data-testid="approval-submitted-confirmation"]')).toBeVisible();
    
    // Simulate underwriting approval (in real scenario, this would be done by underwriting user)
    // For automation purposes, verify approval workflow is triggered
    await page.click('[data-testid="approval-status-link"]');
    await expect(page.locator('[data-testid="approval-workflow-status"]')).toHaveText(/Pending Final Approval|Awaiting Sign-off/);
    
    // Verify approval metadata
    await expect(page.locator('[data-testid="approval-submitted-by"]')).toContainText('product.manager@insurance.com');
    await expect(page.locator('[data-testid="approval-submitted-date"]')).toBeVisible();
    
    // Check document status updated
    await page.goto('/rating-algorithms');
    await page.click('[data-testid="documentation-repository-link"]');
    const documentStatus = page.locator('[data-testid="product-row-life-insurance"] [data-testid="document-status"]');
    await expect(documentStatus).toHaveText(/Pending Approval|Ready for Approval/);
  });
});