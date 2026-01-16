import { test, expect } from '@playwright/test';

test.describe('Rating Engine Integration Requirements Analysis', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the requirements management system
    await page.goto('/requirements-management');
  });

  test('Verify completeness of requirements documentation', async ({ page }) => {
    // Navigate to the Business Requirements Document repository
    await page.click('[data-testid="brd-repository"]');
    await expect(page.locator('[data-testid="brd-repository-page"]')).toBeVisible();
    
    // Open the latest version of the rating engine integration BRD
    await page.click('[data-testid="rating-engine-integration-brd"]');
    await page.click('[data-testid="latest-version"]');
    await expect(page.locator('[data-testid="brd-document"]')).toBeVisible();
    
    // Review the functional requirements section
    await page.click('[data-testid="functional-requirements-section"]');
    const functionalRequirements = page.locator('[data-testid="functional-requirement-item"]');
    await expect(functionalRequirements).not.toHaveCount(0);
    await expect(page.locator('text=All functional and non-functional requirements are present')).toBeVisible();
    
    // Review the non-functional requirements section
    await page.click('[data-testid="non-functional-requirements-section"]');
    await expect(page.locator('[data-testid="performance-requirements"]')).toBeVisible();
    await expect(page.locator('[data-testid="security-requirements"]')).toBeVisible();
    await expect(page.locator('[data-testid="scalability-requirements"]')).toBeVisible();
    await expect(page.locator('[data-testid="availability-requirements"]')).toBeVisible();
    
    // Navigate to the dependencies section
    await page.click('[data-testid="dependencies-section"]');
    await expect(page.locator('[data-testid="system-dependencies"]')).toBeVisible();
    await expect(page.locator('[data-testid="data-dependencies"]')).toBeVisible();
    await expect(page.locator('[data-testid="external-service-dependencies"]')).toBeVisible();
    const dependenciesText = await page.locator('[data-testid="dependencies-section"]').textContent();
    expect(dependenciesText).toBeTruthy();
    
    // Review the constraints section
    await page.click('[data-testid="constraints-section"]');
    await expect(page.locator('[data-testid="technical-constraints"]')).toBeVisible();
    await expect(page.locator('[data-testid="business-constraints"]')).toBeVisible();
    await expect(page.locator('[data-testid="regulatory-constraints"]')).toBeVisible();
    await expect(page.locator('[data-testid="resource-constraints"]')).toBeVisible();
    
    // Navigate to stakeholder sign-off section
    await page.click('[data-testid="stakeholder-signoff-section"]');
    const signoffDocuments = page.locator('[data-testid="signoff-document"]');
    await expect(signoffDocuments).not.toHaveCount(0);
    await expect(page.locator('[data-testid="approval-status"]')).toHaveText(/Approved|Signed/);
    
    // Check document version history and change log
    await page.click('[data-testid="version-history-tab"]');
    await expect(page.locator('[data-testid="version-history-list"]')).toBeVisible();
    await page.click('[data-testid="change-log-tab"]');
    await expect(page.locator('[data-testid="change-log-list"]')).toBeVisible();
  });

  test('Validate requirement change management process', async ({ page }) => {
    // Access the requirements change management system
    await page.click('[data-testid="change-management-system"]');
    await expect(page.locator('[data-testid="change-management-page"]')).toBeVisible();
    
    // Navigate to Submit Change Request section
    await page.click('[data-testid="submit-change-request"]');
    await expect(page.locator('[data-testid="change-request-form"]')).toBeVisible();
    
    // Select an existing requirement from the BRD
    await page.click('[data-testid="select-requirement-dropdown"]');
    await page.click('[data-testid="requirement-REQ-INT-001"]');
    
    // Fill in the change request form
    await page.fill('[data-testid="change-description-input"]', 'Update API response time from 2 seconds to 1 second');
    await page.fill('[data-testid="change-justification-input"]', 'Business requirement for improved user experience');
    await page.selectOption('[data-testid="impact-select"]', 'Medium');
    await page.selectOption('[data-testid="priority-select"]', 'High');
    
    // Attach supporting documentation
    const fileInput = page.locator('[data-testid="attach-document-input"]');
    await fileInput.setInputFiles({
      name: 'business-justification.pdf',
      mimeType: 'application/pdf',
      buffer: Buffer.from('Mock business justification document')
    });
    
    // Submit the change request
    await page.click('[data-testid="submit-change-request-button"]');
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible();
    const changeRequestId = await page.locator('[data-testid="change-request-id"]').textContent();
    expect(changeRequestId).toBeTruthy();
    
    // Navigate to change request tracking dashboard
    await page.click('[data-testid="change-tracking-dashboard"]');
    await expect(page.locator('[data-testid="tracking-dashboard"]')).toBeVisible();
    
    // Search for the newly submitted change request
    await page.fill('[data-testid="search-change-request-input"]', changeRequestId!);
    await page.click('[data-testid="search-button"]');
    const searchResult = page.locator(`[data-testid="change-request-${changeRequestId}"]`);
    await expect(searchResult).toBeVisible();
    await expect(searchResult.locator('[data-testid="cr-status"]')).toHaveText('Logged');
    
    // Verify automated notifications were sent
    await page.click(`[data-testid="change-request-${changeRequestId}"]`);
    await page.click('[data-testid="notifications-tab"]');
    await expect(page.locator('text=Technical Lead')).toBeVisible();
    await expect(page.locator('text=Business Owner')).toBeVisible();
    await expect(page.locator('[data-testid="notification-sent-status"]')).toHaveText(/Sent|Delivered/);
    
    // As a reviewer, access the change request and add review comments
    await page.click('[data-testid="review-tab"]');
    await page.fill('[data-testid="review-comments-textarea"]', 'Technical feasibility confirmed. Requires infrastructure upgrade.');
    await page.click('[data-testid="add-comment-button"]');
    await expect(page.locator('text=Technical feasibility confirmed')).toBeVisible();
    
    // Update the change request status to Approved
    await page.selectOption('[data-testid="change-status-select"]', 'Approved');
    await page.fill('[data-testid="approval-justification-textarea"]', 'Infrastructure upgrade planned for Q2. Approved for implementation.');
    await page.click('[data-testid="update-status-button"]');
    await expect(page.locator('[data-testid="status-updated-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="current-status"]')).toHaveText('Approved');
    
    // Submit another change request for rejection scenario
    await page.click('[data-testid="submit-change-request"]');
    await page.click('[data-testid="select-requirement-dropdown"]');
    await page.click('[data-testid="requirement-REQ-INT-002"]');
    await page.fill('[data-testid="change-description-input"]', 'Add additional data field to integration payload');
    await page.fill('[data-testid="change-justification-input"]', 'Nice to have feature for reporting');
    await page.selectOption('[data-testid="impact-select"]', 'Low');
    await page.selectOption('[data-testid="priority-select"]', 'Low');
    await page.click('[data-testid="submit-change-request-button"]');
    const rejectedCrId = await page.locator('[data-testid="change-request-id"]').textContent();
    
    // Update status to Rejected
    await page.click('[data-testid="change-tracking-dashboard"]');
    await page.fill('[data-testid="search-change-request-input"]', rejectedCrId!);
    await page.click('[data-testid="search-button"]');
    await page.click(`[data-testid="change-request-${rejectedCrId}"]`);
    await page.selectOption('[data-testid="change-status-select"]', 'Rejected');
    await page.fill('[data-testid="rejection-reason-textarea"]', 'Does not align with current business priorities');
    await page.click('[data-testid="update-status-button"]');
    await expect(page.locator('[data-testid="current-status"]')).toHaveText('Rejected');
    
    // Generate change request summary report
    await page.click('[data-testid="change-tracking-dashboard"]');
    await page.click('[data-testid="generate-report-button"]');
    await page.selectOption('[data-testid="report-type-select"]', 'Summary Report');
    await page.click('[data-testid="include-all-requests-checkbox"]');
    await page.click('[data-testid="generate-button"]');
    await expect(page.locator('[data-testid="report-generated-message"]')).toBeVisible();
    await expect(page.locator('[data-testid="report-download-link"]')).toBeVisible();
    
    // Verify report contains both change requests
    const reportContent = page.locator('[data-testid="report-preview"]');
    await expect(reportContent).toContainText(changeRequestId!);
    await expect(reportContent).toContainText(rejectedCrId!);
    await expect(reportContent).toContainText('Approved');
    await expect(reportContent).toContainText('Rejected');
  });
});