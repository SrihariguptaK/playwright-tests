import { test, expect } from '@playwright/test';

test.describe('Bulk Schedule Assignments', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the bulk schedule assignment page
    await page.goto('/schedules/bulk-assignment');
    await expect(page).toHaveURL(/.*bulk-assignment/);
  });

  test('Perform bulk assignment without conflicts', async ({ page }) => {
    // Step 1: Select multiple employees (at least 5) from the employee multi-select dropdown
    await page.click('[data-testid="employee-multiselect"]');
    await page.click('[data-testid="employee-option-1"]');
    await page.click('[data-testid="employee-option-2"]');
    await page.click('[data-testid="employee-option-3"]');
    await page.click('[data-testid="employee-option-4"]');
    await page.click('[data-testid="employee-option-5"]');
    
    // Verify selection accepted
    const selectedCount = await page.locator('[data-testid="selected-employees-count"]').textContent();
    expect(selectedCount).toContain('5');
    
    // Close the dropdown
    await page.click('[data-testid="employee-multiselect"]');
    
    // Step 2: Select a shift template from the available shift templates dropdown
    await page.click('[data-testid="shift-template-dropdown"]');
    await page.click('[data-testid="shift-template-morning"]');
    
    // Verify shift template selected
    await expect(page.locator('[data-testid="shift-template-dropdown"]')).toContainText('Morning');
    
    // Step 3: Specify a date range using the date range picker (e.g., 7 consecutive days)
    await page.click('[data-testid="date-range-start"]');
    await page.fill('[data-testid="date-range-start"]', '2024-06-01');
    await page.click('[data-testid="date-range-end"]');
    await page.fill('[data-testid="date-range-end"]', '2024-06-07');
    
    // Step 4: Click Preview or Review button to view assignment summary
    await page.click('[data-testid="preview-button"]');
    
    // Wait for summary to load
    await expect(page.locator('[data-testid="assignment-summary"]')).toBeVisible();
    
    // Step 5: Review the summary for accuracy
    await expect(page.locator('[data-testid="summary-employee-count"]')).toContainText('5');
    await expect(page.locator('[data-testid="summary-date-range"]')).toContainText('2024-06-01');
    await expect(page.locator('[data-testid="summary-date-range"]')).toContainText('2024-06-07');
    await expect(page.locator('[data-testid="summary-shift-template"]')).toContainText('Morning');
    
    // Step 6: Click Submit or Confirm button to submit the bulk assignment
    await page.click('[data-testid="confirm-button"]');
    
    // Step 7: Wait for bulk assignment processing to complete
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Assignments saved successfully');
    
    // Step 8: Navigate to the schedule view and select the first employee from the bulk assignment
    await page.goto('/schedules/view');
    await page.click('[data-testid="employee-filter"]');
    await page.click('[data-testid="employee-option-1"]');
    
    // Step 9: Verify the schedule details match the assigned shift template
    await expect(page.locator('[data-testid="schedule-entry-2024-06-01"]')).toContainText('Morning');
    await expect(page.locator('[data-testid="schedule-entry-2024-06-02"]')).toContainText('Morning');
    await expect(page.locator('[data-testid="schedule-entry-2024-06-03"]')).toContainText('Morning');
    
    // Step 10: Repeat verification for at least 2 more employees from the bulk assignment
    await page.click('[data-testid="employee-filter"]');
    await page.click('[data-testid="employee-option-2"]');
    await expect(page.locator('[data-testid="schedule-entry-2024-06-01"]')).toContainText('Morning');
    await expect(page.locator('[data-testid="schedule-entry-2024-06-02"]')).toContainText('Morning');
    
    await page.click('[data-testid="employee-filter"]');
    await page.click('[data-testid="employee-option-3"]');
    await expect(page.locator('[data-testid="schedule-entry-2024-06-01"]')).toContainText('Morning');
    await expect(page.locator('[data-testid="schedule-entry-2024-06-02"]')).toContainText('Morning');
  });

  test('Detect conflicts during bulk assignment', async ({ page }) => {
    // Step 1: Select multiple employees including at least one employee who has a conflicting schedule
    await page.click('[data-testid="employee-multiselect"]');
    await page.click('[data-testid="employee-option-6"]'); // Employee with existing schedule
    await page.click('[data-testid="employee-option-7"]');
    await page.click('[data-testid="employee-option-8"]');
    
    // Verify selection accepted
    const selectedCount = await page.locator('[data-testid="selected-employees-count"]').textContent();
    expect(selectedCount).toContain('3');
    
    // Close the dropdown
    await page.click('[data-testid="employee-multiselect"]');
    
    // Step 2: Select a shift template that will overlap with the existing shift
    await page.click('[data-testid="shift-template-dropdown"]');
    await page.click('[data-testid="shift-template-evening"]');
    
    // Step 3: Specify a date range that includes the date with the conflicting shift
    await page.click('[data-testid="date-range-start"]');
    await page.fill('[data-testid="date-range-start"]', '2024-06-10');
    await page.click('[data-testid="date-range-end"]');
    await page.fill('[data-testid="date-range-end"]', '2024-06-16');
    
    // Step 4: Click Preview or Review button to view assignment summary
    await page.click('[data-testid="preview-button"]');
    
    // Wait for summary to load
    await expect(page.locator('[data-testid="assignment-summary"]')).toBeVisible();
    
    // Step 5: Click Submit or Confirm button to submit the bulk assignment
    await page.click('[data-testid="confirm-button"]');
    
    // Step 6: Review the conflict report displayed by the system
    await expect(page.locator('[data-testid="conflict-report"]')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('[data-testid="conflict-report"]')).toContainText('conflicts');
    await expect(page.locator('[data-testid="conflict-employee-list"]')).toContainText('Employee');
    
    // Verify system reports conflicts for affected employees
    const conflictCount = await page.locator('[data-testid="conflict-count"]').textContent();
    expect(parseInt(conflictCount || '0')).toBeGreaterThan(0);
    
    // Step 7: Adjust the selection by removing the employee with conflicts
    await page.click('[data-testid="back-to-edit-button"]');
    
    // Remove conflicting employee
    await page.click('[data-testid="employee-multiselect"]');
    await page.click('[data-testid="employee-option-6"]'); // Deselect employee with conflict
    await page.click('[data-testid="employee-multiselect"]');
    
    // Verify updated selection
    const updatedCount = await page.locator('[data-testid="selected-employees-count"]').textContent();
    expect(updatedCount).toContain('2');
    
    // Step 8: Click Submit or Confirm button to resubmit the adjusted bulk assignment
    await page.click('[data-testid="preview-button"]');
    await expect(page.locator('[data-testid="assignment-summary"]')).toBeVisible();
    await page.click('[data-testid="confirm-button"]');
    
    // Step 9: Wait for processing to complete
    await expect(page.locator('[data-testid="success-message"]')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('[data-testid="success-message"]')).toContainText('Assignments saved successfully');
    
    // Step 10: Verify schedules for the employees included in the final bulk assignment
    await page.goto('/schedules/view');
    
    // Verify employee 7
    await page.click('[data-testid="employee-filter"]');
    await page.click('[data-testid="employee-option-7"]');
    await expect(page.locator('[data-testid="schedule-entry-2024-06-10"]')).toContainText('Evening');
    await expect(page.locator('[data-testid="schedule-entry-2024-06-11"]')).toContainText('Evening');
    
    // Verify employee 8
    await page.click('[data-testid="employee-filter"]');
    await page.click('[data-testid="employee-option-8"]');
    await expect(page.locator('[data-testid="schedule-entry-2024-06-10"]')).toContainText('Evening');
    await expect(page.locator('[data-testid="schedule-entry-2024-06-11"]')).toContainText('Evening');
  });
});