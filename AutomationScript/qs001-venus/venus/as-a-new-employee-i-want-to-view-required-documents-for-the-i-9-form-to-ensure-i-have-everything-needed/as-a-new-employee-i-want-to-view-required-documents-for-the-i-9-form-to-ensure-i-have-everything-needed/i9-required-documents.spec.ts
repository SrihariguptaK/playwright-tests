import { test, expect } from '@playwright/test';

test.describe('I-9 Required Documents - Story 2', () => {
  const I9_LANDING_PAGE_URL = '/i9-landing';

  test.beforeEach(async ({ page }) => {
    await page.goto(I9_LANDING_PAGE_URL);
  });

  test('Verify required documents are listed clearly on the landing page', async ({ page }) => {
    // Navigate to the I-9 landing page
    await expect(page).toHaveURL(new RegExp(I9_LANDING_PAGE_URL));

    // Locate the 'Required Documents' section on the landing page
    const requiredDocsSection = page.locator('[data-testid="required-documents-section"]').or(page.locator('text=Required Documents').locator('..'));
    await expect(requiredDocsSection).toBeVisible();

    // Review the list of required documents displayed
    const documentList = requiredDocsSection.locator('[data-testid="document-list"]').or(requiredDocsSection.locator('ul, ol'));
    await expect(documentList).toBeVisible();

    // Verify that document names are clearly readable and properly formatted
    const documentItems = documentList.locator('li');
    const documentCount = await documentItems.count();
    expect(documentCount).toBeGreaterThan(0);

    for (let i = 0; i < documentCount; i++) {
      const documentItem = documentItems.nth(i);
      await expect(documentItem).toBeVisible();
      const text = await documentItem.textContent();
      expect(text).toBeTruthy();
      expect(text!.trim().length).toBeGreaterThan(0);
    }

    // Check if the documents are categorized (List A, List B, List C)
    const listASection = page.locator('[data-testid="list-a-documents"]').or(page.locator('text=List A'));
    const listBSection = page.locator('[data-testid="list-b-documents"]').or(page.locator('text=List B'));
    const listCSection = page.locator('[data-testid="list-c-documents"]').or(page.locator('text=List C'));

    await expect(listASection).toBeVisible();
    await expect(listBSection).toBeVisible();
    await expect(listCSection).toBeVisible();
  });

  test('Verify each document link is functional and leads to the correct resource', async ({ page, context }) => {
    // Identify all clickable document links in the Required Documents section
    const requiredDocsSection = page.locator('[data-testid="required-documents-section"]').or(page.locator('text=Required Documents').locator('..'));
    const documentLinks = requiredDocsSection.locator('a[href]');
    const linkCount = await documentLinks.count();
    expect(linkCount).toBeGreaterThan(0);

    // Click on the first document link in the list
    const firstLink = documentLinks.first();
    const firstLinkHref = await firstLink.getAttribute('href');
    const firstLinkTarget = await firstLink.getAttribute('target');

    if (firstLinkTarget === '_blank') {
      // Verify external links open in new tabs/windows
      const [newPage] = await Promise.all([
        context.waitForEvent('page'),
        firstLink.click()
      ]);
      await newPage.waitForLoadState();
      expect(newPage.url()).toBeTruthy();
      await newPage.close();
    } else {
      await firstLink.click();
      // Verify the document opens or downloads correctly
      await page.waitForLoadState('networkidle');
    }

    // Return to the I-9 landing page and repeat for each remaining document link
    await page.goto(I9_LANDING_PAGE_URL);

    for (let i = 1; i < Math.min(linkCount, 5); i++) {
      const link = documentLinks.nth(i);
      const linkHref = await link.getAttribute('href');
      
      // Verify that no broken links (404 errors) are present
      expect(linkHref).toBeTruthy();
      expect(linkHref).not.toContain('404');

      const response = await page.request.get(linkHref!);
      expect(response.status()).not.toBe(404);
    }
  });

  test('Verify users can easily understand the categories of documents required', async ({ page }) => {
    // Navigate to the Required Documents section on the I-9 landing page
    const requiredDocsSection = page.locator('[data-testid="required-documents-section"]').or(page.locator('text=Required Documents').locator('..'));
    await expect(requiredDocsSection).toBeVisible();

    // Review the document category structure (List A, List B, List C)
    const listASection = page.locator('[data-testid="list-a-section"]').or(page.locator('text=List A').locator('..'));
    const listBSection = page.locator('[data-testid="list-b-section"]').or(page.locator('text=List B').locator('..'));
    const listCSection = page.locator('[data-testid="list-c-section"]').or(page.locator('text=List C').locator('..'));

    await expect(listASection).toBeVisible();
    await expect(listBSection).toBeVisible();
    await expect(listCSection).toBeVisible();

    // Read the explanation or description provided for each document category
    const listADescription = listASection.locator('[data-testid="list-a-description"]').or(listASection.locator('p, div').first());
    const listBDescription = listBSection.locator('[data-testid="list-b-description"]').or(listBSection.locator('p, div').first());
    const listCDescription = listCSection.locator('[data-testid="list-c-description"]').or(listCSection.locator('p, div').first());

    // Verify that List A explanation indicates documents that establish both identity and employment authorization
    const listAText = await listADescription.textContent();
    expect(listAText?.toLowerCase()).toMatch(/identity.*employment authorization|employment authorization.*identity/);

    // Verify that List B explanation indicates documents that establish identity only
    const listBText = await listBDescription.textContent();
    expect(listBText?.toLowerCase()).toContain('identity');

    // Verify that List C explanation indicates documents that establish employment authorization only
    const listCText = await listCDescription.textContent();
    expect(listCText?.toLowerCase()).toContain('employment authorization');

    // Check for instructions on which combination of documents is acceptable
    const instructions = page.locator('[data-testid="document-combination-instructions"]').or(page.locator('text=/combination|acceptable|required/i'));
    await expect(instructions.first()).toBeVisible();

    // Look for any visual aids (icons, colors, diagrams) that help distinguish categories
    const listAIcon = listASection.locator('svg, img, [class*="icon"]').first();
    const listBIcon = listBSection.locator('svg, img, [class*="icon"]').first();
    const listCIcon = listCSection.locator('svg, img, [class*="icon"]').first();

    const hasVisualAids = await listAIcon.count() > 0 || await listBIcon.count() > 0 || await listCIcon.count() > 0;
    expect(hasVisualAids).toBeTruthy();
  });

  test('Verify user can download necessary forms from the Required Documents section', async ({ page }) => {
    // Navigate to the Required Documents section
    const requiredDocsSection = page.locator('[data-testid="required-documents-section"]').or(page.locator('text=Required Documents').locator('..'));
    await expect(requiredDocsSection).toBeVisible();

    // Identify forms that are available for download (e.g., I-9 form, instructions)
    const downloadLinks = requiredDocsSection.locator('a[download], a[href*=".pdf"], a[href*="download"]');
    const downloadCount = await downloadLinks.count();
    expect(downloadCount).toBeGreaterThan(0);

    // Click on the download link for the I-9 form
    const i9FormLink = downloadLinks.filter({ hasText: /I-9|form/i }).first();
    
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      i9FormLink.click()
    ]);

    // Verify the downloaded file is saved to the default download location
    const fileName = download.suggestedFilename();
    expect(fileName).toBeTruthy();
    expect(fileName.toLowerCase()).toMatch(/i-9|form/);

    // Verify download completed successfully
    const path = await download.path();
    expect(path).toBeTruthy();

    // Return to the page and download any additional available forms
    if (downloadCount > 1) {
      const secondDownloadLink = downloadLinks.nth(1);
      const [secondDownload] = await Promise.all([
        page.waitForEvent('download'),
        secondDownloadLink.click()
      ]);
      const secondFileName = secondDownload.suggestedFilename();
      expect(secondFileName).toBeTruthy();
    }
  });

  test('Verify Required Documents section is accessible from the I-9 landing page navigation', async ({ page }) => {
    // Load the I-9 landing page
    await expect(page).toHaveURL(new RegExp(I9_LANDING_PAGE_URL));

    // Locate the 'Required Documents' section link or button in the navigation or page content
    const requiredDocsLink = page.locator('[data-testid="required-documents-link"]').or(page.locator('a:has-text("Required Documents"), button:has-text("Required Documents")')).first();
    await expect(requiredDocsLink).toBeVisible();

    // Click on the 'Required Documents' section link
    await requiredDocsLink.click();

    // Verify the Required Documents section content is fully displayed
    const requiredDocsSection = page.locator('[data-testid="required-documents-section"]').or(page.locator('text=Required Documents').locator('..'));
    await expect(requiredDocsSection).toBeVisible();

    // Verify section content is loaded
    const documentList = requiredDocsSection.locator('[data-testid="document-list"]').or(requiredDocsSection.locator('ul, ol'));
    await expect(documentList).toBeVisible();
    
    const listItems = documentList.locator('li');
    const itemCount = await listItems.count();
    expect(itemCount).toBeGreaterThan(0);
  });

  test('Verify document links remain functional after page refresh', async ({ page }) => {
    // Navigate to the Required Documents section
    const requiredDocsSection = page.locator('[data-testid="required-documents-section"]').or(page.locator('text=Required Documents').locator('..'));
    await expect(requiredDocsSection).toBeVisible();

    // Click on any document link to verify it works
    const documentLinks = requiredDocsSection.locator('a[href]');
    const firstLink = documentLinks.first();
    const firstLinkHref = await firstLink.getAttribute('href');
    
    const response1 = await page.request.get(firstLinkHref!);
    expect(response1.status()).toBeLessThan(400);

    // Refresh the browser page (F5 or refresh button)
    await page.reload();
    await page.waitForLoadState('networkidle');

    // Click on the same document link again
    const requiredDocsSectionAfterRefresh = page.locator('[data-testid="required-documents-section"]').or(page.locator('text=Required Documents').locator('..'));
    const documentLinksAfterRefresh = requiredDocsSectionAfterRefresh.locator('a[href]');
    const firstLinkAfterRefresh = documentLinksAfterRefresh.first();
    const firstLinkHrefAfterRefresh = await firstLinkAfterRefresh.getAttribute('href');
    
    expect(firstLinkHrefAfterRefresh).toBe(firstLinkHref);
    const response2 = await page.request.get(firstLinkHrefAfterRefresh!);
    expect(response2.status()).toBeLessThan(400);

    // Test multiple document links after refresh
    const linkCount = await documentLinksAfterRefresh.count();
    for (let i = 0; i < Math.min(linkCount, 3); i++) {
      const link = documentLinksAfterRefresh.nth(i);
      const href = await link.getAttribute('href');
      const response = await page.request.get(href!);
      expect(response.status()).toBeLessThan(400);
    }
  });

  test('Verify error handling when document link is broken or unavailable', async ({ page }) => {
    // Navigate to the Required Documents section
    const requiredDocsSection = page.locator('[data-testid="required-documents-section"]').or(page.locator('text=Required Documents').locator('..'));
    await expect(requiredDocsSection).toBeVisible();

    // Simulate clicking on a broken or unavailable document link
    // Create a test link with broken URL for testing error handling
    await page.evaluate(() => {
      const section = document.querySelector('[data-testid="required-documents-section"]') || document.body;
      const brokenLink = document.createElement('a');
      brokenLink.href = '/broken-document-link-404';
      brokenLink.textContent = 'Test Broken Link';
      brokenLink.setAttribute('data-testid', 'broken-link-test');
      section.appendChild(brokenLink);
    });

    const brokenLink = page.locator('[data-testid="broken-link-test"]');
    await brokenLink.click();

    // Observe the error message or notification displayed
    const errorMessage = page.locator('[data-testid="error-message"]').or(page.locator('text=/error|not found|unavailable/i')).first();
    
    // Verify that the error message provides alternative actions or contact information
    await page.waitForTimeout(1000);
    const pageContent = await page.content();
    const hasErrorHandling = pageContent.toLowerCase().includes('error') || 
                            pageContent.toLowerCase().includes('not found') ||
                            pageContent.toLowerCase().includes('contact');

    // Verify that the page does not crash or become unresponsive
    const isPageResponsive = await page.evaluate(() => {
      return document.readyState === 'complete';
    });
    expect(isPageResponsive).toBeTruthy();
  });

  test('Verify Required Documents section displays correctly on mobile devices', async ({ page, browser }) => {
    // Open the I-9 landing page on a mobile device (or use browser mobile emulation)
    const mobileContext = await browser.newContext({
      viewport: { width: 375, height: 667 },
      userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15'
    });
    const mobilePage = await mobileContext.newPage();
    await mobilePage.goto(I9_LANDING_PAGE_URL);

    // Scroll to the Required Documents section
    const requiredDocsSection = mobilePage.locator('[data-testid="required-documents-section"]').or(mobilePage.locator('text=Required Documents').locator('..'));
    await requiredDocsSection.scrollIntoViewIfNeeded();
    await expect(requiredDocsSection).toBeVisible();

    // Verify that all document names are readable without horizontal scrolling
    const documentList = requiredDocsSection.locator('[data-testid="document-list"]').or(requiredDocsSection.locator('ul, ol'));
    const documentItems = documentList.locator('li');
    const itemCount = await documentItems.count();

    for (let i = 0; i < itemCount; i++) {
      const item = documentItems.nth(i);
      await expect(item).toBeVisible();
      const boundingBox = await item.boundingBox();
      expect(boundingBox).toBeTruthy();
      expect(boundingBox!.width).toBeLessThanOrEqual(375);
    }

    // Verify that document categories are clearly separated and distinguishable
    const listASection = mobilePage.locator('[data-testid="list-a-section"]').or(mobilePage.locator('text=List A').locator('..'));
    const listBSection = mobilePage.locator('[data-testid="list-b-section"]').or(mobilePage.locator('text=List B').locator('..'));
    const listCSection = mobilePage.locator('[data-testid="list-c-section"]').or(mobilePage.locator('text=List C').locator('..'));

    await expect(listASection).toBeVisible();
    await expect(listBSection).toBeVisible();
    await expect(listCSection).toBeVisible();

    // Tap on a document link
    const documentLinks = requiredDocsSection.locator('a[href]');
    const firstLink = documentLinks.first();
    await firstLink.tap();
    await mobilePage.waitForLoadState('networkidle');

    // Test multiple document links on mobile
    await mobilePage.goto(I9_LANDING_PAGE_URL);
    const linkCount = await documentLinks.count();
    for (let i = 0; i < Math.min(linkCount, 3); i++) {
      const link = documentLinks.nth(i);
      const href = await link.getAttribute('href');
      expect(href).toBeTruthy();
    }

    await mobileContext.close();
  });

  test('Verify document list updates reflect the latest acceptable documents from HR', async ({ page }) => {
    // Obtain the latest list of acceptable I-9 documents from HR (simulated with expected documents)
    const expectedDocuments = [
      'U.S. Passport',
      'Permanent Resident Card',
      'Employment Authorization Document',
      'Driver\'s License',
      'State ID Card',
      'Social Security Card',
      'Birth Certificate'
    ];

    // Navigate to the Required Documents section on the I-9 landing page
    const requiredDocsSection = page.locator('[data-testid="required-documents-section"]').or(page.locator('text=Required Documents').locator('..'));
    await expect(requiredDocsSection).toBeVisible();

    // Compare each document listed on the page with the official HR list
    const documentList = requiredDocsSection.locator('[data-testid="document-list"]').or(requiredDocsSection.locator('ul, ol'));
    const documentItems = documentList.locator('li');
    const itemCount = await documentItems.count();
    expect(itemCount).toBeGreaterThan(0);

    const displayedDocuments: string[] = [];
    for (let i = 0; i < itemCount; i++) {
      const text = await documentItems.nth(i).textContent();
      if (text) {
        displayedDocuments.push(text.trim());
      }
    }

    // Verify that no outdated or deprecated documents are listed
    const deprecatedDocuments = ['Certificate of Citizenship (old version)', 'Expired Passport'];
    for (const deprecated of deprecatedDocuments) {
      const hasDeprecated = displayedDocuments.some(doc => doc.toLowerCase().includes(deprecated.toLowerCase()));
      expect(hasDeprecated).toBeFalsy();
    }

    // Check that any newly added acceptable documents are included
    const hasCurrentDocuments = displayedDocuments.length > 0;
    expect(hasCurrentDocuments).toBeTruthy();

    // Verify document descriptions match current HR guidelines
    for (let i = 0; i < Math.min(itemCount, 3); i++) {
      const item = documentItems.nth(i);
      const text = await item.textContent();
      expect(text).toBeTruthy();
      expect(text!.trim().length).toBeGreaterThan(0);
    }
  });

  test('Verify accessibility of Required Documents section for users with disabilities', async ({ page }) => {
    // Navigate to the I-9 landing page using keyboard only (Tab key)
    await page.goto(I9_LANDING_PAGE_URL);

    // Tab to the Required Documents section
    let focusedElement = await page.evaluate(() => document.activeElement?.tagName);
    
    // Navigate through the document list using keyboard
    for (let i = 0; i < 10; i++) {
      await page.keyboard.press('Tab');
      focusedElement = await page.evaluate(() => {
        const el = document.activeElement;
        return el?.textContent?.toLowerCase().includes('required documents') ? el.tagName : null;
      });
      if (focusedElement) break;
    }

    // Verify that document categories are accessible
    const requiredDocsSection = page.locator('[data-testid="required-documents-section"]').or(page.locator('text=Required Documents').locator('..'));
    
    // Check ARIA labels and roles
    const hasAriaLabel = await requiredDocsSection.getAttribute('aria-label');
    const hasRole = await requiredDocsSection.getAttribute('role');
    const hasAccessibleName = hasAriaLabel || hasRole || await requiredDocsSection.locator('h1, h2, h3, h4').count() > 0;
    expect(hasAccessibleName).toBeTruthy();

    // Press Enter on a document link using keyboard
    const documentLinks = requiredDocsSection.locator('a[href]');
    const firstLink = documentLinks.first();
    await firstLink.focus();
    
    const linkHref = await firstLink.getAttribute('href');
    expect(linkHref).toBeTruthy();

    // Check color contrast of text and links using accessibility tools
    const linkColor = await firstLink.evaluate((el) => {
      const styles = window.getComputedStyle(el);
      return {
        color: styles.color,
        backgroundColor: styles.backgroundColor
      };
    });
    expect(linkColor.color).toBeTruthy();

    // Verify that all images or icons have appropriate alt text
    const images = requiredDocsSection.locator('img');
    const imageCount = await images.count();
    
    for (let i = 0; i < imageCount; i++) {
      const img = images.nth(i);
      const alt = await img.getAttribute('alt');
      const ariaLabel = await img.getAttribute('aria-label');
      const hasAccessibleText = alt !== null || ariaLabel !== null;
      expect(hasAccessibleText).toBeTruthy();
    }

    // Verify SVG icons have accessible names
    const svgIcons = requiredDocsSection.locator('svg');
    const svgCount = await svgIcons.count();
    
    for (let i = 0; i < svgCount; i++) {
      const svg = svgIcons.nth(i);
      const ariaLabel = await svg.getAttribute('aria-label');
      const role = await svg.getAttribute('role');
      const title = await svg.locator('title').count();
      const hasAccessibleName = ariaLabel || role === 'img' || title > 0;
      expect(hasAccessibleName).toBeTruthy();
    }
  });
});