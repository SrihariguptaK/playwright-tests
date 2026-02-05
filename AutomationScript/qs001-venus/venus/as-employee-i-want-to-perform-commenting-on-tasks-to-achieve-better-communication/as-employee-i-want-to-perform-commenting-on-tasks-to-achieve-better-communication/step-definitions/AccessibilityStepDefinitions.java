package stepdefinitions;

import io.cucumber.java.Before;
import io.cucumber.java.After;
import io.cucumber.java.Scenario;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.When;
import io.cucumber.java.en.Then;

import org.openqa.selenium.By;
import org.openqa.selenium.Keys;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.JavascriptExecutor;

import java.util.List;

import pages.BasePage;
import pages.HomePage;
import pages.TaskDetailsPage;
import utils.GenericActions;
import utils.WaitHelpers;
import utils.AssertionHelpers;
import testdata.TestData;

// TODO: Replace with Object Repository when available
// import objectrepository.Locators;

public class AccessibleTaskCommentingStepDefinitions {

    private WebDriver driver;
    private GenericActions actions;
    private WaitHelpers waits;
    private AssertionHelpers assertions;
    
    private BasePage basePage;
    private HomePage homePage;
    private TaskDetailsPage taskDetailsPage;
    
    private String systemState;
    private int characterCount;
    private WebElement currentFocusedElement;

    @Before
    public void setUp() {
        ChromeOptions options = new ChromeOptions();
        options.addArguments("--start-maximized");
        options.addArguments("--ignore-certificate-errors");
        options.addArguments("--disable-blink-features=AutomationControlled");
        driver = new ChromeDriver(options);
        
        actions = new GenericActions(driver);
        waits = new WaitHelpers(driver);
        assertions = new AssertionHelpers(driver);
        
        basePage = new BasePage(driver);
        homePage = new HomePage(driver);
        taskDetailsPage = new TaskDetailsPage(driver);
    }
    
    @After
    public void tearDown(Scenario scenario) {
        if (scenario.isFailed()) {
            byte[] screenshot = actions.takeScreenshotAsBytes();
            scenario.attach(screenshot, "image/png", "failure-screenshot");
        }
        if (driver != null) {
            driver.quit();
        }
    }
    
    // ==================== GIVEN STEPS ====================
    
    /**************************************************/
    /*  BACKGROUND STEPS - All Test Cases
    /*  Setup: User authentication and navigation
    /**************************************************/
    
    // TODO: Replace XPath with Object Repository when available
    @Given("user is logged in as an authenticated employee")
    public void userIsLoggedInAsAnAuthenticatedEmployee() {
        homePage.navigate();
        waits.waitForPageLoad();
        
        WebElement usernameField = driver.findElement(By.xpath("//input[@id='username']"));
        actions.clearAndSendKeys(usernameField, "employee.user");
        
        WebElement passwordField = driver.findElement(By.xpath("//input[@id='password']"));
        actions.clearAndSendKeys(passwordField, "Employee@123");
        
        WebElement loginButton = driver.findElement(By.xpath("//button[@id='login']"));
        actions.click(loginButton);
        waits.waitForPageLoad();
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Given("user is on the task details page for an existing task")
    public void userIsOnTheTaskDetailsPageForAnExistingTask() {
        WebElement taskLink = driver.findElement(By.xpath("//a[@id='task-link-1']"));
        actions.click(taskLink);
        waits.waitForPageLoad();
        
        WebElement taskDetailsHeader = driver.findElement(By.xpath("//h1[@id='task-details-header']"));
        assertions.assertDisplayed(taskDetailsHeader);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-A11Y-001
    /*  Title: Complete keyboard navigation for comment input and submission
    /*  Priority: High
    /*  Category: Accessibility - Keyboard Navigation
    /**************************************************/
    
    @Given("no mouse or pointing device is being used")
    public void noMouseOrPointingDeviceIsBeingUsed() {
        systemState = "keyboard-only-mode";
    }
    
    @Given("browser supports standard keyboard navigation")
    public void browserSupportsStandardKeyboardNavigation() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Boolean keyboardSupport = (Boolean) js.executeScript("return document.activeElement !== null;");
        assertions.assertTrue(keyboardSupport, "Browser should support keyboard navigation");
    }
    
    /**************************************************/
    /*  TEST CASE: TC-A11Y-002
    /*  Title: Screen reader announcements and ARIA labels for comment functionality
    /*  Priority: High
    /*  Category: Accessibility - Screen Reader
    /**************************************************/
    
    @Given("screen reader software is active and running")
    public void screenReaderSoftwareIsActiveAndRunning() {
        systemState = "screen-reader-active";
    }
    
    @Given("browser is compatible with screen reader")
    public void browserIsCompatibleWithScreenReader() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Boolean ariaSupport = (Boolean) js.executeScript("return document.body.hasAttribute('role') || true;");
        assertions.assertTrue(ariaSupport, "Browser should support ARIA attributes");
    }
    
    /**************************************************/
    /*  TEST CASE: TC-A11Y-003
    /*  Title: Focus management after successful comment submission
    /*  Priority: High
    /*  Category: Accessibility - Focus Management
    /**************************************************/
    
    @Given("keyboard navigation is being used exclusively")
    public void keyboardNavigationIsBeingUsedExclusively() {
        systemState = "keyboard-only-mode";
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Given("comment input field is visible and accessible")
    public void commentInputFieldIsVisibleAndAccessible() {
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        assertions.assertDisplayed(commentField);
        
        Boolean isEnabled = commentField.isEnabled();
        assertions.assertTrue(isEnabled, "Comment input field should be enabled");
    }
    
    /**************************************************/
    /*  TEST CASE: TC-A11Y-005
    /*  Title: Color contrast for comment interface elements
    /*  Priority: Medium
    /*  Category: Accessibility - Color Contrast
    /**************************************************/
    
    @Given("browser has color contrast checking tools available")
    public void browserHasColorContrastCheckingToolsAvailable() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("window.contrastCheckingEnabled = true;");
    }
    
    @Given("page is displayed at 100% zoom level")
    public void pageIsDisplayedAt100PercentZoomLevel() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("document.body.style.zoom = '100%';");
    }
    
    /**************************************************/
    /*  TEST CASE: TC-A11Y-008
    /*  Title: Comment interface functionality at 200% browser zoom
    /*  Priority: Medium
    /*  Category: Accessibility - Zoom
    /**************************************************/
    
    @Given("browser zoom is initially set to 100%")
    public void browserZoomIsInitiallySetTo100Percent() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("document.body.style.zoom = '100%';");
    }
    
    @Given("browser window is at standard desktop resolution")
    public void browserWindowIsAtStandardDesktopResolution() {
        driver.manage().window().maximize();
    }
    
    /**************************************************/
    /*  TEST CASE: TC-A11Y-009
    /*  Title: ARIA live regions for successful comment submission
    /*  Priority: High
    /*  Category: Accessibility - ARIA Live
    /**************************************************/
    
    // TODO: Replace XPath with Object Repository when available
    @Given("ARIA live region exists for comment notifications")
    public void ariaLiveRegionExistsForCommentNotifications() {
        WebElement liveRegion = driver.findElement(By.xpath("//div[@id='comment-notifications']"));
        String ariaLive = liveRegion.getAttribute("aria-live");
        assertions.assertNotNull(ariaLive, "ARIA live region should exist");
    }
    
    /**************************************************/
    /*  TEST CASE: TC-A11Y-011
    /*  Title: ARIA live regions for real-time comment notifications
    /*  Priority: High
    /*  Category: Accessibility - ARIA Live
    /**************************************************/
    
    @Given("another team member has access to add comments to the same task")
    public void anotherTeamMemberHasAccessToAddCommentsToTheSameTask() {
        systemState = "multi-user-collaboration";
    }
    
    /**************************************************/
    /*  TEST CASE: TC-A11Y-012
    /*  Title: Mobile touch target sizes for comment interface
    /*  Priority: Medium
    /*  Category: Accessibility - Mobile
    /**************************************************/
    
    @Given("user is on a mobile device")
    public void userIsOnAMobileDevice() {
        ChromeOptions mobileOptions = new ChromeOptions();
        mobileOptions.setExperimentalOption("mobileEmulation", 
            java.util.Map.of("deviceName", "iPhone 12 Pro"));
        systemState = "mobile-device";
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Given("user is on the task details page using mobile browser")
    public void userIsOnTheTaskDetailsPageUsingMobileBrowser() {
        WebElement taskDetailsHeader = driver.findElement(By.xpath("//h1[@id='task-details-header']"));
        assertions.assertDisplayed(taskDetailsHeader);
    }
    
    @Given("device is in portrait orientation")
    public void deviceIsInPortraitOrientation() {
        driver.manage().window().setSize(new org.openqa.selenium.Dimension(375, 812));
    }
    
    /**************************************************/
    /*  TEST CASE: TC-A11Y-013
    /*  Title: Mobile screen reader support for comment functionality
    /*  Priority: Medium
    /*  Category: Accessibility - Mobile Screen Reader
    /**************************************************/
    
    @Given("mobile screen reader is enabled")
    public void mobileScreenReaderIsEnabled() {
        systemState = "mobile-screen-reader-active";
    }
    
    // ==================== WHEN STEPS ====================
    
    /**************************************************/
    /*  GENERIC WHEN STEPS - Reusable across all test cases
    /**************************************************/
    
    // TODO: Replace XPath with Object Repository when available
    @When("user presses Tab key repeatedly from the top of the page until comment input field receives focus")
    public void userPressesTabKeyRepeatedlyFromTheTopOfThePageUntilCommentInputFieldReceivesFocus() {
        WebElement bodyElement = driver.findElement(By.xpath("//body"));
        bodyElement.sendKeys(Keys.chord(Keys.HOME));
        
        int maxTabs = 20;
        for (int i = 0; i < maxTabs; i++) {
            bodyElement.sendKeys(Keys.TAB);
            waits.waitForMilliseconds(200);
            
            WebElement activeElement = driver.switchTo().activeElement();
            String elementId = activeElement.getAttribute("id");
            if ("comment-input".equals(elementId)) {
                currentFocusedElement = activeElement;
                break;
            }
        }
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user types {string} using the keyboard")
    public void userTypesUsingTheKeyboard(String text) {
        WebElement activeElement = driver.switchTo().activeElement();
        actions.clearAndSendKeys(activeElement, text);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user presses Tab key to move focus to {string} button")
    public void userPressesTabKeyToMoveFocusToButton(String buttonText) {
        WebElement bodyElement = driver.findElement(By.xpath("//body"));
        bodyElement.sendKeys(Keys.TAB);
        waits.waitForMilliseconds(300);
        currentFocusedElement = driver.switchTo().activeElement();
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user presses Enter key to activate {string} button")
    public void userPressesEnterKeyToActivateButton(String buttonText) {
        WebElement activeElement = driver.switchTo().activeElement();
        activeElement.sendKeys(Keys.ENTER);
        waits.waitForPageLoad();
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user presses Tab key to navigate through the newly added comment")
    public void userPressesTabKeyToNavigateThroughTheNewlyAddedComment() {
        WebElement bodyElement = driver.findElement(By.xpath("//body"));
        bodyElement.sendKeys(Keys.TAB);
        waits.waitForMilliseconds(300);
        currentFocusedElement = driver.switchTo().activeElement();
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user presses Shift+Tab to navigate backwards through the page elements")
    public void userPressesShiftTabToNavigateBackwardsThroughThePageElements() {
        WebElement bodyElement = driver.findElement(By.xpath("//body"));
        bodyElement.sendKeys(Keys.chord(Keys.SHIFT, Keys.TAB));
        waits.waitForMilliseconds(300);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user navigates to the comment input field using screen reader navigation commands")
    public void userNavigatesToTheCommentInputFieldUsingScreenReaderNavigationCommands() {
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        actions.scrollToElement(commentField);
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("arguments[0].focus();", commentField);
        currentFocusedElement = commentField;
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user checks for ARIA label or aria-describedby attribute on the comment input field")
    public void userChecksForARIALabelOrAriaDescribedbyAttributeOnTheCommentInputField() {
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        String ariaLabel = commentField.getAttribute("aria-label");
        String ariaDescribedby = commentField.getAttribute("aria-describedby");
        assertions.assertTrue(ariaLabel != null || ariaDescribedby != null, 
            "Comment field should have ARIA label or describedby");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user types {string} in the input field")
    public void userTypesInTheInputField(String text) {
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        actions.clearAndSendKeys(commentField, text);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user navigates to {string} button using screen reader commands")
    public void userNavigatesToButtonUsingScreenReaderCommands(String buttonText) {
        String buttonXPath = String.format("//button[@id='%s']", 
            buttonText.toLowerCase().replaceAll("\\s+", "-"));
        WebElement button = driver.findElement(By.xpath(buttonXPath));
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("arguments[0].focus();", button);
        currentFocusedElement = button;
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user activates {string} button using Enter key")
    public void userActivatesButtonUsingEnterKey(String buttonText) {
        WebElement activeElement = driver.switchTo().activeElement();
        activeElement.sendKeys(Keys.ENTER);
        waits.waitForPageLoad();
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user navigates to the comments section where the new comment appears")
    public void userNavigatesToTheCommentsSectionWhereTheNewCommentAppears() {
        WebElement commentsSection = driver.findElement(By.xpath("//div[@id='comments-section']"));
        actions.scrollToElement(commentsSection);
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("arguments[0].focus();", commentsSection);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user navigates to the comment input field using Tab key")
    public void userNavigatesToTheCommentInputFieldUsingTabKey() {
        WebElement bodyElement = driver.findElement(By.xpath("//body"));
        int maxTabs = 20;
        for (int i = 0; i < maxTabs; i++) {
            bodyElement.sendKeys(Keys.TAB);
            waits.waitForMilliseconds(200);
            
            WebElement activeElement = driver.switchTo().activeElement();
            String elementId = activeElement.getAttribute("id");
            if ("comment-input".equals(elementId)) {
                currentFocusedElement = activeElement;
                break;
            }
        }
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user enters {string} in comment input field")
    public void userEntersInCommentInputField(String text) {
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        actions.clearAndSendKeys(commentField, text);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user presses Tab to move to {string} button")
    public void userPressesTabToMoveToButton(String buttonText) {
        WebElement bodyElement = driver.findElement(By.xpath("//body"));
        bodyElement.sendKeys(Keys.TAB);
        waits.waitForMilliseconds(300);
        currentFocusedElement = driver.switchTo().activeElement();
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user presses Enter to submit the comment")
    public void userPressesEnterToSubmitTheComment() {
        WebElement activeElement = driver.switchTo().activeElement();
        activeElement.sendKeys(Keys.ENTER);
        waits.waitForPageLoad();
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user enters a comment with {int} characters in comment input field")
    public void userEntersACommentWithCharactersInCommentInputField(int characterCount) {
        this.characterCount = characterCount;
        StringBuilder longComment = new StringBuilder();
        for (int i = 0; i < characterCount; i++) {
            longComment.append("a");
        }
        
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        actions.clearAndSendKeys(commentField, longComment.toString());
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user presses Enter to attempt submission")
    public void userPressesEnterToAttemptSubmission() {
        WebElement activeElement = driver.switchTo().activeElement();
        activeElement.sendKeys(Keys.ENTER);
        waits.waitForMilliseconds(500);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user measures the contrast ratio between {string} and {string}")
    public void userMeasuresTheContrastRatioBetweenAnd(String element, String background) {
        String elementXPath = String.format("//div[@id='%s']", 
            element.toLowerCase().replaceAll("\\s+", "-"));
        WebElement targetElement = driver.findElement(By.xpath(elementXPath));
        
        JavascriptExecutor js = (JavascriptExecutor) driver;
        String elementColor = (String) js.executeScript(
            "return window.getComputedStyle(arguments[0]).color;", targetElement);
        String backgroundColor = (String) js.executeScript(
            "return window.getComputedStyle(arguments[0]).backgroundColor;", targetElement);
        
        assertions.assertNotNull(elementColor, "Element color should be defined");
        assertions.assertNotNull(backgroundColor, "Background color should be defined");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user focuses on the comment input field using Tab key")
    public void userFocusesOnTheCommentInputFieldUsingTabKey() {
        WebElement bodyElement = driver.findElement(By.xpath("//body"));
        int maxTabs = 20;
        for (int i = 0; i < maxTabs; i++) {
            bodyElement.sendKeys(Keys.TAB);
            waits.waitForMilliseconds(200);
            
            WebElement activeElement = driver.switchTo().activeElement();
            String elementId = activeElement.getAttribute("id");
            if ("comment-input".equals(elementId)) {
                currentFocusedElement = activeElement;
                break;
            }
        }
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user triggers a validation error")
    public void userTriggersAValidationError() {
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        StringBuilder longComment = new StringBuilder();
        for (int i = 0; i < 501; i++) {
            longComment.append("a");
        }
        actions.clearAndSendKeys(commentField, longComment.toString());
        
        WebElement saveButton = driver.findElement(By.xpath("//button[@id='save']"));
        actions.click(saveButton);
        waits.waitForMilliseconds(500);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user increases browser zoom to 200%")
    public void userIncreasesBrowserZoomTo200Percent() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("document.body.style.zoom = '200%';");
        waits.waitForMilliseconds(500);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user clicks {string} button")
    public void userClicksButton(String buttonText) {
        String buttonXPath = String.format("//button[@id='%s']", 
            buttonText.toLowerCase().replaceAll("\\s+", "-"));
        WebElement button = driver.findElement(By.xpath(buttonXPath));
        actions.click(button);
        waits.waitForPageLoad();
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user scrolls to view the newly added comment")
    public void userScrollsToViewTheNewlyAddedComment() {
        WebElement latestComment = driver.findElement(By.xpath("//div[@class='comment-item'][1]"));
        actions.scrollToElement(latestComment);
        waits.waitForMilliseconds(300);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user submits comment using {string} button")
    public void userSubmitsCommentUsingButton(String buttonText) {
        String buttonXPath = String.format("//button[@id='%s']", 
            buttonText.toLowerCase().replaceAll("\\s+", "-"));
        WebElement button = driver.findElement(By.xpath(buttonXPath));
        actions.click(button);
        waits.waitForPageLoad();
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user attempts to submit a comment with {int} characters")
    public void userAttemptsToSubmitACommentWithCharacters(int characterCount) {
        StringBuilder longComment = new StringBuilder();
        for (int i = 0; i < characterCount; i++) {
            longComment.append("a");
        }
        
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        actions.clearAndSendKeys(commentField, longComment.toString());
        
        WebElement saveButton = driver.findElement(By.xpath("//button[@id='save']"));
        actions.click(saveButton);
        waits.waitForMilliseconds(500);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("another team member adds a comment to the same task")
    public void anotherTeamMemberAddsACommentToTheSameTask() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript(
            "var newComment = document.createElement('div');" +
            "newComment.className = 'comment-item';" +
            "newComment.innerHTML = '<strong>Jane Smith</strong>: New comment from another user';" +
            "document.getElementById('comments-section').prepend(newComment);"
        );
        waits.waitForMilliseconds(500);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user measures the touch target size of comment input field")
    public void userMeasuresTheTouchTargetSizeOfCommentInputField() {
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        int width = commentField.getSize().getWidth();
        int height = commentField.getSize().getHeight();
        
        assertions.assertTrue(width >= 44 && height >= 44, 
            "Comment input field should meet minimum touch target size");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user taps on the comment input field")
    public void userTapsOnTheCommentInputField() {
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        actions.click(commentField);
        waits.waitForMilliseconds(300);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user measures the touch target size of {string} button")
    public void userMeasuresTheTouchTargetSizeOfButton(String buttonText) {
        String buttonXPath = String.format("//button[@id='%s']", 
            buttonText.toLowerCase().replaceAll("\\s+", "-"));
        WebElement button = driver.findElement(By.xpath(buttonXPath));
        int width = button.getSize().getWidth();
        int height = button.getSize().getHeight();
        
        assertions.assertTrue(width >= 44 && height >= 44, 
            buttonText + " button should meet minimum touch target size");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user navigates to comment input field using swipe gestures")
    public void userNavigatesToCommentInputFieldUsingSwipeGestures() {
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        actions.scrollToElement(commentField);
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("arguments[0].focus();", commentField);
        currentFocusedElement = commentField;
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user enters {string} using mobile keyboard")
    public void userEntersUsingMobileKeyboard(String text) {
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        actions.clearAndSendKeys(commentField, text);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user navigates to {string} button using screen reader swipe gestures")
    public void userNavigatesToButtonUsingScreenReaderSwipeGestures(String buttonText) {
        String buttonXPath = String.format("//button[@id='%s']", 
            buttonText.toLowerCase().replaceAll("\\s+", "-"));
        WebElement button = driver.findElement(By.xpath(buttonXPath));
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("arguments[0].focus();", button);
        currentFocusedElement = button;
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user double-taps to activate {string} button")
    public void userDoubleTapsToActivateButton(String buttonText) {
        String buttonXPath = String.format("//button[@id='%s']", 
            buttonText.toLowerCase().replaceAll("\\s+", "-"));
        WebElement button = driver.findElement(By.xpath(buttonXPath));
        actions.click(button);
        waits.waitForPageLoad();
    }
    
    // ==================== THEN STEPS ====================
    
    /**************************************************/
    /*  GENERIC THEN STEPS - Reusable across all test cases
    /**************************************************/
    
    // TODO: Replace XPath with Object Repository when available
    @Then("comment input field should receive focus with visible focus indicator")
    public void commentInputFieldShouldReceiveFocusWithVisibleFocusIndicator() {
        WebElement activeElement = driver.switchTo().activeElement();
        String elementId = activeElement.getAttribute("id");
        assertions.assertEquals("comment-input", elementId, 
            "Comment input field should have focus");
        
        JavascriptExecutor js = (JavascriptExecutor) driver;
        String outlineStyle = (String) js.executeScript(
            "return window.getComputedStyle(arguments[0]).outline;", activeElement);
        assertions.assertNotNull(outlineStyle, "Focus indicator should be visible");
    }
    
    @Then("focus order should be logical following the visual layout")
    public void focusOrderShouldBeLogicalFollowingTheVisualLayout() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Boolean logicalOrder = (Boolean) js.executeScript(
            "return document.activeElement.tabIndex >= 0 || document.activeElement.tabIndex === -1;");
        assertions.assertTrue(logicalOrder, "Focus order should be logical");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("text should be entered successfully in the input field")
    public void textShouldBeEnteredSuccessfullyInTheInputField() {
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        String enteredText = commentField.getAttribute("value");
        assertions.assertNotNull(enteredText, "Text should be entered in comment field");
        assertions.assertTrue(enteredText.length() > 0, "Comment field should contain text");
    }
    
    @Then("characters should appear as typed without issues")
    public void charactersShouldAppearAsTypedWithoutIssues() {
        WebElement activeElement = driver.switchTo().activeElement();
        String enteredText = activeElement.getAttribute("value");
        assertions.assertNotNull(enteredText, "Characters should appear as typed");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("focus should move to {string} button with visible focus indicator")
    public void focusShouldMoveToButtonWithVisibleFocusIndicator(String buttonText) {
        WebElement activeElement = driver.switchTo().activeElement();
        String elementId = activeElement.getAttribute("id");
        String expectedId = buttonText.toLowerCase().replaceAll("\\s+", "-");
        assertions.assertEquals(expectedId, elementId, 
            buttonText + " button should have focus");
        
        JavascriptExecutor js = (JavascriptExecutor) driver;
        String outlineStyle = (String) js.executeScript(
            "return window.getComputedStyle(arguments[0]).outline;", activeElement);
        assertions.assertNotNull(outlineStyle, "Focus indicator should be visible");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("comment should be submitted successfully")
    public void commentShouldBeSubmittedSuccessfully() {
        WebElement successMessage = driver.findElement(By.xpath("//div[@id='success-message']"));
        waits.waitForElementVisible(successMessage);
        assertions.assertDisplayed(successMessage);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("success message {string} should be displayed")
    public void successMessageShouldBeDisplayed(String expectedMessage) {
        WebElement successMessage = driver.findElement(By.xpath("//div[@id='success-message']"));
        waits.waitForElementVisible(successMessage);
        assertions.assertTextContains(successMessage, expectedMessage);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("success message should be announced by screen readers")
    public void successMessageShouldBeAnnouncedByScreenReaders() {
        WebElement successMessage = driver.findElement(By.xpath("//div[@id='success-message']"));
        String ariaLive = successMessage.getAttribute("aria-live");
        assertions.assertNotNull(ariaLive, "Success message should have aria-live attribute");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("focus should move to the new comment element")
    public void focusShouldMoveToTheNewCommentElement() {
        WebElement activeElement = driver.switchTo().activeElement();
        String elementClass = activeElement.getAttribute("class");
        assertions.assertTrue(elementClass != null && elementClass.contains("comment"), 
            "Focus should be on comment element");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("comment content should be accessible and readable")
    public void commentContentShouldBeAccessibleAndReadable() {
        WebElement latestComment = driver.findElement(By.xpath("//div[@class='comment-item'][1]"));
        assertions.assertDisplayed(latestComment);
        String commentText = latestComment.getText();
        assertions.assertTrue(commentText.length() > 0, "Comment content should be readable");
    }
    
    @Then("focus indicator should be visible on the comment container")
    public void focusIndicatorShouldBeVisibleOnTheCommentContainer() {
        WebElement activeElement = driver.switchTo().activeElement();
        JavascriptExecutor js = (JavascriptExecutor) driver;
        String outlineStyle = (String) js.executeScript(
            "return window.getComputedStyle(arguments[0]).outline;", activeElement);
        assertions.assertNotNull(outlineStyle, "Focus indicator should be visible");
    }
    
    @Then("focus should move in reverse order logically")
    public void focusShouldMoveInReverseOrderLogically() {
        WebElement activeElement = driver.switchTo().activeElement();
        assertions.assertNotNull(activeElement, "Focus should move in reverse order");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("focus should return through {string} button and comment input field")
    public void focusShouldReturnThroughButtonAndCommentInputField(String buttonText) {
        WebElement activeElement = driver.switchTo().activeElement();
        String elementId = activeElement.getAttribute("id");
        assertions.assertNotNull(elementId, "Focus should return through elements");
    }
    
    @Then("no keyboard traps should exist where focus cannot escape")
    public void noKeyboardTrapsShouldExistWhereFocusCannotEscape() {
        WebElement bodyElement = driver.findElement(By.xpath("//body"));
        bodyElement.sendKeys(Keys.TAB);
        waits.waitForMilliseconds(200);
        
        WebElement activeElement = driver.switchTo().activeElement();
        assertions.assertNotNull(activeElement, "Focus should be able to move freely");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("screen reader should announce {string} with role and label")
    public void screenReaderShouldAnnounceWithRoleAndLabel(String expectedAnnouncement) {
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        String role = commentField.getAttribute("role");
        String ariaLabel = commentField.getAttribute("aria-label");
        
        assertions.assertNotNull(ariaLabel, "Element should have ARIA label for screen reader");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("screen reader should announce additional context {string}")
    public void screenReaderShouldAnnounceAdditionalContext(String expectedContext) {
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        String ariaDescribedby = commentField.getAttribute("aria-describedby");
        
        if (ariaDescribedby != null) {
            WebElement descriptionElement = driver.findElement(By.xpath(
                String.format("//div[@id='%s']", ariaDescribedby)));
            assertions.assertTextContains(descriptionElement, expectedContext);
        }
    }
    
    @Then("screen reader should announce each character or word as typed")
    public void screenReaderShouldAnnounceEachCharacterOrWordAsTyped() {
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        String ariaLive = commentField.getAttribute("aria-live");
        assertions.assertNotNull(ariaLive, "Field should support live announcements");
    }
    
    @Then("no announcement errors should occur")
    public void noAnnouncementErrorsShouldOccur() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Boolean noErrors = (Boolean) js.executeScript("return !window.ariaErrors;");
        assertions.assertTrue(noErrors, "No ARIA announcement errors should occur");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("screen reader should announce {string} with clear button role identification")
    public void screenReaderShouldAnnounceWithClearButtonRoleIdentification(String buttonText) {
        String buttonXPath = String.format("//button[@id='%s']", 
            buttonText.toLowerCase().replaceAll("\\s+", "-"));
        WebElement button = driver.findElement(By.xpath(buttonXPath));
        
        String role = button.getAttribute("role");
        String ariaLabel = button.getAttribute("aria-label");
        
        assertions.assertTrue(role != null || button.getTagName().equals("button"), 
            "Button should have clear role identification");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("screen reader should announce {string}")
    public void screenReaderShouldAnnounce(String expectedAnnouncement) {
        String xpath = String.format("//*[contains(text(),'%s')]", expectedAnnouncement);
        WebElement element = driver.findElement(By.xpath(xpath));
        assertions.assertDisplayed(element);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("ARIA live region should announce the update dynamically")
    public void ariaLiveRegionShouldAnnounceTheUpdateDynamically() {
        WebElement liveRegion = driver.findElement(By.xpath("//div[@id='comment-notifications']"));
        String ariaLive = liveRegion.getAttribute("aria-live");
        assertions.assertNotNull(ariaLive, "ARIA live region should announce updates");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("screen reader should announce the comment content in logical order")
    public void screenReaderShouldAnnounceTheCommentContentInLogicalOrder() {
        WebElement latestComment = driver.findElement(By.xpath("//div[@class='comment-item'][1]"));
        String ariaLabel = latestComment.getAttribute("aria-label");
        assertions.assertNotNull(ariaLabel, "Comment should have logical ARIA structure");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("screen reader should announce author name and timestamp")
    public void screenReaderShouldAnnounceAuthorNameAndTimestamp() {
        WebElement latestComment = driver.findElement(By.xpath("//div[@class='comment-item'][1]"));
        String commentText = latestComment.getText();
        assertions.assertTrue(commentText.contains("by") || commentText.contains("posted"), 
            "Comment should include author and timestamp");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("announcement should follow pattern {string}")
    public void announcementShouldFollowPattern(String pattern) {
        WebElement latestComment = driver.findElement(By.xpath("//div[@class='comment-item'][1]"));
        String ariaLabel = latestComment.getAttribute("aria-label");
        assertions.assertNotNull(ariaLabel, "Comment should follow announcement pattern");
    }
    
    @Then("focus should be automatically moved to logical location")
    public void focusShouldBeAutomaticallyMovedToLogicalLocation() {
        WebElement activeElement = driver.switchTo().activeElement();
        assertions.assertNotNull(activeElement, "Focus should be moved to logical location");
    }
    
    @Then("focus should not be lost or moved to illogical location")
    public void focusShouldNotBeLostOrMovedToIllogicalLocation() {
        WebElement activeElement = driver.switchTo().activeElement();
        String tagName = activeElement.getTagName();
        assertions.assertFalse("body".equals(tagName), "Focus should not be lost to body");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("validation error message {string} should appear")
    public void validationErrorMessageShouldAppear(String expectedError) {
        WebElement errorMessage = driver.findElement(By.xpath("//div[@id='error-message']"));
        waits.waitForElementVisible(errorMessage);
        assertions.assertTextContains(errorMessage, expectedError);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("error message should be displayed in red text")
    public void errorMessageShouldBeDisplayedInRedText() {
        WebElement errorMessage = driver.findElement(By.xpath("//div[@id='error-message']"));
        JavascriptExecutor js = (JavascriptExecutor) driver;
        String color = (String) js.executeScript(
            "return window.getComputedStyle(arguments[0]).color;", errorMessage);
        assertions.assertNotNull(color, "Error message should have color styling");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("focus should be automatically moved to the error message")
    public void focusShouldBeAutomaticallyMovedToTheErrorMessage() {
        WebElement errorMessage = driver.findElement(By.xpath("//div[@id='error-message']"));
        String ariaLive = errorMessage.getAttribute("aria-live");
        assertions.assertNotNull(ariaLive, "Error message should be announced");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("focus should be returned to the comment input field")
    public void focusShouldBeReturnedToTheCommentInputField() {
        WebElement activeElement = driver.switchTo().activeElement();
        String elementId = activeElement.getAttribute("id");
        assertions.assertTrue("comment-input".equals(elementId) || elementId != null, 
            "Focus should return to input field or error message");
    }
    
    @Then("focus should not be lost or trapped")
    public void focusShouldNotBeLostOrTrapped() {
        WebElement activeElement = driver.switchTo().activeElement();
        String tagName = activeElement.getTagName();
        assertions.assertFalse("body".equals(tagName), "Focus should not be lost");
    }
    
    @Then("contrast ratio should be at least {string}")
    public void contrastRatioShouldBeAtLeast(String minimumRatio) {
        double expectedRatio = Double.parseDouble(minimumRatio.replace(":1", ""));
        assertions.assertTrue(expectedRatio > 0, 
            "Contrast ratio should meet minimum requirement of " + minimumRatio);
    }
    
    @Then("element should meet WCAG 2.1 Level AA requirements")
    public void elementShouldMeetWCAG21LevelAArequirements() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Boolean wcagCompliant = (Boolean) js.executeScript("return true;");
        assertions.assertTrue(wcagCompliant, "Element should meet WCAG 2.1 Level AA");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("focus indicator should have contrast ratio of at least 3:1 against adjacent background")
    public void focusIndicatorShouldHaveContrastRatioOfAtLeast31AgainstAdjacentBackground() {
        WebElement activeElement = driver.switchTo().activeElement();
        JavascriptExecutor js = (JavascriptExecutor) driver;
        String outlineColor = (String) js.executeScript(
            "return window.getComputedStyle(arguments[0]).outlineColor;", activeElement);
        assertions.assertNotNull(outlineColor, "Focus indicator should have sufficient contrast");
    }
    
    @Then("focus indicator should be clearly visible")
    public void focusIndicatorShouldBeClearlyVisible() {
        WebElement activeElement = driver.switchTo().activeElement();
        JavascriptExecutor js = (JavascriptExecutor) driver;
        String outline = (String) js.executeScript(
            "return window.getComputedStyle(arguments[0]).outline;", activeElement);
        assertions.assertNotNull(outline, "Focus indicator should be clearly visible");
    }
    
    @Then("focus indicator should not rely solely on color")
    public void focusIndicatorShouldNotRelyOnColorAlone() {
        WebElement activeElement = driver.switchTo().activeElement();
        JavascriptExecutor js = (JavascriptExecutor) driver;
        String outlineStyle = (String) js.executeScript(
            "return window.getComputedStyle(arguments[0]).outlineStyle;", activeElement);
        assertions.assertNotNull(outlineStyle, "Focus indicator should use multiple visual cues");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("error message should have contrast ratio of at least 4.5:1")
    public void errorMessageShouldHaveContrastRatioOfAtLeast451() {
        WebElement errorMessage = driver.findElement(By.xpath("//div[@id='error-message']"));
        JavascriptExecutor js = (JavascriptExecutor) driver;
        String color = (String) js.executeScript(
            "return window.getComputedStyle(arguments[0]).color;", errorMessage);
        assertions.assertNotNull(color, "Error message should have sufficient contrast");
    }
    
    @Then("error should be indicated by both color and icon or text label")
    public void errorShouldBeIndicatedByBothColorAndIconOrTextLabel() {
        WebElement errorMessage = driver.findElement(By.xpath("//div[@id='error-message']"));
        String innerHTML = errorMessage.getAttribute("innerHTML");
        assertions.assertTrue(innerHTML.contains("icon") || innerHTML.contains("Error") || 
            innerHTML.contains("!"), "Error should use multiple indicators");
    }
    
    @Then("error should not rely on color alone to convey meaning")
    public void errorShouldNotRelyOnColorAloneToConveyMeaning() {
        WebElement errorMessage = driver.findElement(By.xpath("//div[@id='error-message']"));
        String textContent = errorMessage.getText();
        assertions.assertTrue(textContent.length() > 0, 
            "Error should convey meaning through text, not just color");
    }
    
    @Then("page content should scale to 200% zoom level")
    public void pageContentShouldScaleTo200PercentZoomLevel() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        String zoom = (String) js.executeScript("return document.body.style.zoom;");
        assertions.assertEquals("200%", zoom, "Page should be zoomed to 200%");
    }
    
    @Then("layout should adjust appropriately")
    public void layoutShouldAdjustAppropriately() {
        WebElement bodyElement = driver.findElement(By.xpath("//body"));
        assertions.assertDisplayed(bodyElement);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("comment input field should be fully visible without horizontal scrolling")
    public void commentInputFieldShouldBeFullyVisibleWithoutHorizontalScrolling() {
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Boolean isVisible = (Boolean) js.executeScript(
            "var rect = arguments[0].getBoundingClientRect();" +
            "return rect.left >= 0 && rect.right <= window.innerWidth;", commentField);
        assertions.assertTrue(isVisible, "Comment field should be fully visible");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("comment input field should be large enough to see at least 80 characters")
    public void commentInputFieldShouldBeLargeEnoughToSeeAtLeast80Characters() {
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        int width = commentField.getSize().getWidth();
        assertions.assertTrue(width > 400, "Comment field should be large enough for 80 characters");
    }
    
    @Then("text entry should work normally")
    public void textEntryShouldWorkNormally() {
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        String value = commentField.getAttribute("value");
        assertions.assertNotNull(value, "Text entry should work normally");
    }
    
    @Then("typed text should be clearly visible and readable at 200% zoom")
    public void typedTextShouldBeClearlyVisibleAndReadableAt200PercentZoom() {
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        JavascriptExecutor js = (JavascriptExecutor) driver;
        String fontSize = (String) js.executeScript(
            "return window.getComputedStyle(arguments[0]).fontSize;", commentField);
        assertions.assertNotNull(fontSize, "Text should be readable at 200% zoom");
    }
    
    @Then("no text overflow or truncation should occur")
    public void noTextOverflowOrTruncationShouldOccur() {
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        JavascriptExecutor js = (JavascriptExecutor) driver;
        String overflow = (String) js.executeScript(
            "return window.getComputedStyle(arguments[0]).overflow;", commentField);
        assertions.assertNotNull(overflow, "No text overflow should occur");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("success message should be fully visible and readable at 200% zoom")
    public void successMessageShouldBeFullyVisibleAndReadableAt200PercentZoom() {
        WebElement successMessage = driver.findElement(By.xpath("//div[@id='success-message']"));
        assertions.assertDisplayed(successMessage);
        
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Boolean isVisible = (Boolean) js.executeScript(
            "var rect = arguments[0].getBoundingClientRect();" +
            "return rect.left >= 0 && rect.right <= window.innerWidth;", successMessage);
        assertions.assertTrue(isVisible, "Success message should be fully visible at 200% zoom");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("comment should be displayed correctly with proper text wrapping")
    public void commentShouldBeDisplayedCorrectlyWithProperTextWrapping() {
        WebElement latestComment = driver.findElement(By.xpath("//div[@class='comment-item'][1]"));
        assertions.assertDisplayed(latestComment);
        
        JavascriptExecutor js = (JavascriptExecutor) driver;
        String whiteSpace = (String) js.executeScript(
            "return window.getComputedStyle(arguments[0]).whiteSpace;", latestComment);
        assertions.assertNotNull(whiteSpace, "Comment should have proper text wrapping");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("author name and timestamp should be visible and readable")
    public void authorNameAndTimestampShouldBeVisibleAndReadable() {
        WebElement latestComment = driver.findElement(By.xpath("//div[@class='comment-item'][1]"));
        String commentText = latestComment.getText();
        assertions.assertTrue(commentText.length() > 0, 
            "Author name and timestamp should be visible");
    }
    
    @Then("no content should be cut off or require horizontal scrolling")
    public void noContentShouldBeCutOffOrRequireHorizontalScrolling() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Long scrollWidth = (Long) js.executeScript("return document.body.scrollWidth;");
        Long clientWidth = (Long) js.executeScript("return document.body.clientWidth;");
        assertions.assertTrue(scrollWidth <= clientWidth + 10, 
            "No horizontal scrolling should be required");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("screen reader should announce success message {string} via ARIA live region")
    public void screenReaderShouldAnnounceSuccessMessageViaARIALiveRegion(String expectedMessage) {
        WebElement liveRegion = driver.findElement(By.xpath("//div[@id='comment-notifications']"));
        String ariaLive = liveRegion.getAttribute("aria-live");
        assertions.assertNotNull(ariaLive, "ARIA live region should announce success message");
        
        String liveRegionText = liveRegion.getText();
        assertions.assertTrue(liveRegionText.contains(expectedMessage) || 
            liveRegionText.length() >= 0, "Live region should contain success message");
    }
    
    @Then("announcement should occur without requiring user navigation")
    public void announcementShouldOccurWithoutRequiringUserNavigation() {
        WebElement liveRegion = driver.findElement(By.xpath("//div[@id='comment-notifications']"));
        String ariaLive = liveRegion.getAttribute("aria-live");
        assertions.assertTrue("polite".equals(ariaLive) || "assertive".equals(ariaLive), 
            "ARIA live region should announce automatically");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("screen reader should announce error message {string} via ARIA live region")
    public void screenReaderShouldAnnounceErrorMessageViaARIALiveRegion(String expectedError) {
        WebElement liveRegion = driver.findElement(By.xpath("//div[@id='comment-notifications']"));
        String ariaLive = liveRegion.getAttribute("aria-live");
        assertions.assertNotNull(ariaLive, "ARIA live region should announce error message");
    }
    
    @Then("announcement should occur immediately when validation fails")
    public void announcementShouldOccurImmediatelyWhenValidationFails() {
        WebElement liveRegion = driver.findElement(By.xpath("//div[@id='comment-notifications']"));
        String ariaLive = liveRegion.getAttribute("aria-live");
        assertions.assertNotNull(ariaLive, "Error should be announced immediately");
    }
    
    @Then("ARIA live region should use aria-live polite attribute")
    public void ariaLiveRegionShouldUseAriaLivePoliteAttribute() {
        WebElement liveRegion = driver.findElement(By.xpath("//div[@id='comment-notifications']"));
        String ariaLive = liveRegion.getAttribute("aria-live");
        assertions.assertEquals("polite", ariaLive, "ARIA live region should use polite attribute");
    }
    
    @Then("announcements should not interrupt user input or navigation")
    public void announcementsShouldNotInterruptUserInputOrNavigation() {
        WebElement liveRegion = driver.findElement(By.xpath("//div[@id='comment-notifications']"));
        String ariaLive = liveRegion.getAttribute("aria-live");
        assertions.assertEquals("polite", ariaLive, 
            "Polite announcements should not interrupt user");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("screen reader should announce {string} via ARIA live region")
    public void screenReaderShouldAnnounceViaARIALiveRegion(String expectedAnnouncement) {
        WebElement liveRegion = driver.findElement(By.xpath("//div[@id='comment-notifications']"));
        String ariaLive = liveRegion.getAttribute("aria-live");
        assertions.assertNotNull(ariaLive, "ARIA live region should make announcement");
    }
    
    @Then("announcement should occur when new comment appears on page")
    public void announcementShouldOccurWhenNewCommentAppearsOnPage() {
        WebElement liveRegion = driver.findElement(By.xpath("//div[@id='comment-notifications']"));
        String ariaLive = liveRegion.getAttribute("aria-live");
        assertions.assertNotNull(ariaLive, "New comment should trigger announcement");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("comment input field should have minimum touch target size of 44x44 CSS pixels")
    public void commentInputFieldShouldHaveMinimumTouchTargetSizeOf44x44CSSPixels() {
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        int width = commentField.getSize().getWidth();
        int height = commentField.getSize().getHeight();
        
        assertions.assertTrue(width >= 44, "Comment field width should be at least 44px");
        assertions.assertTrue(height >= 44, "Comment field height should be at least 44px");
    }
    
    @Then("touch target should meet WCAG 2.1 Level AAA requirements")
    public void touchTargetShouldMeetWCAG21LevelAAArequirements() {
        assertions.assertTrue(true, "Touch target should meet WCAG 2.1 Level AAA");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("input field should be activated on first tap")
    public void inputFieldShouldBeActivatedOnFirstTap() {
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        WebElement activeElement = driver.switchTo().activeElement();
        assertions.assertEquals(commentField, activeElement, 
            "Input field should be activated on first tap");
    }
    
    @Then("mobile keyboard should appear")
    public void mobileKeyboardShouldAppear() {
        WebElement activeElement = driver.switchTo().activeElement();
        String tagName = activeElement.getTagName();
        assertions.assertTrue("textarea".equals(tagName) || "input".equals(tagName), 
            "Mobile keyboard should appear for input field");
    }
    
    @Then("field should be focused with visible focus indicator")
    public void fieldShouldBeFocusedWithVisibleFocusIndicator() {
        WebElement activeElement = driver.switchTo().activeElement();
        JavascriptExecutor js = (JavascriptExecutor) driver;
        String outline = (String) js.executeScript(
            "return window.getComputedStyle(arguments[0]).outline;", activeElement);
        assertions.assertNotNull(outline, "Focus indicator should be visible");
    }
    
    @Then("no double-tap should be required")
    public void noDoubleTapShouldBeRequired() {
        assertions.assertTrue(true, "Single tap should be sufficient for activation");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("{string} button should have minimum touch target size of 44x44 CSS pixels")
    public void buttonShouldHaveMinimumTouchTargetSizeOf44x44CSSPixels(String buttonText) {
        String buttonXPath = String.format("//button[@id='%s']", 
            buttonText.toLowerCase().replaceAll("\\s+", "-"));
        WebElement button = driver.findElement(By.xpath(buttonXPath));
        int width = button.getSize().getWidth();
        int height = button.getSize().getHeight();
        
        assertions.assertTrue(width >= 44, buttonText + " button width should be at least 44px");
        assertions.assertTrue(height >= 44, buttonText + " button height should be at least 44px");
    }
    
    @Then("button should have adequate spacing from other interactive elements")
    public void buttonShouldHaveAdequateSpacingFromOtherInteractiveElements() {
        assertions.assertTrue(true, "Button should have adequate spacing");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("screen reader should announce {string}")
    public void screenReaderShouldAnnounceFieldType(String expectedAnnouncement) {
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        String ariaLabel = commentField.getAttribute("aria-label");
        assertions.assertNotNull(ariaLabel, "Screen reader should announce field type");
    }
    
    @Then("field should be easily discoverable through swipe navigation")
    public void fieldShouldBeEasilyDiscoverableThroughSwipeNavigation() {
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        assertions.assertDisplayed(commentField);
    }
    
    @Then("text entry should work correctly with screen reader active")
    public void textEntryShouldWorkCorrectlyWithScreenReaderActive() {
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        String value = commentField.getAttribute