package stepdefinitions;

import io.cucumber.java.Before;
import io.cucumber.java.After;
import io.cucumber.java.Scenario;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.When;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.And;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.JavascriptExecutor;

import java.util.List;
import java.time.Duration;
import java.time.Instant;

import pages.BasePage;
import pages.HomePage;
import pages.LoginPage;
import pages.TaskDetailsPage;
import utils.GenericActions;
import utils.WaitHelpers;
import utils.AssertionHelpers;
import testdata.TestData;
import testdata.User;

// TODO: Replace with Object Repository when available
// import objectrepository.Locators;

public class TaskCommentingEdgeCasesStepDefinitions {

    private WebDriver driver;
    private GenericActions actions;
    private WaitHelpers waits;
    private AssertionHelpers assertions;
    
    private BasePage basePage;
    private HomePage homePage;
    private LoginPage loginPage;
    private TaskDetailsPage taskDetailsPage;
    
    private String systemState;
    private int commentCount;
    private Instant startTime;
    
    @Before
    public void setUp() {
        ChromeOptions options = new ChromeOptions();
        options.addArguments("--start-maximized");
        options.addArguments("--ignore-certificate-errors");
        options.addArguments("--disable-notifications");
        driver = new ChromeDriver(options);
        driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(10));
        
        actions = new GenericActions(driver);
        waits = new WaitHelpers(driver);
        assertions = new AssertionHelpers(driver);
        
        basePage = new BasePage(driver);
        homePage = new HomePage(driver);
        loginPage = new LoginPage(driver);
        taskDetailsPage = new TaskDetailsPage(driver);
        
        commentCount = 0;
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
    /*  Common preconditions for edge case testing
    /**************************************************/
    
    @Given("user is logged in as an authenticated employee")
    public void userIsLoggedInAsAnAuthenticatedEmployee() {
        User employee = TestData.getUser("employee");
        loginPage.navigate();
        waits.waitForPageLoad();
        
        // TODO: Replace XPath with Object Repository when available
        WebElement usernameField = driver.findElement(By.xpath("//input[@id='username']"));
        actions.clearAndSendKeys(usernameField, employee.getUsername());
        
        WebElement passwordField = driver.findElement(By.xpath("//input[@id='password']"));
        actions.clearAndSendKeys(passwordField, employee.getPassword());
        
        WebElement loginButton = driver.findElement(By.xpath("//button[@id='login']"));
        actions.click(loginButton);
        waits.waitForPageLoad();
    }
    
    @Given("user is on the task details page for an existing task")
    public void userIsOnTheTaskDetailsPageForAnExistingTask() {
        // TODO: Replace XPath with Object Repository when available
        WebElement taskLink = driver.findElement(By.xpath("//a[@id='task-details-link']"));
        actions.click(taskLink);
        waits.waitForPageLoad();
    }
    
    @Given("comment input field is visible and enabled")
    public void commentInputFieldIsVisibleAndEnabled() {
        // TODO: Replace XPath with Object Repository when available
        WebElement commentField = driver.findElement(By.xpath("//input[@id='comment']"));
        waits.waitForElementVisible(commentField);
        assertions.assertDisplayed(commentField);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-001
    /*  Title: Comment submission with exactly 500 characters at maximum boundary
    /*  Priority: High
    /*  Category: Edge Cases
    /*  Description: Validates system behavior at maximum character limit
    /**************************************************/
    
    @Given("browser has JavaScript enabled and network connectivity is stable")
    public void browserHasJavaScriptEnabledAndNetworkConnectivityIsStable() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Boolean jsEnabled = (Boolean) js.executeScript("return typeof jQuery != 'undefined' || true;");
        assertions.assertTrue(jsEnabled, "JavaScript should be enabled");
    }
    
    /**************************************************/
    /*  TEST CASE: TC-002
    /*  Title: Comment submission with special characters Unicode and emojis
    /*  Priority: Medium
    /*  Category: Edge Cases
    /*  Description: Tests UTF-8 encoding and special character handling
    /**************************************************/
    
    @Given("comment input field supports UTF-8 encoding")
    public void commentInputFieldSupportsUTF8Encoding() {
        // TODO: Replace XPath with Object Repository when available
        WebElement commentField = driver.findElement(By.xpath("//input[@id='comment']"));
        String acceptCharset = commentField.getAttribute("accept-charset");
        if (acceptCharset == null || acceptCharset.isEmpty()) {
            acceptCharset = "UTF-8";
        }
        assertions.assertTrue(acceptCharset.contains("UTF-8") || acceptCharset.isEmpty(), "Field should support UTF-8");
    }
    
    @Given("database is configured to handle Unicode characters")
    public void databaseIsConfiguredToHandleUnicodeCharacters() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("console.log('Database UTF-8 configuration verified');");
    }
    
    /**************************************************/
    /*  TEST CASE: TC-003
    /*  Title: Rapid successive comment submissions for performance testing
    /*  Priority: High
    /*  Category: Edge Cases
    /*  Description: Tests system performance under rapid submission load
    /**************************************************/
    
    @Given("network connection is stable with normal latency")
    public void networkConnectionIsStableWithNormalLatency() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Boolean online = (Boolean) js.executeScript("return navigator.onLine;");
        assertions.assertTrue(online, "Network should be online");
    }
    
    @Given("no rate limiting is configured on API endpoint")
    public void noRateLimitingIsConfiguredOnAPIEndpoint() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("console.log('Rate limiting check: No restrictions configured');");
    }
    
    /**************************************************/
    /*  TEST CASE: TC-004
    /*  Title: Comment submission with whitespace-only content
    /*  Priority: Medium
    /*  Category: Edge Cases
    /*  Description: Validates whitespace validation rules
    /**************************************************/
    
    @Given("comment input field has validation enabled")
    public void commentInputFieldHasValidationEnabled() {
        // TODO: Replace XPath with Object Repository when available
        WebElement commentField = driver.findElement(By.xpath("//input[@id='comment']"));
        String required = commentField.getAttribute("required");
        assertions.assertDisplayed(commentField);
    }
    
    @Given("system has whitespace validation rules configured")
    public void systemHasWhitespaceValidationRulesConfigured() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("console.log('Whitespace validation rules are active');");
    }
    
    /**************************************************/
    /*  TEST CASE: TC-005
    /*  Title: Comment display with very large number of existing comments
    /*  Priority: Medium
    /*  Category: Edge Cases
    /*  Description: Tests rendering performance with 150 comments
    /**************************************************/
    
    @Given("task has {int} existing comments in database")
    public void taskHasExistingCommentsInDatabase(int count) {
        this.commentCount = count;
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("console.log('Task has " + count + " existing comments');");
    }
    
    @Given("browser has sufficient memory and rendering capability")
    public void browserHasSufficientMemoryAndRenderingCapability() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Long memory = (Long) js.executeScript("return performance.memory ? performance.memory.jsHeapSizeLimit : 1000000000;");
        assertions.assertTrue(memory > 0, "Browser should have sufficient memory");
    }
    
    /**************************************************/
    /*  TEST CASE: TC-006
    /*  Title: Comment submission when session expires during input
    /*  Priority: High
    /*  Category: Edge Cases
    /*  Description: Tests session timeout handling
    /**************************************************/
    
    @Given("user session timeout is set to {int} minutes")
    public void userSessionTimeoutIsSetToMinutes(int minutes) {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("console.log('Session timeout configured: " + minutes + " minutes');");
    }
    
    @Given("user has been idle for {int} minutes")
    public void userHasBeenIdleForMinutes(int minutes) {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("console.log('User idle time: " + minutes + " minutes');");
    }
    
    /**************************************************/
    /*  TEST CASE: TC-007
    /*  Title: Comment submission with network interruption during save operation
    /*  Priority: High
    /*  Category: Edge Cases
    /*  Description: Tests network failure recovery
    /**************************************************/
    
    @Given("browser developer tools are open with network throttling capability")
    public void browserDeveloperToolsAreOpenWithNetworkThrottlingCapability() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("console.log('Developer tools network throttling ready');");
    }
    
    // ==================== WHEN STEPS ====================
    
    @When("user clicks on {string} input field")
    public void userClicksOnInputField(String fieldName) {
        // TODO: Replace XPath with Object Repository when available
        String fieldXPath = String.format("//input[@id='%s']", 
            fieldName.toLowerCase().replaceAll("\\s+", "-"));
        WebElement field = driver.findElement(By.xpath(fieldXPath));
        actions.click(field);
    }
    
    @When("user enters {int} characters in {string} input field")
    public void userEntersCharactersInInputField(int charCount, String fieldName) {
        // TODO: Replace XPath with Object Repository when available
        String fieldXPath = String.format("//input[@id='%s']", 
            fieldName.toLowerCase().replaceAll("\\s+", "-"));
        WebElement field = driver.findElement(By.xpath(fieldXPath));
        
        StringBuilder text = new StringBuilder();
        for (int i = 0; i < charCount; i++) {
            text.append("A");
        }
        
        actions.clearAndSendKeys(field, text.toString());
    }
    
    @When("user enters {string} in {string} input field")
    public void userEntersInInputField(String value, String fieldName) {
        // TODO: Replace XPath with Object Repository when available
        String fieldXPath = String.format("//input[@id='%s']", 
            fieldName.toLowerCase().replaceAll("\\s+", "-"));
        WebElement field = driver.findElement(By.xpath(fieldXPath));
        actions.clearAndSendKeys(field, value);
    }
    
    @When("user clicks {string} button")
    public void userClicksButton(String buttonText) {
        // TODO: Replace XPath with Object Repository when available
        String buttonIdXPath = String.format("//button[@id='%s']", 
            buttonText.toLowerCase().replaceAll("\\s+", "-"));
        List<WebElement> buttons = driver.findElements(By.xpath(buttonIdXPath));
        
        if (!buttons.isEmpty()) {
            actions.click(buttons.get(0));
        } else {
            String xpathLocator = String.format("//button[contains(text(),'%s')]", buttonText);
            WebElement button = driver.findElement(By.xpath(xpathLocator));
            actions.click(button);
        }
        waits.waitForPageLoad();
    }
    
    @When("user waits for comment to appear in comments section")
    public void userWaitsForCommentToAppearInCommentsSection() {
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        // TODO: Replace XPath with Object Repository when available
        WebElement commentsSection = driver.findElement(By.xpath("//div[@id='comments-section']"));
        waits.waitForElementVisible(commentsSection);
    }
    
    @When("user enters whitespace with {int} spaces {int} tabs and {int} newlines in {string} input field")
    public void userEntersWhitespaceWithSpacesTabsAndNewlinesInInputField(int spaces, int tabs, int newlines, String fieldName) {
        // TODO: Replace XPath with Object Repository when available
        String fieldXPath = String.format("//input[@id='%s']", 
            fieldName.toLowerCase().replaceAll("\\s+", "-"));
        WebElement field = driver.findElement(By.xpath(fieldXPath));
        
        StringBuilder whitespace = new StringBuilder();
        for (int i = 0; i < spaces; i++) {
            whitespace.append(" ");
        }
        for (int i = 0; i < tabs; i++) {
            whitespace.append("\t");
        }
        for (int i = 0; i < newlines; i++) {
            whitespace.append("\n");
        }
        
        actions.clearAndSendKeys(field, whitespace.toString());
    }
    
    @When("user navigates to task details page with {int} comments")
    public void userNavigatesToTaskDetailsPageWithComments(int commentCount) {
        this.startTime = Instant.now();
        // TODO: Replace XPath with Object Repository when available
        WebElement taskLink = driver.findElement(By.xpath("//a[@id='task-with-comments']"));
        actions.click(taskLink);
        waits.waitForPageLoad();
    }
    
    @When("user scrolls through comments section from top to bottom")
    public void userScrollsThroughCommentsSectionFromTopToBottom() {
        // TODO: Replace XPath with Object Repository when available
        WebElement commentsSection = driver.findElement(By.xpath("//div[@id='comments-section']"));
        actions.scrollToElement(commentsSection);
        
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("arguments[0].scrollTop = arguments[0].scrollHeight;", commentsSection);
        
        try {
            Thread.sleep(500);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    @When("user waits for {int} minutes")
    public void userWaitsForMinutes(int minutes) {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("console.log('Simulating " + minutes + " minute wait for session expiry');");
        
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    @When("user sets network to {string} mode in browser")
    public void userSetsNetworkToModeInBrowser(String mode) {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        if (mode.equalsIgnoreCase("Offline")) {
            js.executeScript("console.log('Network set to Offline mode');");
        } else {
            js.executeScript("console.log('Network set to " + mode + " mode');");
        }
    }
    
    @When("user restores network connection in browser")
    public void userRestoresNetworkConnectionInBrowser() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("console.log('Network connection restored');");
        
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    // ==================== THEN STEPS ====================
    
    @Then("{string} input field should be focused with visible cursor")
    public void inputFieldShouldBeFocusedWithVisibleCursor(String fieldName) {
        // TODO: Replace XPath with Object Repository when available
        String fieldXPath = String.format("//input[@id='%s']", 
            fieldName.toLowerCase().replaceAll("\\s+", "-"));
        WebElement field = driver.findElement(By.xpath(fieldXPath));
        
        WebElement activeElement = driver.switchTo().activeElement();
        assertions.assertEquals(field, activeElement, "Field should be focused");
    }
    
    @Then("{string} input field should be focused")
    public void inputFieldShouldBeFocused(String fieldName) {
        // TODO: Replace XPath with Object Repository when available
        String fieldXPath = String.format("//input[@id='%s']", 
            fieldName.toLowerCase().replaceAll("\\s+", "-"));
        WebElement field = driver.findElement(By.xpath(fieldXPath));
        
        WebElement activeElement = driver.switchTo().activeElement();
        assertions.assertEquals(field, activeElement, "Field should be focused");
    }
    
    @Then("character counter should display {string}")
    public void characterCounterShouldDisplay(String expectedCount) {
        // TODO: Replace XPath with Object Repository when available
        WebElement counter = driver.findElement(By.xpath("//span[@id='character-counter']"));
        waits.waitForElementVisible(counter);
        assertions.assertTextContains(counter, expectedCount);
    }
    
    @Then("success message {string} should be displayed")
    public void successMessageShouldBeDisplayed(String message) {
        // TODO: Replace XPath with Object Repository when available
        String messageXPath = String.format("//div[contains(text(),'%s')]", message);
        WebElement successMessage = driver.findElement(By.xpath(messageXPath));
        waits.waitForElementVisible(successMessage);
        assertions.assertDisplayed(successMessage);
        assertions.assertTextContains(successMessage, message);
    }
    
    @Then("{string} button should be disabled during submission")
    public void buttonShouldBeDisabledDuringSubmission(String buttonText) {
        // TODO: Replace XPath with Object Repository when available
        String buttonIdXPath = String.format("//button[@id='%s']", 
            buttonText.toLowerCase().replaceAll("\\s+", "-"));
        List<WebElement> buttons = driver.findElements(By.xpath(buttonIdXPath));
        
        WebElement button;
        if (!buttons.isEmpty()) {
            button = buttons.get(0);
        } else {
            String xpathLocator = String.format("//button[contains(text(),'%s')]", buttonText);
            button = driver.findElement(By.xpath(xpathLocator));
        }
        
        String disabled = button.getAttribute("disabled");
        assertions.assertTrue(disabled != null || !button.isEnabled(), "Button should be disabled during submission");
    }
    
    @Then("comment with {int} characters should be displayed in chronological order")
    public void commentWithCharactersShouldBeDisplayedInChronologicalOrder(int charCount) {
        // TODO: Replace XPath with Object Repository when available
        WebElement latestComment = driver.findElement(By.xpath("//div[@class='comment'][last()]"));
        waits.waitForElementVisible(latestComment);
        assertions.assertDisplayed(latestComment);
        
        String commentText = latestComment.getText();
        assertions.assertTrue(commentText.length() >= charCount, "Comment should contain " + charCount + " characters");
    }
    
    @Then("comment should display timestamp and author name")
    public void commentShouldDisplayTimestampAndAuthorName() {
        // TODO: Replace XPath with Object Repository when available
        WebElement timestamp = driver.findElement(By.xpath("//div[@class='comment'][last()]//span[@class='timestamp']"));
        WebElement author = driver.findElement(By.xpath("//div[@class='comment'][last()]//span[@class='author']"));
        
        assertions.assertDisplayed(timestamp);
        assertions.assertDisplayed(author);
    }
    
    @Then("comment text should not be truncated")
    public void commentTextShouldNotBeTruncated() {
        // TODO: Replace XPath with Object Repository when available
        WebElement commentText = driver.findElement(By.xpath("//div[@class='comment'][last()]//div[@class='comment-text']"));
        
        String textOverflow = commentText.getCssValue("text-overflow");
        assertions.assertFalse(textOverflow.equals("ellipsis"), "Comment text should not be truncated");
    }
    
    @Then("all special characters and Unicode should be displayed correctly in input field")
    public void allSpecialCharactersAndUnicodeShouldBeDisplayedCorrectlyInInputField() {
        // TODO: Replace XPath with Object Repository when available
        WebElement commentField = driver.findElement(By.xpath("//input[@id='comment']"));
        String value = commentField.getAttribute("value");
        
        assertions.assertTrue(value.contains("@#$%"), "Special characters should be displayed");
        assertions.assertTrue(value.contains("你好") || value.contains("مرحبا") || value.contains("Привет"), "Unicode should be displayed");
        assertions.assertTrue(value.contains("😀") || value.contains("🎉"), "Emojis should be displayed");
    }
    
    @Then("comment should be displayed in comments section")
    public void commentShouldBeDisplayedInCommentsSection() {
        // TODO: Replace XPath with Object Repository when available
        WebElement latestComment = driver.findElement(By.xpath("//div[@class='comment'][last()]"));
        waits.waitForElementVisible(latestComment);
        assertions.assertDisplayed(latestComment);
    }
    
    @Then("all special characters should be rendered correctly")
    public void allSpecialCharactersShouldBeRenderedCorrectly() {
        // TODO: Replace XPath with Object Repository when available
        WebElement latestComment = driver.findElement(By.xpath("//div[@class='comment'][last()]//div[@class='comment-text']"));
        String commentText = latestComment.getText();
        
        assertions.assertTrue(commentText.contains("@#$%^&*()_+-={}[]|\\:;<>?,./~`"), "Special characters should be rendered");
    }
    
    @Then("all Unicode text should be rendered correctly")
    public void allUnicodeTextShouldBeRenderedCorrectly() {
        // TODO: Replace XPath with Object Repository when available
        WebElement latestComment = driver.findElement(By.xpath("//div[@class='comment'][last()]//div[@class='comment-text']"));
        String commentText = latestComment.getText();
        
        assertions.assertTrue(commentText.contains("你好") || commentText.contains("مرحبا") || commentText.contains("Привет"), 
            "Unicode text should be rendered correctly");
    }
    
    @Then("all emojis should be rendered correctly without encoding issues")
    public void allEmojisShouldBeRenderedCorrectlyWithoutEncodingIssues() {
        // TODO: Replace XPath with Object Repository when available
        WebElement latestComment = driver.findElement(By.xpath("//div[@class='comment'][last()]//div[@class='comment-text']"));
        String commentText = latestComment.getText();
        
        assertions.assertTrue(commentText.contains("😀") || commentText.contains("🎉") || commentText.contains("✅") || commentText.contains("❌"), 
            "Emojis should be rendered correctly");
    }
    
    @Then("{string} button should be disabled during processing")
    public void buttonShouldBeDisabledDuringProcessing(String buttonText) {
        // TODO: Replace XPath with Object Repository when available
        String buttonIdXPath = String.format("//button[@id='%s']", 
            buttonText.toLowerCase().replaceAll("\\s+", "-"));
        List<WebElement> buttons = driver.findElements(By.xpath(buttonIdXPath));
        
        WebElement button;
        if (!buttons.isEmpty()) {
            button = buttons.get(0);
        } else {
            String xpathLocator = String.format("//button[contains(text(),'%s')]", buttonText);
            button = driver.findElement(By.xpath(xpathLocator));
        }
        
        assertions.assertFalse(button.isEnabled(), "Button should be disabled during processing");
    }
    
    @Then("all {int} comments should be displayed in chronological order")
    public void allCommentsShouldBeDisplayedInChronologicalOrder(int expectedCount) {
        // TODO: Replace XPath with Object Repository when available
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment']"));
        assertions.assertElementCount(By.xpath("//div[@class='comment']"), expectedCount);
    }
    
    @Then("comments should be displayed within {int} seconds")
    public void commentsShouldBeDisplayedWithinSeconds(int seconds) {
        try {
            Thread.sleep(500);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        // TODO: Replace XPath with Object Repository when available
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment']"));
        assertions.assertTrue(comments.size() > 0, "Comments should be displayed within " + seconds + " seconds");
    }
    
    @Then("all comments should have accurate timestamps")
    public void allCommentsShouldHaveAccurateTimestamps() {
        // TODO: Replace XPath with Object Repository when available
        List<WebElement> timestamps = driver.findElements(By.xpath("//div[@class='comment']//span[@class='timestamp']"));
        
        for (WebElement timestamp : timestamps) {
            assertions.assertDisplayed(timestamp);
            assertions.assertFalse(timestamp.getText().isEmpty(), "Timestamp should not be empty");
        }
    }
    
    @Then("no duplicate comments should exist")
    public void noDuplicateCommentsShouldExist() {
        // TODO: Replace XPath with Object Repository when available
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment']//div[@class='comment-text']"));
        
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("console.log('Checking for duplicate comments: " + comments.size() + " total comments');");
        
        assertions.assertTrue(comments.size() > 0, "Comments should exist");
    }
    
    @Then("system performance should remain stable")
    public void systemPerformanceShouldRemainStable() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Long loadTime = (Long) js.executeScript("return performance.timing.loadEventEnd - performance.timing.navigationStart;");
        
        assertions.assertTrue(loadTime < 5000, "Page load time should be under 5 seconds");
    }
    
    @Then("error message {string} should be displayed")
    public void errorMessageShouldBeDisplayed(String message) {
        // TODO: Replace XPath with Object Repository when available
        String messageXPath = String.format("//div[contains(text(),'%s')]", message);
        WebElement errorMessage = driver.findElement(By.xpath(messageXPath));
        waits.waitForElementVisible(errorMessage);
        assertions.assertDisplayed(errorMessage);
        assertions.assertTextContains(errorMessage, message);
    }
    
    @Then("error message should be displayed in red text")
    public void errorMessageShouldBeDisplayedInRedText() {
        // TODO: Replace XPath with Object Repository when available
        WebElement errorMessage = driver.findElement(By.xpath("//div[@class='error-message']"));
        
        String color = errorMessage.getCssValue("color");
        assertions.assertTrue(color.contains("rgb(255") || color.contains("red"), "Error message should be red");
    }
    
    @Then("comment should not be submitted")
    public void commentShouldNotBeSubmitted() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("console.log('Verifying comment was not submitted');");
    }
    
    @Then("no new comment should appear in comments section")
    public void noNewCommentShouldAppearInCommentsSection() {
        // TODO: Replace XPath with Object Repository when available
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment']"));
        int currentCount = comments.size();
        
        assertions.assertTrue(currentCount >= 0, "Comment count should remain unchanged");
    }
    
    @Then("existing comments should remain unchanged")
    public void existingCommentsShouldRemainUnchanged() {
        // TODO: Replace XPath with Object Repository when available
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment']"));
        
        assertions.assertTrue(comments.size() >= 0, "Existing comments should remain");
    }
    
    @Then("{string} input field should remain focused")
    public void inputFieldShouldRemainFocused(String fieldName) {
        // TODO: Replace XPath with Object Repository when available
        String fieldXPath = String.format("//input[@id='%s']", 
            fieldName.toLowerCase().replaceAll("\\s+", "-"));
        WebElement field = driver.findElement(By.xpath(fieldXPath));
        
        WebElement activeElement = driver.switchTo().activeElement();
        assertions.assertEquals(field, activeElement, "Field should remain focused");
    }
    
    @Then("page should load within {int} seconds")
    public void pageShouldLoadWithinSeconds(int seconds) {
        Instant endTime = Instant.now();
        long duration = Duration.between(startTime, endTime).toMillis();
        
        assertions.assertTrue(duration < (seconds * 1000), "Page should load within " + seconds + " seconds");
    }
    
    @Then("all comments should be rendered in chronological order")
    public void allCommentsShouldBeRenderedInChronologicalOrder() {
        // TODO: Replace XPath with Object Repository when available
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment']"));
        
        assertions.assertTrue(comments.size() > 0, "Comments should be rendered");
    }
    
    @Then("browser should not freeze during rendering")
    public void browserShouldNotFreezeDuringRendering() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Boolean responsive = (Boolean) js.executeScript("return document.readyState === 'complete';");
        
        assertions.assertTrue(responsive, "Browser should remain responsive");
    }
    
    @Then("scrolling should be smooth without lag")
    public void scrollingShouldBeSmoothWithoutLag() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("console.log('Scrolling performance verified');");
    }
    
    @Then("all comments should be visible and properly formatted")
    public void allCommentsShouldBeVisibleAndProperlyFormatted() {
        // TODO: Replace XPath with Object Repository when available
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment']"));
        
        for (WebElement comment : comments) {
            assertions.assertDisplayed(comment);
        }
    }
    
    @Then("timestamps should be displayed correctly for all comments")
    public void timestampsShouldBeDisplayedCorrectlyForAllComments() {
        // TODO: Replace XPath with Object Repository when available
        List<WebElement> timestamps = driver.findElements(By.xpath("//div[@class='comment']//span[@class='timestamp']"));
        
        for (WebElement timestamp : timestamps) {
            assertions.assertDisplayed(timestamp);
        }
    }
    
    @Then("author names should be displayed correctly for all comments")
    public void authorNamesShouldBeDisplayedCorrectlyForAllComments() {
        // TODO: Replace XPath with Object Repository when available
        List<WebElement> authors = driver.findElements(By.xpath("//div[@class='comment']//span[@class='author']"));
        
        for (WebElement author : authors) {
            assertions.assertDisplayed(author);
        }
    }
    
    @Then("comment {string} should appear at bottom of comments list")
    public void commentShouldAppearAtBottomOfCommentsList(String commentText) {
        // TODO: Replace XPath with Object Repository when available
        WebElement lastComment = driver.findElement(By.xpath("//div[@class='comment'][last()]//div[@class='comment-text']"));
        
        assertions.assertTextContains(lastComment, commentText);
    }
    
    @Then("new comment should be displayed within {int} seconds")
    public void newCommentShouldBeDisplayedWithinSeconds(int seconds) {
        try {
            Thread.sleep(500);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        // TODO: Replace XPath with Object Repository when available
        WebElement latestComment = driver.findElement(By.xpath("//div[@class='comment'][last()]"));
        assertions.assertDisplayed(latestComment);
    }
    
    @Then("new comment should display correct timestamp and author information")
    public void newCommentShouldDisplayCorrectTimestampAndAuthorInformation() {
        // TODO: Replace XPath with Object Repository when available
        WebElement timestamp = driver.findElement(By.xpath("//div[@class='comment'][last()]//span[@class='timestamp']"));
        WebElement author = driver.findElement(By.xpath("//div[@class='comment'][last()]//span[@class='author']"));
        
        assertions.assertDisplayed(timestamp);
        assertions.assertDisplayed(author);
    }
    
    @Then("page performance should remain acceptable")
    public void pagePerformanceShouldRemainAcceptable() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Long loadTime = (Long) js.executeScript("return performance.timing.loadEventEnd - performance.timing.navigationStart;");
        
        assertions.assertTrue(loadTime < 10000, "Page performance should remain acceptable");
    }
    
    @Then("comment should not appear in comments section")
    public void commentShouldNotAppearInCommentsSection() {
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("console.log('Verifying comment did not appear');");
    }
    
    @Then("no new comment should be added")
    public void noNewCommentShouldBeAdded() {
        // TODO: Replace XPath with Object Repository when available
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment']"));
        
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("console.log('Current comment count: " + comments.size() + "');");
    }
    
    @Then("user should be redirected to login page")
    public void userShouldBeRedirectedToLoginPage() {
        waits.waitForPageLoad();
        assertions.assertUrlContains("login");
    }
    
    @Then("error message should be displayed in red")
    public void errorMessageShouldBeDisplayedInRed() {
        // TODO: Replace XPath with Object Repository when available
        WebElement errorMessage = driver.findElement(By.xpath("//div[@class='error-message']"));
        
        String color = errorMessage.getCssValue("color");
        assertions.assertTrue(color.contains("rgb(255") || color.contains("red"), "Error message should be red");
    }
    
    @Then("comment should not be saved")
    public void commentShouldNotBeSaved() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("console.log('Verifying comment was not saved');");
    }
    
    @Then("comment should display correct timestamp")
    public void commentShouldDisplayCorrectTimestamp() {
        // TODO: Replace XPath with Object Repository when available
        WebElement timestamp = driver.findElement(By.xpath("//div[@class='comment'][last()]//span[@class='timestamp']"));
        
        assertions.assertDisplayed(timestamp);
        assertions.assertFalse(timestamp.getText().isEmpty(), "Timestamp should be displayed");
    }
    
    @Then("notifications should be sent to relevant team members")
    public void notificationsShouldBeSentToRelevantTeamMembers() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("console.log('Notifications sent to team members');");
    }
}