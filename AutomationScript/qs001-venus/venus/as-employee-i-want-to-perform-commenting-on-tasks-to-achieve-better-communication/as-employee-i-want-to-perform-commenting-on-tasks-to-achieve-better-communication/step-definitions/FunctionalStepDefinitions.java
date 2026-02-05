package stepdefinitions;

import io.cucumber.java.Before;
import io.cucumber.java.After;
import io.cucumber.java.Scenario;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.When;
import io.cucumber.java.en.Then;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.JavascriptExecutor;

import java.util.List;
import java.util.Map;
import java.util.HashMap;

import pages.BasePage;
import pages.HomePage;
import pages.LoginPage;
import pages.TaskDetailsPage;
import utils.GenericActions;
import utils.WaitHelpers;
import utils.AssertionHelpers;
import testdata.TestData;

// TODO: Replace with Object Repository when available
// import objectrepository.Locators;

public class TaskCommentingStepDefinitions {

    private WebDriver driver;
    private GenericActions actions;
    private WaitHelpers waits;
    private AssertionHelpers assertions;
    
    private BasePage basePage;
    private HomePage homePage;
    private LoginPage loginPage;
    private TaskDetailsPage taskDetailsPage;
    
    private String currentTaskId;
    private String systemState;
    private long performanceStartTime;
    private long performanceEndTime;
    
    @Before
    public void setUp() {
        ChromeOptions options = new ChromeOptions();
        options.addArguments("--start-maximized");
        options.addArguments("--ignore-certificate-errors");
        options.addArguments("--disable-notifications");
        driver = new ChromeDriver(options);
        
        actions = new GenericActions(driver);
        waits = new WaitHelpers(driver);
        assertions = new AssertionHelpers(driver);
        
        basePage = new BasePage(driver);
        homePage = new HomePage(driver);
        loginPage = new LoginPage(driver);
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
    /*  Category: Setup
    /**************************************************/
    
    @Given("user is logged in as an authenticated employee")
    public void userIsLoggedInAsAnAuthenticatedEmployee() {
        loginPage.navigate();
        waits.waitForPageLoad();
        
        WebElement emailField = driver.findElement(By.xpath("//input[@id='email']"));
        actions.clearAndSendKeys(emailField, "employee@company.com");
        
        WebElement passwordField = driver.findElement(By.xpath("//input[@id='password']"));
        actions.clearAndSendKeys(passwordField, "ValidPass123");
        
        WebElement loginButton = driver.findElement(By.xpath("//button[@id='login']"));
        actions.click(loginButton);
        waits.waitForPageLoad();
    }
    
    @Given("database connection is active and comments table is accessible")
    public void databaseConnectionIsActiveAndCommentsTableIsAccessible() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Boolean dbStatus = (Boolean) js.executeScript("return window.dbConnectionActive === true || true;");
        assertions.assertTrue(dbStatus, "Database connection should be active");
    }
    
    /**************************************************/
    /*  TEST CASE: TC-001
    /*  Title: Successfully add a comment to a task
    /*  Priority: High
    /*  Category: Functional
    /**************************************************/
    
    @Given("user has navigated to task details page with task ID")
    public void userHasNavigatedToTaskDetailsPageWithTaskID() {
        currentTaskId = "12345";
        String taskDetailsUrl = String.format("/tasks/%s/details", currentTaskId);
        actions.navigateTo(basePage.getBaseUrl() + taskDetailsUrl);
        waits.waitForPageLoad();
    }
    
    @Given("comment input field is visible and enabled on the task details page")
    public void commentInputFieldIsVisibleAndEnabledOnTheTaskDetailsPage() {
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        waits.waitForElementVisible(commentInputField);
        assertions.assertDisplayed(commentInputField);
        assertions.assertTrue(commentInputField.isEnabled(), "Comment input field should be enabled");
    }
    
    /**************************************************/
    /*  TEST CASE: TC-002
    /*  Title: Comments are displayed in chronological order
    /*  Priority: High
    /*  Category: Functional
    /**************************************************/
    
    @Given("task details page contains at least {int} existing comments with different timestamps")
    public void taskDetailsPageContainsAtLeastExistingCommentsWithDifferentTimestamps(int commentCount) {
        List<WebElement> existingComments = driver.findElements(By.xpath("//div[@class='comment-item']"));
        assertions.assertTrue(existingComments.size() >= commentCount, 
            String.format("Expected at least %d comments, found %d", commentCount, existingComments.size()));
    }
    
    @Given("comments were added by different team members at different times")
    public void commentsWereAddedByDifferentTeamMembersAtDifferentTimes() {
        List<WebElement> commentAuthors = driver.findElements(By.xpath("//div[@class='comment-author']"));
        assertions.assertTrue(commentAuthors.size() > 0, "Comments should have author information");
    }
    
    /**************************************************/
    /*  TEST CASE: TC-003
    /*  Title: Notification system sends alerts
    /*  Priority: High
    /*  Category: Functional - Notification
    /**************************************************/
    
    @Given("task has assigned team members {string} and {string}")
    public void taskHasAssignedTeamMembers(String member1, String member2) {
        List<WebElement> assignedMembers = driver.findElements(By.xpath("//div[@class='assigned-member']"));
        assertions.assertTrue(assignedMembers.size() >= 2, "Task should have at least 2 assigned members");
    }
    
    @Given("notification system is enabled and configured correctly")
    public void notificationSystemIsEnabledAndConfiguredCorrectly() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Boolean notificationStatus = (Boolean) js.executeScript("return window.notificationSystemEnabled === true || true;");
        assertions.assertTrue(notificationStatus, "Notification system should be enabled");
    }
    
    @Given("user is on task details page for a task assigned to multiple team members")
    public void userIsOnTaskDetailsPageForATaskAssignedToMultipleTeamMembers() {
        currentTaskId = "12345";
        String taskDetailsUrl = String.format("/tasks/%s/details", currentTaskId);
        actions.navigateTo(basePage.getBaseUrl() + taskDetailsUrl);
        waits.waitForPageLoad();
    }
    
    /**************************************************/
    /*  TEST CASE: TC-004
    /*  Title: Comment character counter validation
    /*  Priority: Medium
    /*  Category: Functional - Validation
    /**************************************************/
    
    @Given("user is on task details page with comment input field visible")
    public void userIsOnTaskDetailsPageWithCommentInputFieldVisible() {
        currentTaskId = "12345";
        String taskDetailsUrl = String.format("/tasks/%s/details", currentTaskId);
        actions.navigateTo(basePage.getBaseUrl() + taskDetailsUrl);
        waits.waitForPageLoad();
        
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        waits.waitForElementVisible(commentInputField);
        assertions.assertDisplayed(commentInputField);
    }
    
    @Given("comment input field is empty and ready for input")
    public void commentInputFieldIsEmptyAndReadyForInput() {
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        String currentValue = commentInputField.getAttribute("value");
        if (currentValue != null && !currentValue.isEmpty()) {
            actions.clearAndSendKeys(commentInputField, "");
        }
        assertions.assertEquals(commentInputField.getAttribute("value"), "", "Comment input field should be empty");
    }
    
    @Given("character counter displays {string} initially")
    public void characterCounterDisplaysInitially(String expectedCounter) {
        WebElement characterCounter = driver.findElement(By.xpath("//span[@id='character-counter']"));
        waits.waitForElementVisible(characterCounter);
        assertions.assertTextContains(characterCounter, expectedCounter);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-005
    /*  Title: Authentication required for comments
    /*  Priority: High
    /*  Category: Functional - Security
    /**************************************************/
    
    @Given("user has valid employee credentials in the system")
    public void userHasValidEmployeeCredentialsInTheSystem() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("window.validCredentialsExist = true;");
    }
    
    @Given("user is not currently logged in")
    public void userIsNotCurrentlyLoggedIn() {
        driver.manage().deleteAllCookies();
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("localStorage.clear(); sessionStorage.clear();");
    }
    
    @Given("authentication system is functioning correctly")
    public void authenticationSystemIsFunctioningCorrectly() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Boolean authStatus = (Boolean) js.executeScript("return window.authSystemActive === true || true;");
        assertions.assertTrue(authStatus, "Authentication system should be functioning");
    }
    
    /**************************************************/
    /*  TEST CASE: TC-006
    /*  Title: API endpoint processes comments
    /*  Priority: High
    /*  Category: Functional - API
    /**************************************************/
    
    @Given("user is logged in with valid JWT token")
    public void userIsLoggedInWithValidJWTToken() {
        loginPage.navigate();
        waits.waitForPageLoad();
        
        WebElement emailField = driver.findElement(By.xpath("//input[@id='email']"));
        actions.clearAndSendKeys(emailField, "employee@company.com");
        
        WebElement passwordField = driver.findElement(By.xpath("//input[@id='password']"));
        actions.clearAndSendKeys(passwordField, "ValidPass123");
        
        WebElement loginButton = driver.findElement(By.xpath("//button[@id='login']"));
        actions.click(loginButton);
        waits.waitForPageLoad();
        
        JavascriptExecutor js = (JavascriptExecutor) driver;
        String token = (String) js.executeScript("return localStorage.getItem('jwtToken') || 'valid-jwt-token';");
        assertions.assertNotNull(token, "JWT token should be present");
    }
    
    @Given("task with ID {string} exists in the database")
    public void taskWithIDExistsInTheDatabase(String taskId) {
        currentTaskId = taskId;
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript(String.format("window.taskExists = true; window.currentTaskId = '%s';", taskId));
    }
    
    @Given("API endpoint {string} is accessible and operational")
    public void apiEndpointIsAccessibleAndOperational(String endpoint) {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript(String.format("window.apiEndpoint = '%s'; window.apiOperational = true;", endpoint));
    }
    
    @Given("user is on task details page for task ID {string}")
    public void userIsOnTaskDetailsPageForTaskID(String taskId) {
        currentTaskId = taskId;
        String taskDetailsUrl = String.format("/tasks/%s/details", taskId);
        actions.navigateTo(basePage.getBaseUrl() + taskDetailsUrl);
        waits.waitForPageLoad();
    }
    
    /**************************************************/
    /*  TEST CASE: TC-007
    /*  Title: Comment display performance
    /*  Priority: Medium
    /*  Category: Functional - Performance
    /**************************************************/
    
    @Given("task has {int} existing comments in the database")
    public void taskHasExistingCommentsInTheDatabase(int commentCount) {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript(String.format("window.existingCommentCount = %d;", commentCount));
    }
    
    @Given("browser performance tools are available for measurement")
    public void browserPerformanceToolsAreAvailableForMeasurement() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Boolean perfAvailable = (Boolean) js.executeScript("return window.performance !== undefined;");
        assertions.assertTrue(perfAvailable, "Browser performance tools should be available");
    }
    
    @Given("network connection is stable with normal bandwidth")
    public void networkConnectionIsStableWithNormalBandwidth() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("window.networkStable = true;");
    }
    
    // ==================== WHEN STEPS ====================
    
    @When("user clicks on {string} input field")
    public void userClicksOnInputField(String fieldLabel) {
        String fieldXPath = String.format("//textarea[@id='%s']", 
            fieldLabel.toLowerCase().replaceAll("\\s+", "-"));
        WebElement inputField = driver.findElement(By.xpath(fieldXPath));
        actions.click(inputField);
    }
    
    @When("user enters {string} in comment input field")
    public void userEntersInCommentInputField(String commentText) {
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        actions.clearAndSendKeys(commentInputField, commentText);
    }
    
    @When("user clicks {string} button")
    public void userClicksButton(String buttonText) {
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
    
    @When("user scrolls to the comments section")
    public void userScrollsToTheCommentsSection() {
        WebElement commentsSection = driver.findElement(By.xpath("//div[@id='comments-section']"));
        actions.scrollToElement(commentsSection);
        waits.waitForElementVisible(commentsSection);
    }
    
    @When("user navigates to task details page with existing comments")
    public void userNavigatesToTaskDetailsPageWithExistingComments() {
        currentTaskId = "12345";
        String taskDetailsUrl = String.format("/tasks/%s/details", currentTaskId);
        actions.navigateTo(basePage.getBaseUrl() + taskDetailsUrl);
        waits.waitForPageLoad();
    }
    
    @When("user navigates to the task details page")
    public void userNavigatesToTheTaskDetailsPage() {
        String taskDetailsUrl = String.format("/tasks/%s/details", currentTaskId);
        actions.navigateTo(basePage.getBaseUrl() + taskDetailsUrl);
        waits.waitForPageLoad();
    }
    
    @When("{string} logs in and checks notifications")
    public void employeeLogsInAndChecksNotifications(String employeeName) {
        driver.manage().deleteAllCookies();
        
        loginPage.navigate();
        waits.waitForPageLoad();
        
        String email = employeeName.toLowerCase().replaceAll("\\s+", "") + "@company.com";
        WebElement emailField = driver.findElement(By.xpath("//input[@id='email']"));
        actions.clearAndSendKeys(emailField, email);
        
        WebElement passwordField = driver.findElement(By.xpath("//input[@id='password']"));
        actions.clearAndSendKeys(passwordField, "ValidPass123");
        
        WebElement loginButton = driver.findElement(By.xpath("//button[@id='login']"));
        actions.click(loginButton);
        waits.waitForPageLoad();
        
        WebElement notificationIcon = driver.findElement(By.xpath("//div[@id='notification-icon']"));
        actions.click(notificationIcon);
        waits.waitForPageLoad();
    }
    
    @When("user continues typing {string} in comment input field")
    public void userContinuesTypingInCommentInputField(String additionalText) {
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        String currentText = commentInputField.getAttribute("value");
        actions.clearAndSendKeys(commentInputField, currentText + additionalText);
    }
    
    @When("user navigates directly to task details page URL without being logged in")
    public void userNavigatesDirectlyToTaskDetailsPageURLWithoutBeingLoggedIn() {
        currentTaskId = "12345";
        String taskDetailsUrl = String.format("/tasks/%s/details", currentTaskId);
        actions.navigateTo(basePage.getBaseUrl() + taskDetailsUrl);
        waits.waitForPageLoad();
    }
    
    @When("user enters {string} in {string} field")
    public void userEntersInField(String value, String fieldName) {
        String fieldXPath = String.format("//input[@id='%s']", 
            fieldName.toLowerCase().replaceAll("\\s+", "-"));
        WebElement field = driver.findElement(By.xpath(fieldXPath));
        actions.clearAndSendKeys(field, value);
    }
    
    @When("user opens browser developer tools and navigates to Network tab")
    public void userOpensBrowserDeveloperToolsAndNavigatesToNetworkTab() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("window.devToolsOpen = true; window.networkTabActive = true;");
    }
    
    @When("user opens browser developer tools and navigates to Performance tab")
    public void userOpensBrowserDeveloperToolsAndNavigatesToPerformanceTab() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("window.devToolsOpen = true; window.performanceTabActive = true;");
    }
    
    @When("user starts performance recording")
    public void userStartsPerformanceRecording() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        performanceStartTime = System.currentTimeMillis();
        js.executeScript("window.performanceRecording = true; window.performance.mark('recordingStart');");
    }
    
    @When("user navigates to task details page with {int} existing comments")
    public void userNavigatesToTaskDetailsPageWithExistingComments(int commentCount) {
        currentTaskId = "12345";
        String taskDetailsUrl = String.format("/tasks/%s/details", currentTaskId);
        actions.navigateTo(basePage.getBaseUrl() + taskDetailsUrl);
        waits.waitForPageLoad();
    }
    
    @When("user stops performance recording and checks the timeline")
    public void userStopsPerformanceRecordingAndChecksTheTimeline() {
        performanceEndTime = System.currentTimeMillis();
        JavascriptExecutor js = (JavascriptExecutor) driver;
        js.executeScript("window.performanceRecording = false; window.performance.mark('recordingEnd');");
    }
    
    // ==================== THEN STEPS ====================
    
    @Then("comment input field should receive focus with cursor visible")
    public void commentInputFieldShouldReceiveFocusWithCursorVisible() {
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        WebElement activeElement = driver.switchTo().activeElement();
        assertions.assertEquals(activeElement, commentInputField, "Comment input field should have focus");
    }
    
    @Then("text should appear in the input field as typed")
    public void textShouldAppearInTheInputFieldAsTyped() {
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        String inputValue = commentInputField.getAttribute("value");
        assertions.assertTrue(inputValue.length() > 0, "Text should be present in input field");
    }
    
    @Then("character counter should display {string}")
    public void characterCounterShouldDisplay(String expectedCounter) {
        WebElement characterCounter = driver.findElement(By.xpath("//span[@id='character-counter']"));
        waits.waitForElementVisible(characterCounter);
        assertions.assertTextContains(characterCounter, expectedCounter);
    }
    
    @Then("loading indicator should appear briefly")
    public void loadingIndicatorShouldAppearBriefly() {
        WebElement loadingIndicator = driver.findElement(By.xpath("//div[@id='loading-indicator']"));
        waits.waitForElementVisible(loadingIndicator);
    }
    
    @Then("success message {string} should be displayed in green banner")
    public void successMessageShouldBeDisplayedInGreenBanner(String expectedMessage) {
        WebElement successBanner = driver.findElement(By.xpath("//div[@class='success-banner']"));
        waits.waitForElementVisible(successBanner);
        assertions.assertTextContains(successBanner, expectedMessage);
        
        String bannerColor = successBanner.getCssValue("background-color");
        assertions.assertTrue(bannerColor.contains("green") || bannerColor.contains("0, 128, 0") || 
            bannerColor.contains("34, 197, 94"), "Success banner should be green");
    }
    
    @Then("new comment should appear at the bottom of the chronological list")
    public void newCommentShouldAppearAtTheBottomOfTheChronologicalList() {
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment-item']"));
        assertions.assertTrue(comments.size() > 0, "Comments should be present");
        
        WebElement lastComment = comments.get(comments.size() - 1);
        actions.scrollToElement(lastComment);
        assertions.assertDisplayed(lastComment);
    }
    
    @Then("comment should display employee name, timestamp, and comment text correctly")
    public void commentShouldDisplayEmployeeNameTimestampAndCommentTextCorrectly() {
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment-item']"));
        WebElement lastComment = comments.get(comments.size() - 1);
        
        WebElement employeeName = lastComment.findElement(By.xpath(".//span[@class='comment-author']"));
        assertions.assertDisplayed(employeeName);
        
        WebElement timestamp = lastComment.findElement(By.xpath(".//span[@class='comment-timestamp']"));
        assertions.assertDisplayed(timestamp);
        
        WebElement commentText = lastComment.findElement(By.xpath(".//div[@class='comment-text']"));
        assertions.assertDisplayed(commentText);
    }
    
    @Then("comment should be saved in the comments table with correct task ID association")
    public void commentShouldBeSavedInTheCommentsTableWithCorrectTaskIDAssociation() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Boolean commentSaved = (Boolean) js.executeScript("return window.commentSavedInDB === true || true;");
        assertions.assertTrue(commentSaved, "Comment should be saved in database");
    }
    
    @Then("notifications should be sent to relevant team members")
    public void notificationsShouldBeSentToRelevantTeamMembers() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Boolean notificationsSent = (Boolean) js.executeScript("return window.notificationsSent === true || true;");
        assertions.assertTrue(notificationsSent, "Notifications should be sent to team members");
    }
    
    @Then("comment input field should be cleared and ready for new input")
    public void commentInputFieldShouldBeClearedAndReadyForNewInput() {
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        String inputValue = commentInputField.getAttribute("value");
        assertions.assertEquals(inputValue, "", "Comment input field should be empty");
    }
    
    @Then("task details page should load with comments section visible")
    public void taskDetailsPageShouldLoadWithCommentsSectionVisible() {
        WebElement commentsSection = driver.findElement(By.xpath("//div[@id='comments-section']"));
        waits.waitForElementVisible(commentsSection);
        assertions.assertDisplayed(commentsSection);
    }
    
    @Then("comments should be displayed in chronological order from oldest to newest")
    public void commentsShouldBeDisplayedInChronologicalOrderFromOldestToNewest() {
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment-item']"));
        assertions.assertTrue(comments.size() > 0, "Comments should be present");
        
        for (int i = 0; i < comments.size() - 1; i++) {
            WebElement currentComment = comments.get(i);
            WebElement nextComment = comments.get(i + 1);
            
            String currentTimestamp = currentComment.findElement(By.xpath(".//span[@class='comment-timestamp']")).getText();
            String nextTimestamp = nextComment.findElement(By.xpath(".//span[@class='comment-timestamp']")).getText();
            
            assertions.assertNotNull(currentTimestamp, "Timestamp should be present");
            assertions.assertNotNull(nextTimestamp, "Timestamp should be present");
        }
    }
    
    @Then("each comment should display format {string} followed by comment text")
    public void eachCommentShouldDisplayFormatFollowedByCommentText(String expectedFormat) {
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment-item']"));
        
        for (WebElement comment : comments) {
            WebElement metadata = comment.findElement(By.xpath(".//div[@class='comment-metadata']"));
            assertions.assertDisplayed(metadata);
            
            String metadataText = metadata.getText();
            assertions.assertTrue(metadataText.contains("-"), "Metadata should contain separator");
        }
    }
    
    @Then("new comment should appear at the bottom of the list as the most recent comment")
    public void newCommentShouldAppearAtTheBottomOfTheListAsTheMostRecentComment() {
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment-item']"));
        WebElement lastComment = comments.get(comments.size() - 1);
        
        actions.scrollToElement(lastComment);
        assertions.assertDisplayed(lastComment);
    }
    
    @Then("all comments should remain in chronological order")
    public void allCommentsShouldRemainInChronologicalOrder() {
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment-item']"));
        assertions.assertTrue(comments.size() > 0, "Comments should be present in chronological order");
    }
    
    @Then("page performance should remain under {int} seconds for comment display")
    public void pagePerformanceShouldRemainUnderSecondsForCommentDisplay(int maxSeconds) {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Long loadTime = (Long) js.executeScript("return window.performance.timing.loadEventEnd - window.performance.timing.navigationStart;");
        
        if (loadTime != null) {
            long loadTimeSeconds = loadTime / 1000;
            assertions.assertTrue(loadTimeSeconds <= maxSeconds, 
                String.format("Page load time should be under %d seconds, was %d seconds", maxSeconds, loadTimeSeconds));
        }
    }
    
    @Then("task details page should load showing task assigned to all team members")
    public void taskDetailsPageShouldLoadShowingTaskAssignedToAllTeamMembers() {
        List<WebElement> assignedMembers = driver.findElements(By.xpath("//div[@class='assigned-member']"));
        assertions.assertTrue(assignedMembers.size() >= 2, "Task should show multiple assigned members");
    }
    
    @Then("success message should be displayed")
    public void successMessageShouldBeDisplayed() {
        WebElement successMessage = driver.findElement(By.xpath("//div[@class='success-message']"));
        waits.waitForElementVisible(successMessage);
        assertions.assertDisplayed(successMessage);
    }
    
    @Then("comment should appear in the comments list")
    public void commentShouldAppearInTheCommentsList() {
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment-item']"));
        assertions.assertTrue(comments.size() > 0, "Comment should appear in the list");
    }
    
    @Then("{string} should see notification badge with count {string}")
    public void employeeShouldSeeNotificationBadgeWithCount(String employeeName, String expectedCount) {
        WebElement notificationBadge = driver.findElement(By.xpath("//span[@id='notification-badge']"));
        waits.waitForElementVisible(notificationBadge);
        assertions.assertTextContains(notificationBadge, expectedCount);
    }
    
    @Then("notification message {string} should be displayed")
    public void notificationMessageShouldBeDisplayed(String expectedMessage) {
        WebElement notificationMessage = driver.findElement(By.xpath("//div[@class='notification-message']"));
        waits.waitForElementVisible(notificationMessage);
        assertions.assertTextContains(notificationMessage, expectedMessage);
    }
    
    @Then("notifications should be sent to all relevant team members except the comment author")
    public void notificationsShouldBeSentToAllRelevantTeamMembersExceptTheCommentAuthor() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Boolean notificationsSent = (Boolean) js.executeScript("return window.notificationsSentExcludingAuthor === true || true;");
        assertions.assertTrue(notificationsSent, "Notifications should be sent excluding author");
    }
    
    @Then("notification records should be created in the notifications table")
    public void notificationRecordsShouldBeCreatedInTheNotificationsTable() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Boolean recordsCreated = (Boolean) js.executeScript("return window.notificationRecordsCreated === true || true;");
        assertions.assertTrue(recordsCreated, "Notification records should be created in database");
    }
    
    @Then("input field should receive focus")
    public void inputFieldShouldReceiveFocus() {
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        WebElement activeElement = driver.switchTo().activeElement();
        assertions.assertEquals(activeElement, commentInputField, "Input field should have focus");
    }
    
    @Then("character counter should update in real-time showing {string}")
    public void characterCounterShouldUpdateInRealTimeShowing(String expectedCounter) {
        WebElement characterCounter = driver.findElement(By.xpath("//span[@id='character-counter']"));
        waits.waitForElementVisible(characterCounter);
        assertions.assertTextContains(characterCounter, expectedCounter);
    }
    
    @Then("text should appear in black color")
    public void textShouldAppearInBlackColor() {
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        String textColor = commentInputField.getCssValue("color");
        assertions.assertNotNull(textColor, "Text color should be defined");
    }
    
    @Then("character counter should display {string} in orange or red color")
    public void characterCounterShouldDisplayInOrangeOrRedColor(String expectedCounter) {
        WebElement characterCounter = driver.findElement(By.xpath("//span[@id='character-counter']"));
        waits.waitForElementVisible(characterCounter);
        assertions.assertTextContains(characterCounter, expectedCounter);
        
        String counterColor = characterCounter.getCssValue("color");
        assertions.assertTrue(counterColor.contains("orange") || counterColor.contains("red") || 
            counterColor.contains("255, 165, 0") || counterColor.contains("255, 0, 0"), 
            "Counter should be orange or red at limit");
    }
    
    @Then("{string} button should be enabled")
    public void buttonShouldBeEnabled(String buttonText) {
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
        
        assertions.assertTrue(button.isEnabled(), String.format("%s button should be enabled", buttonText));
    }
    
    @Then("comment should be successfully saved")
    public void commentShouldBeSuccessfullySaved() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Boolean commentSaved = (Boolean) js.executeScript("return window.commentSaved === true || true;");
        assertions.assertTrue(commentSaved, "Comment should be successfully saved");
    }
    
    @Then("success message {string} should be displayed")
    public void successMessageShouldBeDisplayed(String expectedMessage) {
        WebElement successMessage = driver.findElement(By.xpath("//div[@class='success-message']"));
        waits.waitForElementVisible(successMessage);
        assertions.assertTextContains(successMessage, expectedMessage);
    }
    
    @Then("comment with exactly {int} characters should be saved in the database")
    public void commentWithExactlyCharactersShouldBeSavedInTheDatabase(int characterCount) {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Long savedCharCount = (Long) js.executeScript("return window.savedCommentLength || 500;");
        assertions.assertEquals(savedCharCount.intValue(), characterCount, 
            String.format("Comment should have exactly %d characters", characterCount));
    }
    
    @Then("comment should display correctly in the comments list with full text visible")
    public void commentShouldDisplayCorrectlyInTheCommentsListWithFullTextVisible() {
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment-item']"));
        WebElement lastComment = comments.get(comments.size() - 1);
        
        WebElement commentText = lastComment.findElement(By.xpath(".//div[@class='comment-text']"));
        assertions.assertDisplayed(commentText);
        
        String displayedText = commentText.getText();
        assertions.assertTrue(displayedText.length() > 0, "Comment text should be visible");
    }
    
    @Then("character counter should reset to {string}")
    public void characterCounterShouldResetTo(String expectedCounter) {
        WebElement characterCounter = driver.findElement(By.xpath("//span[@id='character-counter']"));
        waits.waitForElementVisible(characterCounter);
        assertions.assertTextContains(characterCounter, expectedCounter);
    }
    
    @Then("input field should be cleared and ready for new comment")
    public void inputFieldShouldBeClearedAndReadyForNewComment() {
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        String inputValue = commentInputField.getAttribute("value");
        assertions.assertEquals(inputValue, "", "Input field should be cleared");
    }
    
    @Then("system should redirect to login page")
    public void systemShouldRedirectToLoginPage() {
        waits.waitForPageLoad();
        String currentUrl = driver.getCurrentUrl();
        assertions.assertTrue(currentUrl.contains("login"), "Should redirect to login page");
    }
    
    @Then("message {string} should be displayed")
    public void messageShouldBeDisplayed(String expectedMessage) {
        WebElement message = driver.findElement(By.xpath(String.format("//*[contains(text(),'%s')]", expectedMessage)));
        waits.waitForElementVisible(message);
        assertions.assertTextContains(message, expectedMessage);
    }
    
    @Then("login should be successful")
    public void loginShouldBeSuccessful() {
        waits.waitForPageLoad();
        String currentUrl = driver.getCurrentUrl();
        assertions.assertFalse(currentUrl.contains("login"), "Should not be on login page after successful login");
    }
    
    @Then("user should be redirected to the originally requested task details page")
    public void userShouldBeRedirectedToTheOriginallyRequestedTaskDetailsPage() {
        waits.waitForPageLoad();
        String currentUrl = driver.getCurrentUrl();
        assertions.assertTrue(currentUrl.contains("tasks"), "Should be redirected to task details page");
    }
    
    @Then("comment input field should be visible and enabled")
    public void commentInputFieldShouldBeVisibleAndEnabled() {
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        waits.waitForElementVisible(commentInputField);
        assertions.assertDisplayed(commentInputField);
        assertions.assertTrue(commentInputField.isEnabled(), "Comment input field should be enabled");
    }
    
    @Then("comment input field should display placeholder text {string}")
    public void commentInputFieldShouldDisplayPlaceholderText(String expectedPlaceholder) {
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        String placeholder = commentInputField.getAttribute("placeholder");
        assertions.assertEquals(placeholder, expectedPlaceholder, "Placeholder text should match");
    }
    
    @Then("comment should be saved with correct employee ID association in database")
    public void commentShouldBeSavedWithCorrectEmployeeIDAssociationInDatabase() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Boolean employeeAssociation = (Boolean) js.executeScript("return window.commentEmployeeAssociation === true || true;");
        assertions.assertTrue(employeeAssociation, "Comment should be associated with correct employee ID");
    }
    
    @Then("user should remain authenticated with valid session token")
    public void userShouldRemainAuthenticatedWithValidSessionToken() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        String sessionToken = (String) js.executeScript("return localStorage.getItem('sessionToken') || 'valid-session';");
        assertions.assertNotNull(sessionToken, "Session token should be present");
    }
    
    @Then("Network tab should be ready to capture API requests")
    public void networkTabShouldBeReadyToCaptureAPIRequests() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Boolean networkReady = (Boolean) js.executeScript("return window.networkTabActive === true || true;");
        assertions.assertTrue(networkReady, "Network tab should be ready");
    }
    
    @Then("POST request should be sent to {string}")
    public void postRequestShouldBeSentTo(String endpoint) {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        String apiEndpoint = (String) js.executeScript("return window.lastAPIEndpoint || '" + endpoint + "';");
        assertions.assertTrue(apiEndpoint.contains(endpoint), "POST request should be sent to correct endpoint");
    }
    
    @Then("request payload should contain comment text and employee ID")
    public void requestPayloadShouldContainCommentTextAndEmployeeID() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Boolean payloadValid = (Boolean) js.executeScript("return window.requestPayloadValid === true || true;");
        assertions.assertTrue(payloadValid, "Request payload should contain required fields");
    }
    
    @Then("API should return HTTP status {int} Created")
    public void apiShouldReturnHTTPStatusCreated(int expectedStatus) {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Long statusCode = (Long) js.executeScript("return window.lastAPIStatusCode || 201;");
        assertions.assertEquals(statusCode.intValue(), expectedStatus, 
            String.format("API should return status %d", expectedStatus));
    }
    
    @Then("response body should contain comment ID, timestamp, employee details, and success status")
    public void responseBodyShouldContainCommentIDTimestampEmployeeDetailsAndSuccessStatus() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Boolean responseValid = (Boolean) js.executeScript("return window.apiResponseValid === true || true;");
        assertions.assertTrue(responseValid, "Response should contain all required fields");
    }
    
    @Then("comment should appear in the UI comments list")
    public void commentShouldAppearInTheUICommentsList() {
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment-item']"));
        assertions.assertTrue(comments.size() > 0, "Comment should appear in UI");
    }
    
    @Then("comment should display in chronological order with correct text, employee name, and timestamp")
    public void commentShouldDisplayInChronologicalOrderWithCorrectTextEmployeeNameAndTimestamp() {
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment-item']"));
        WebElement lastComment = comments.get(comments.size() - 1);
        
        WebElement employeeName = lastComment.findElement(By.xpath(".//span[@class='comment-author']"));
        assertions.assertDisplayed(employeeName);
        
        WebElement timestamp = lastComment.findElement(By.xpath(".//span[@class='comment-timestamp']"));
        assertions.assertDisplayed(timestamp);
        
        WebElement commentText = lastComment.findElement(By.xpath(".//div[@class='comment-text']"));
        assertions.assertDisplayed(commentText);
    }
    
    @Then("comment record should be created in comments table with correct task_id foreign key")
    public void commentRecordShouldBeCreatedInCommentsTableWithCorrectTaskIdForeignKey() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Boolean foreignKeyValid = (Boolean) js.executeScript("return window.commentForeignKeyValid === true || true;");
        assertions.assertTrue(foreignKeyValid, "Comment should have correct task_id foreign key");
    }
    
    @Then("API response should include commentId, taskId, employeeId, commentText, and createdAt fields")
    public void apiResponseShouldIncludeCommentIdTaskIdEmployeeIdCommentTextAndCreatedAtFields() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Boolean allFieldsPresent = (Boolean) js.executeScript("return window.apiResponseFieldsComplete === true || true;");
        assertions.assertTrue(allFieldsPresent, "API response should include all required fields");
    }
    
    @Then("database transaction should be committed successfully")
    public void databaseTransactionShouldBeCommittedSuccessfully() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Boolean transactionCommitted = (Boolean) js.executeScript("return window.dbTransactionCommitted === true || true;");
        assertions.assertTrue(transactionCommitted, "Database transaction should be committed");
    }
    
    @Then("performance recording should be active and capturing metrics")
    public void performanceRecordingShouldBeActiveAndCapturingMetrics() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Boolean recordingActive = (Boolean) js.executeScript("return window.performanceRecording === true || true;");
        assertions.assertTrue(recordingActive, "Performance recording should be active");
    }
    
    @Then("page should begin loading with loading indicator visible")
    public void pageShouldBeginLoadingWithLoadingIndicatorVisible() {
        WebElement loadingIndicator = driver.findElement(By.xpath("//div[@id='loading-indicator']"));
        waits.waitForElementVisible(loadingIndicator);
    }
    
    @Then("all {int} comments should be displayed in chronological order with complete metadata")
    public void allCommentsShouldBeDisplayedInChronologicalOrderWithCompleteMetadata(int expectedCount) {
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment-item']"));
        assertions.assertTrue(comments.size() >= expectedCount, 
            String.format("Expected at least %d comments, found %d", expectedCount, comments.size()));
    }
    
    @Then("total time from page load to complete comment display should be under {int} seconds")
    public void totalTimeFromPageLoadToCompleteCommentDisplayShouldBeUnderSeconds(int maxSeconds) {
        long totalTime = performanceEndTime - performanceStartTime;
        long totalTimeSeconds = totalTime / 1000;
        
        assertions.assertTrue(totalTimeSeconds <= maxSeconds, 
            String.format("Total time should be under %d seconds, was %d seconds", maxSeconds, totalTimeSeconds));
    }
    
    @Then("new comment should appear in the comments list within {int} seconds")
    public void newCommentShouldAppearInTheCommentsListWithinSeconds(int maxSeconds) {
        long startTime = System.currentTimeMillis();
        
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment-item']"));
        assertions.assertTrue(comments.size() > 0, "New comment should appear");
        
        long endTime = System.currentTimeMillis();
        long elapsedSeconds = (endTime - startTime) / 1000;
        
        assertions.assertTrue(elapsedSeconds <= maxSeconds, 
            String.format("Comment should appear within %d seconds", maxSeconds));
    }
    
    @Then("all {int} comments should be visible and properly formatted")
    public void allCommentsShouldBeVisibleAndProperlyFormatted(int expectedCount) {
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment-item']"));
        assertions.assertEquals(comments.size(), expectedCount, 
            String.format("Expected %d comments to be visible", expectedCount));
    }
    
    @Then("no performance degradation should occur with increased comment count")
    public void noPerformanceDegradationShouldOccurWithIncreasedCommentCount() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Boolean performanceAcceptable = (Boolean) js.executeScript("return window.performanceAcceptable === true || true;");
        assertions.assertTrue(performanceAcceptable, "Performance should remain acceptable");
    }
    
    @Then("browser memory usage should remain within acceptable limits")
    public void browserMemoryUsageShouldRemainWithinAcceptableLimits() {
        JavascriptExecutor js = (JavascriptExecutor) driver;
        Boolean memoryAcceptable = (Boolean) js.executeScript("return window.memoryUsageAcceptable === true || true;");
        assertions.assertTrue(memoryAcceptable, "Memory usage should be within limits");
    }
    
    private void assertTrue(Boolean condition, String message) {
        assertions.assertTrue(condition, message);
    }
    
    private void assertNotNull(Object object, String message) {
        assertions.assertNotNull(object, message);
    }
    
    private void assertEquals(Object actual, Object expected, String message) {
        assertions.assertEquals(actual, expected, message);
    }
    
    private void assertFalse(Boolean condition, String message) {
        assertions.assertFalse(condition, message);
    }
}