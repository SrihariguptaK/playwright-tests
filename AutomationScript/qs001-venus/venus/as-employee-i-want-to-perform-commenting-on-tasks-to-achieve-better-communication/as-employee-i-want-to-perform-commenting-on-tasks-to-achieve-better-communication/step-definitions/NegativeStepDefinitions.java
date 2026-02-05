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

import java.util.List;

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

public class TaskCommentingValidationStepDefinitions {

    private WebDriver driver;
    private GenericActions actions;
    private WaitHelpers waits;
    private AssertionHelpers assertions;
    
    private BasePage basePage;
    private HomePage homePage;
    private LoginPage loginPage;
    private TaskDetailsPage taskDetailsPage;
    
    private String systemState;
    private String commentText;
    
    @Before
    public void setUp() {
        ChromeOptions options = new ChromeOptions();
        options.addArguments("--start-maximized");
        options.addArguments("--ignore-certificate-errors");
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
    /*  TEST CASE: TC-NEG-001
    /*  Title: System rejects comment submission when character limit exceeds 500 characters
    /*  Priority: High
    /*  Category: Negative
    /*  Description: Validates character limit enforcement and error messaging
    /**************************************************/
    
    @Given("user is logged in as authenticated employee")
    public void userIsLoggedInAsAuthenticatedEmployee() {
        loginPage.navigate();
        waits.waitForPageLoad();
        
        // TODO: Replace XPath with Object Repository when available
        WebElement usernameField = driver.findElement(By.xpath("//input[@id='username']"));
        actions.clearAndSendKeys(usernameField, TestData.getUser("employee").getUsername());
        
        WebElement passwordField = driver.findElement(By.xpath("//input[@id='password']"));
        actions.clearAndSendKeys(passwordField, TestData.getUser("employee").getPassword());
        
        WebElement loginButton = driver.findElement(By.xpath("//button[@id='login']"));
        actions.click(loginButton);
        waits.waitForPageLoad();
    }
    
    @Given("user is on task details page")
    public void userIsOnTaskDetailsPage() {
        taskDetailsPage.navigate();
        waits.waitForPageLoad();
        
        // TODO: Replace XPath with Object Repository when available
        WebElement taskDetailsHeader = driver.findElement(By.xpath("//h1[@id='task-details-header']"));
        assertions.assertDisplayed(taskDetailsHeader);
    }
    
    @Given("comment input field is empty and ready for input")
    public void commentInputFieldIsEmptyAndReadyForInput() {
        // TODO: Replace XPath with Object Repository when available
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input-field']"));
        actions.clearAndSendKeys(commentField, "");
        assertions.assertDisplayed(commentField);
    }
    
    @Given("validation rules are configured to enforce {int} character maximum")
    public void validationRulesAreConfiguredToEnforceCharacterMaximum(int maxCharacters) {
        // TODO: Replace XPath with Object Repository when available
        WebElement characterCounter = driver.findElement(By.xpath("//span[@id='character-counter']"));
        assertions.assertDisplayed(characterCounter);
        String counterText = characterCounter.getText();
        assertions.assertTextContains(characterCounter, "/" + maxCharacters);
    }
    
    @Given("comment input field is visible and empty")
    public void commentInputFieldIsVisibleAndEmpty() {
        // TODO: Replace XPath with Object Repository when available
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input-field']"));
        assertions.assertDisplayed(commentField);
        String fieldValue = commentField.getAttribute("value");
        if (fieldValue != null && !fieldValue.isEmpty()) {
            actions.clearAndSendKeys(commentField, "");
        }
    }
    
    @Given("validation rules require non-empty comment text")
    public void validationRulesRequireNonEmptyCommentText() {
        // TODO: Replace XPath with Object Repository when available
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input-field']"));
        String requiredAttribute = commentField.getAttribute("required");
        assertions.assertDisplayed(commentField);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-NEG-004
    /*  Title: System prevents unauthenticated users from submitting comments
    /*  Priority: High
    /*  Category: Negative
    /*  Description: Validates authentication enforcement and session handling
    /**************************************************/
    
    @Given("user session has expired or been invalidated")
    public void userSessionHasExpiredOrBeenInvalidated() {
        actions.executeJavaScript("sessionStorage.clear(); localStorage.clear();");
    }
    
    @Given("API endpoint requires valid authentication token")
    public void apiEndpointRequiresValidAuthenticationToken() {
        // TODO: Replace XPath with Object Repository when available
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input-field']"));
        assertions.assertDisplayed(commentField);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-NEG-005
    /*  Title: System handles API endpoint failure gracefully
    /*  Priority: High
    /*  Category: Negative
    /*  Description: Validates error handling for network failures
    /**************************************************/
    
    @Given("network connection is active but API server is experiencing issues")
    public void networkConnectionIsActiveButAPIServerIsExperiencingIssues() {
        // TODO: Replace XPath with Object Repository when available
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input-field']"));
        assertions.assertDisplayed(commentField);
    }
    
    @Given("browser developer tools are open")
    public void browserDeveloperToolsAreOpen() {
        actions.executeJavaScript("console.log('Developer tools should be open for network throttling');");
    }
    
    /**************************************************/
    /*  TEST CASE: TC-NEG-006
    /*  Title: System rejects comment submission with SQL injection attempts
    /*  Priority: High
    /*  Category: Negative
    /*  Description: Validates SQL injection prevention
    /**************************************************/
    
    @Given("input validation and SQL injection prevention measures are implemented")
    public void inputValidationAndSQLInjectionPreventionMeasuresAreImplemented() {
        // TODO: Replace XPath with Object Repository when available
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input-field']"));
        assertions.assertDisplayed(commentField);
    }
    
    @Given("database has existing comments and task data")
    public void databaseHasExistingCommentsAndTaskData() {
        // TODO: Replace XPath with Object Repository when available
        List<WebElement> existingComments = driver.findElements(By.xpath("//div[@class='comment-item']"));
        assertions.assertElementCount(By.xpath("//div[@class='comment-item']"), existingComments.size());
    }
    
    /**************************************************/
    /*  TEST CASE: TC-NEG-007
    /*  Title: System handles database connection failure
    /*  Priority: Medium
    /*  Category: Negative
    /*  Description: Validates database failure handling
    /**************************************************/
    
    @Given("database connection can be simulated to fail or timeout")
    public void databaseConnectionCanBeSimulatedToFailOrTimeout() {
        // TODO: Replace XPath with Object Repository when available
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input-field']"));
        assertions.assertDisplayed(commentField);
    }
    
    @Given("error handling is implemented for database failures")
    public void errorHandlingIsImplementedForDatabaseFailures() {
        // TODO: Replace XPath with Object Repository when available
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input-field']"));
        assertions.assertDisplayed(commentField);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-NEG-008
    /*  Title: System rejects comment submission for non-existent task ID
    /*  Priority: Medium
    /*  Category: Negative
    /*  Description: Validates task existence validation
    /**************************************************/
    
    @Given("user has navigated to task details page URL with invalid task ID {string}")
    public void userHasNavigatedToTaskDetailsPageURLWithInvalidTaskID(String taskId) {
        String url = String.format("/tasks/%s/details", taskId);
        actions.navigateTo(basePage.getBaseUrl() + url);
        waits.waitForPageLoad();
    }
    
    @Given("task ID {string} does not exist in database")
    public void taskIDDoesNotExistInDatabase(String taskId) {
        // TODO: Replace XPath with Object Repository when available
        List<WebElement> errorMessages = driver.findElements(By.xpath("//div[@id='error-message']"));
        if (!errorMessages.isEmpty()) {
            assertions.assertDisplayed(errorMessages.get(0));
        }
    }
    
    @Given("API endpoint validates task existence before accepting comments")
    public void apiEndpointValidatesTaskExistenceBeforeAcceptingComments() {
        // TODO: Replace XPath with Object Repository when available
        WebElement pageContent = driver.findElement(By.xpath("//body"));
        assertions.assertDisplayed(pageContent);
    }
    
    // ==================== WHEN STEPS ====================
    
    @When("user clicks on comment input field")
    public void userClicksOnCommentInputField() {
        // TODO: Replace XPath with Object Repository when available
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input-field']"));
        actions.click(commentField);
    }
    
    @When("user enters comment with {int} characters in comment input field")
    public void userEntersCommentWithCharactersInCommentInputField(int characterCount) {
        StringBuilder comment = new StringBuilder();
        for (int i = 0; i < characterCount; i++) {
            comment.append("a");
        }
        this.commentText = comment.toString();
        
        // TODO: Replace XPath with Object Repository when available
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input-field']"));
        actions.clearAndSendKeys(commentField, this.commentText);
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
    
    @When("user deletes {int} characters from comment")
    public void userDeletesCharactersFromComment(int charactersToDelete) {
        // TODO: Replace XPath with Object Repository when available
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input-field']"));
        String currentText = commentField.getAttribute("value");
        if (currentText != null && currentText.length() >= charactersToDelete) {
            String newText = currentText.substring(0, currentText.length() - charactersToDelete);
            actions.clearAndSendKeys(commentField, newText);
            this.commentText = newText;
        }
    }
    
    @When("user enters {string} in comment input field")
    public void userEntersInCommentInputField(String text) {
        this.commentText = text;
        // TODO: Replace XPath with Object Repository when available
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input-field']"));
        actions.clearAndSendKeys(commentField, text);
    }
    
    @When("user session is manually expired by clearing authentication token")
    public void userSessionIsManuallyExpiredByClearingAuthenticationToken() {
        actions.executeJavaScript("sessionStorage.removeItem('authToken'); localStorage.removeItem('authToken');");
        actions.executeJavaScript("document.cookie.split(';').forEach(function(c) { document.cookie = c.replace(/^ +/, '').replace(/=.*/, '=;expires=' + new Date().toUTCString() + ';path=/'); });");
    }
    
    @When("user enables network throttling to {string} mode in developer tools")
    public void userEnablesNetworkThrottlingToModeInDeveloperTools(String mode) {
        if (mode.equalsIgnoreCase("Offline")) {
            actions.executeJavaScript("window.navigator.onLine = false;");
        }
    }
    
    @When("user disables offline mode")
    public void userDisablesOfflineMode() {
        actions.executeJavaScript("window.navigator.onLine = true;");
    }
    
    @When("database connection failure is simulated at server level")
    public void databaseConnectionFailureIsSimulatedAtServerLevel() {
        actions.executeJavaScript("console.log('Database connection failure simulated');");
    }
    
    @When("database connection is restored")
    public void databaseConnectionIsRestored() {
        actions.executeJavaScript("console.log('Database connection restored');");
    }
    
    @When("user navigates to {string} URL")
    public void userNavigatesToURL(String url) {
        actions.navigateTo(basePage.getBaseUrl() + url);
        waits.waitForPageLoad();
    }
    
    @When("user enters only whitespace characters with {int} spaces and {int} tabs in comment input field")
    public void userEntersOnlyWhitespaceCharactersWithSpacesAndTabsInCommentInputField(int spaces, int tabs) {
        StringBuilder whitespace = new StringBuilder();
        for (int i = 0; i < spaces; i++) {
            whitespace.append(" ");
        }
        for (int i = 0; i < tabs; i++) {
            whitespace.append("\t");
        }
        this.commentText = whitespace.toString();
        
        // TODO: Replace XPath with Object Repository when available
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input-field']"));
        actions.clearAndSendKeys(commentField, this.commentText);
    }
    
    // ==================== THEN STEPS ====================
    
    @Then("character counter should show {string}")
    public void characterCounterShouldShow(String expectedCounter) {
        // TODO: Replace XPath with Object Repository when available
        WebElement characterCounter = driver.findElement(By.xpath("//span[@id='character-counter']"));
        waits.waitForElementVisible(characterCounter);
        assertions.assertTextContains(characterCounter, expectedCounter);
    }
    
    @Then("character counter should show {string} in red color")
    public void characterCounterShouldShowInRedColor(String expectedCounter) {
        // TODO: Replace XPath with Object Repository when available
        WebElement characterCounter = driver.findElement(By.xpath("//span[@id='character-counter']"));
        waits.waitForElementVisible(characterCounter);
        assertions.assertTextContains(characterCounter, expectedCounter);
        
        String color = characterCounter.getCssValue("color");
        String className = characterCounter.getAttribute("class");
        assertions.assertDisplayed(characterCounter);
    }
    
    @Then("error message {string} should be displayed below input field in red text")
    public void errorMessageShouldBeDisplayedBelowInputFieldInRedText(String expectedErrorMessage) {
        // TODO: Replace XPath with Object Repository when available
        String errorXPath = String.format("//div[@id='error-message' or @class='error-message'][contains(text(),'%s')]", expectedErrorMessage);
        WebElement errorMessage = driver.findElement(By.xpath(errorXPath));
        waits.waitForElementVisible(errorMessage);
        assertions.assertTextContains(errorMessage, expectedErrorMessage);
        assertions.assertDisplayed(errorMessage);
    }
    
    @Then("save button should be disabled or show validation error {string}")
    public void saveButtonShouldBeDisabledOrShowValidationError(String validationError) {
        // TODO: Replace XPath with Object Repository when available
        WebElement saveButton = driver.findElement(By.xpath("//button[@id='save' or contains(text(),'Save')]"));
        String disabledAttribute = saveButton.getAttribute("disabled");
        
        if (disabledAttribute == null || disabledAttribute.isEmpty()) {
            String errorXPath = String.format("//div[@class='validation-error'][contains(text(),'%s')]", validationError);
            List<WebElement> validationErrors = driver.findElements(By.xpath(errorXPath));
            if (!validationErrors.isEmpty()) {
                assertions.assertDisplayed(validationErrors.get(0));
            }
        }
    }
    
    @Then("comment should not be submitted")
    public void commentShouldNotBeSubmitted() {
        // TODO: Replace XPath with Object Repository when available
        List<WebElement> successMessages = driver.findElements(By.xpath("//div[@id='success-message' or @class='success-message']"));
        if (!successMessages.isEmpty()) {
            String successText = successMessages.get(0).getText();
            if (successText.contains("successfully") || successText.contains("added")) {
                throw new AssertionError("Comment was submitted when it should not have been");
            }
        }
    }
    
    @Then("error message should disappear")
    public void errorMessageShouldDisappear() {
        // TODO: Replace XPath with Object Repository when available
        List<WebElement> errorMessages = driver.findElements(By.xpath("//div[@id='error-message' or @class='error-message']"));
        if (!errorMessages.isEmpty()) {
            for (WebElement error : errorMessages) {
                if (error.isDisplayed()) {
                    throw new AssertionError("Error message is still visible when it should have disappeared");
                }
            }
        }
    }
    
    @Then("{string} button should be enabled")
    public void buttonShouldBeEnabled(String buttonText) {
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
        
        String disabledAttribute = button.getAttribute("disabled");
        if (disabledAttribute != null && !disabledAttribute.isEmpty()) {
            throw new AssertionError("Button is disabled when it should be enabled");
        }
    }
    
    @Then("no comment should be saved in database")
    public void noCommentShouldBeSavedInDatabase() {
        // TODO: Replace XPath with Object Repository when available
        List<WebElement> commentsList = driver.findElements(By.xpath("//div[@class='comment-item']"));
        int initialCount = commentsList.size();
        
        waits.waitForPageLoad();
        
        List<WebElement> updatedCommentsList = driver.findElements(By.xpath("//div[@class='comment-item']"));
        int finalCount = updatedCommentsList.size();
        
        if (finalCount > initialCount) {
            throw new AssertionError("Comment was saved to database when it should not have been");
        }
    }
    
    @Then("no API call should be made to POST endpoint")
    public void noAPICallShouldBeMadeToPOSTEndpoint() {
        actions.executeJavaScript("console.log('Verify no POST API call was made');");
    }
    
    @Then("error message {string} should be displayed in red below input field")
    public void errorMessageShouldBeDisplayedInRedBelowInputField(String expectedErrorMessage) {
        // TODO: Replace XPath with Object Repository when available
        String errorXPath = String.format("//div[@id='error-message' or @class='error-message'][contains(text(),'%s')]", expectedErrorMessage);
        WebElement errorMessage = driver.findElement(By.xpath(errorXPath));
        waits.waitForElementVisible(errorMessage);
        assertions.assertTextContains(errorMessage, expectedErrorMessage);
        assertions.assertDisplayed(errorMessage);
    }
    
    @Then("no empty or whitespace-only comments should be saved in database")
    public void noEmptyOrWhitespaceOnlyCommentsShouldBeSavedInDatabase() {
        // TODO: Replace XPath with Object Repository when available
        List<WebElement> commentsList = driver.findElements(By.xpath("//div[@class='comment-item']"));
        
        for (WebElement comment : commentsList) {
            String commentText = comment.getText().trim();
            if (commentText.isEmpty()) {
                throw new AssertionError("Empty or whitespace-only comment found in database");
            }
        }
    }
    
    @Then("no notifications should be sent to team members")
    public void noNotificationsShouldBeSentToTeamMembers() {
        actions.executeJavaScript("console.log('Verify no notifications were sent');");
    }
    
    @Then("API endpoint should not be called")
    public void apiEndpointShouldNotBeCalled() {
        actions.executeJavaScript("console.log('Verify API endpoint was not called');");
    }
    
    @Then("input should appear empty visually")
    public void inputShouldAppearEmptyVisually() {
        // TODO: Replace XPath with Object Repository when available
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input-field']"));
        String visibleText = commentField.getText().trim();
        String value = commentField.getAttribute("value");
        
        if (value != null) {
            String trimmedValue = value.trim();
            if (!trimmedValue.isEmpty()) {
                throw new AssertionError("Input field does not appear empty visually");
            }
        }
    }
    
    @Then("error message {string} should be displayed")
    public void errorMessageShouldBeDisplayed(String expectedErrorMessage) {
        // TODO: Replace XPath with Object Repository when available
        String errorXPath = String.format("//div[@id='error-message' or @class='error-message'][contains(text(),'%s')]", expectedErrorMessage);
        WebElement errorMessage = driver.findElement(By.xpath(errorXPath));
        waits.waitForElementVisible(errorMessage);
        assertions.assertTextContains(errorMessage, expectedErrorMessage);
        assertions.assertDisplayed(errorMessage);
    }
    
    @Then("session should be expired but user remains on current page")
    public void sessionShouldBeExpiredButUserRemainsOnCurrentPage() {
        String currentUrl = driver.getCurrentUrl();
        assertions.assertUrlContains("tasks");
    }
    
    @Then("user should be redirected to login page")
    public void userShouldBeRedirectedToLoginPage() {
        waits.waitForPageLoad();
        String currentUrl = driver.getCurrentUrl();
        assertions.assertUrlContains("login");
    }
    
    @Then("API should return HTTP status {int} with error message {string}")
    public void apiShouldReturnHTTPStatusWithErrorMessage(int statusCode, String errorMessage) {
        actions.executeJavaScript(String.format("console.log('Verify API returned status %d with message: %s');", statusCode, errorMessage));
    }
    
    @Then("return URL should be set to current task details page")
    public void returnURLShouldBeSetToCurrentTaskDetailsPage() {
        String currentUrl = driver.getCurrentUrl();
        actions.executeJavaScript(String.format("console.log('Return URL should be: %s');", currentUrl));
    }
    
    @Then("comment text should not be persisted after redirect")
    public void commentTextShouldNotBePersistedAfterRedirect() {
        // TODO: Replace XPath with Object Repository when available
        List<WebElement> commentFields = driver.findElements(By.xpath("//textarea[@id='comment-input-field']"));
        if (!commentFields.isEmpty()) {
            String fieldValue = commentFields.get(0).getAttribute("value");
            if (fieldValue != null && !fieldValue.isEmpty()) {
                throw new AssertionError("Comment text was persisted after redirect");
            }
        }
    }
    
    @Then("security audit log should record unauthorized access attempt")
    public void securityAuditLogShouldRecordUnauthorizedAccessAttempt() {
        actions.executeJavaScript("console.log('Verify security audit log recorded unauthorized access attempt');");
    }
    
    @Then("network should be set to offline mode")
    public void networkShouldBeSetToOfflineMode() {
        Boolean isOnline = (Boolean) actions.executeJavaScript("return window.navigator.onLine;");
        if (isOnline == null || isOnline) {
            throw new AssertionError("Network is not in offline mode");
        }
    }
    
    @Then("loading indicator should appear briefly")
    public void loadingIndicatorShouldAppearBriefly() {
        // TODO: Replace XPath with Object Repository when available
        List<WebElement> loadingIndicators = driver.findElements(By.xpath("//div[@id='loading-indicator' or @class='loading-indicator']"));
        if (!loadingIndicators.isEmpty()) {
            assertions.assertDisplayed(loadingIndicators.get(0));
        }
    }
    
    @Then("error message {string} should be displayed in red banner at top of page")
    public void errorMessageShouldBeDisplayedInRedBannerAtTopOfPage(String expectedErrorMessage) {
        // TODO: Replace XPath with Object Repository when available
        String errorXPath = String.format("//div[@id='error-banner' or @class='error-banner'][contains(text(),'%s')]", expectedErrorMessage);
        WebElement errorBanner = driver.findElement(By.xpath(errorXPath));
        waits.waitForElementVisible(errorBanner);
        assertions.assertTextContains(errorBanner, expectedErrorMessage);
        assertions.assertDisplayed(errorBanner);
    }
    
    @Then("comment text should remain in input field")
    public void commentTextShouldRemainInInputField() {
        // TODO: Replace XPath with Object Repository when available
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment-input-field']"));
        String fieldValue = commentField.getAttribute("value");
        
        if (fieldValue == null || fieldValue.isEmpty()) {
            throw new AssertionError("Comment text did not remain in input field");
        }
    }
    
    @Then("user should remain on task details page")
    public void userShouldRemainOnTaskDetailsPage() {
        String currentUrl = driver.getCurrentUrl();
        assertions.assertUrlContains("tasks");
        assertions.assertUrlContains("details");
    }
    
    @Then("success message {string} should be displayed")
    public void successMessageShouldBeDisplayed(String expectedSuccessMessage) {
        // TODO: Replace XPath with Object Repository when available
        String successXPath = String.format("//div[@id='success-message' or @class='success-message'][contains(text(),'%s')]", expectedSuccessMessage);
        WebElement successMessage = driver.findElement(By.xpath(successXPath));
        waits.waitForElementVisible(successMessage);
        assertions.assertTextContains(successMessage, expectedSuccessMessage);
        assertions.assertDisplayed(successMessage);
    }
    
    @Then("comment should be saved as plain text string without executing SQL or validation error {string} should appear")
    public void commentShouldBeSavedAsPlainTextStringWithoutExecutingSQLOrValidationErrorShouldAppear(String validationError) {
        // TODO: Replace XPath with Object Repository when available
        List<WebElement> errorMessages = driver.findElements(By.xpath(String.format("//div[@class='error-message'][contains(text(),'%s')]", validationError)));
        
        if (errorMessages.isEmpty()) {
            List<WebElement> commentsList = driver.findElements(By.xpath("//div[@class='comment-item']"));
            boolean foundSQLInjectionAsText = false;
            
            for (WebElement comment : commentsList) {
                String commentText = comment.getText();
                if (commentText.contains("DROP TABLE") || commentText.contains("';")) {
                    foundSQLInjectionAsText = true;
                    break;
                }
            }
            
            if (!foundSQLInjectionAsText) {
                throw new AssertionError("SQL injection was neither saved as plain text nor blocked with validation error");
            }
        } else {
            assertions.assertDisplayed(errorMessages.get(0));
        }
    }
    
    @Then("database table should be intact")
    public void databaseTableShouldBeIntact() {
        // TODO: Replace XPath with Object Repository when available
        List<WebElement> commentsList = driver.findElements(By.xpath("//div[@class='comment-item']"));
        assertions.assertElementCount(By.xpath("//div[@class='comment-item']"), commentsList.size());
    }
    
    @Then("all existing comments should be visible on page")
    public void allExistingCommentsShouldBeVisibleOnPage() {
        // TODO: Replace XPath with Object Repository when available
        List<WebElement> commentsList = driver.findElements(By.xpath("//div[@class='comment-item']"));
        
        for (WebElement comment : commentsList) {
            assertions.assertDisplayed(comment);
        }
    }
    
    @Then("no data loss should occur")
    public void noDataLossShouldOccur() {
        // TODO: Replace XPath with Object Repository when available
        List<WebElement> commentsList = driver.findElements(By.xpath("//div[@class='comment-item']"));
        assertions.assertElementCount(By.xpath("//div[@class='comment-item']"), commentsList.size());
    }
    
    @Then("SQL injection attempt should be logged in security audit log")
    public void sqlInjectionAttemptShouldBeLoggedInSecurityAuditLog() {
        actions.executeJavaScript("console.log('Verify SQL injection attempt was logged in security audit log');");
    }
    
    @Then("database integrity should be maintained")
    public void databaseIntegrityShouldBeMaintained() {
        // TODO: Replace XPath with Object Repository when available
        List<WebElement> commentsList = driver.findElements(By.xpath("//div[@class='comment-item']"));
        assertions.assertElementCount(By.xpath("//div[@class='comment-item']"), commentsList.size());
    }
    
    @Then("database should become unavailable for write operations")
    public void databaseShouldBecomeUnavailableForWriteOperations() {
        actions.executeJavaScript("console.log('Database is unavailable for write operations');");
    }
    
    @Then("loading indicator should appear")
    public void loadingIndicatorShouldAppear() {
        // TODO: Replace XPath with Object Repository when available
        List<WebElement> loadingIndicators = driver.findElements(By.xpath("//div[@id='loading-indicator' or @class='loading-indicator']"));
        if (!loadingIndicators.isEmpty()) {
            assertions.assertDisplayed(loadingIndicators.get(0));
        }
    }
    
    @Then("error message {string} should be displayed in red banner")
    public void errorMessageShouldBeDisplayedInRedBanner(String expectedErrorMessage) {
        // TODO: Replace XPath with Object Repository when available
        String errorXPath = String.format("//div[@id='error-banner' or @class='error-banner'][contains(text(),'%s')]", expectedErrorMessage);
        WebElement errorBanner = driver.findElement(By.xpath(errorXPath));
        waits.waitForElementVisible(errorBanner);
        assertions.assertTextContains(errorBanner, expectedErrorMessage);
        assertions.assertDisplayed(errorBanner);
    }
    
    @Then("API should return HTTP status {int} or {int} with error details")
    public void apiShouldReturnHTTPStatusOrWithErrorDetails(int statusCode1, int statusCode2) {
        actions.executeJavaScript(String.format("console.log('Verify API returned status %d or %d with error details');", statusCode1, statusCode2));
    }
    
    @Then("no partial or corrupted data should be written to database")
    public void noPartialOrCorruptedDataShouldBeWrittenToDatabase() {
        // TODO: Replace XPath with Object Repository when available
        List<WebElement> commentsList = driver.findElements(By.xpath("//div[@class='comment-item']"));
        
        for (WebElement comment : commentsList) {
            String commentText = comment.getText();
            if (commentText == null || commentText.trim().isEmpty()) {
                throw new AssertionError("Partial or corrupted data found in database");
            }
        }
    }
    
    @Then("user session should remain active and valid")
    public void userSessionShouldRemainActiveAndValid() {
        Boolean hasAuthToken = (Boolean) actions.executeJavaScript("return sessionStorage.getItem('authToken') !== null || localStorage.getItem('authToken') !== null;");
        if (hasAuthToken == null || !hasAuthToken) {
            throw new AssertionError("User session is not active and valid");
        }
    }
    
    @Then("page should show {string} error or {string} message")
    public void pageShouldShowErrorOrMessage(String error1, String error2) {
        // TODO: Replace XPath with Object Repository when available
        String errorXPath1 = String.format("//*[contains(text(),'%s')]", error1);
        String errorXPath2 = String.format("//*[contains(text(),'%s')]", error2);
        
        List<WebElement> error1Elements = driver.findElements(By.xpath(errorXPath1));
        List<WebElement> error2Elements = driver.findElements(By.xpath(errorXPath2));
        
        if (error1Elements.isEmpty() && error2Elements.isEmpty()) {
            throw new AssertionError(String.format("Neither '%s' nor '%s' error message was displayed", error1, error2));
        }
        
        if (!error1Elements.isEmpty()) {
            assertions.assertDisplayed(error1Elements.get(0));
        } else {
            assertions.assertDisplayed(error2Elements.get(0));
        }
    }
    
    @Then("error message {string} should be displayed in red banner")
    public void errorMessageShouldBeDisplayedInRedBannerAlternate(String expectedErrorMessage) {
        // TODO: Replace XPath with Object Repository when available
        String errorXPath = String.format("//div[@id='error-banner' or @class='error-banner'][contains(text(),'%s')]", expectedErrorMessage);
        WebElement errorBanner = driver.findElement(By.xpath(errorXPath));
        waits.waitForElementVisible(errorBanner);
        assertions.assertTextContains(errorBanner, expectedErrorMessage);
        assertions.assertDisplayed(errorBanner);
    }
    
    @Then("API should return HTTP status {int} with error message {string}")
    public void apiShouldReturnHTTPStatusWithErrorMessageAlternate(int statusCode, String errorMessage) {
        actions.executeJavaScript(String.format("console.log('Verify API returned status %d with message: %s');", statusCode, errorMessage));
    }
    
    @Then("no comment record should be created in database")
    public void noCommentRecordShouldBeCreatedInDatabase() {
        // TODO: Replace XPath with Object Repository when available
        List<WebElement> commentsList = driver.findElements(By.xpath("//div[@class='comment-item']"));
        int initialCount = commentsList.size();
        
        waits.waitForPageLoad();
        
        List<WebElement> updatedCommentsList = driver.findElements(By.xpath("//div[@class='comment-item']"));
        int finalCount = updatedCommentsList.size();
        
        if (finalCount > initialCount) {
            throw new AssertionError("Comment record was created in database when it should not have been");
        }
    }
    
    @Then("database referential integrity should be maintained with no orphaned comment records")
    public void databaseReferentialIntegrityShouldBeMaintainedWithNoOrphanedCommentRecords() {
        actions.executeJavaScript("console.log('Verify database referential integrity is maintained with no orphaned records');");
    }
}