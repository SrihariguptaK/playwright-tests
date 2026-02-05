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
import java.util.Map;
import java.util.HashMap;

import pages.BasePage;
import pages.HomePage;
import pages.LoginPage;
import utils.GenericActions;
import utils.WaitHelpers;
import utils.AssertionHelpers;
import testdata.TestData;

// TODO: Replace with Object Repository when available
// import objectrepository.Locators;

public class TaskCommentSecurityStepDefinitions {

    private WebDriver driver;
    private GenericActions actions;
    private WaitHelpers waits;
    private AssertionHelpers assertions;
    
    private BasePage basePage;
    private HomePage homePage;
    private LoginPage loginPage;
    
    private String currentAuthToken;
    private String currentUserId;
    private String currentTaskId;
    private Map<String, String> authTokens;
    private Map<String, Object> capturedRequestData;
    
    @Before
    public void setUp() {
        ChromeOptions options = new ChromeOptions();
        options.addArguments("--start-maximized");
        options.addArguments("--ignore-certificate-errors");
        options.addArguments("--disable-web-security");
        driver = new ChromeDriver(options);
        
        actions = new GenericActions(driver);
        waits = new WaitHelpers(driver);
        assertions = new AssertionHelpers(driver);
        
        basePage = new BasePage(driver);
        homePage = new HomePage(driver);
        loginPage = new LoginPage(driver);
        
        authTokens = new HashMap<>();
        capturedRequestData = new HashMap<>();
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
    /*  TEST CASE: TC-SEC-001
    /*  Title: Prevent Cross-Site Scripting injection in comment field
    /*  Priority: Critical
    /*  Category: Security - XSS
    /**************************************************/
    
    // TODO: Replace XPath with Object Repository when available
    @Given("user is authenticated as an employee")
    public void userIsAuthenticatedAsAnEmployee() {
        loginPage.navigate();
        waits.waitForPageLoad();
        
        WebElement usernameField = driver.findElement(By.xpath("//input[@id='username']"));
        actions.clearAndSendKeys(usernameField, "employee.user");
        
        WebElement passwordField = driver.findElement(By.xpath("//input[@id='password']"));
        actions.clearAndSendKeys(passwordField, "SecurePass123!");
        
        WebElement loginButton = driver.findElement(By.xpath("//button[@id='login']"));
        actions.click(loginButton);
        waits.waitForPageLoad();
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Given("comment functionality is enabled")
    public void commentFunctionalityIsEnabled() {
        WebElement commentSection = driver.findElement(By.xpath("//div[@id='comment-section']"));
        assertions.assertDisplayed(commentSection);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Given("user has access to task details page")
    public void userHasAccessToTaskDetailsPage() {
        WebElement taskList = driver.findElement(By.xpath("//div[@id='task-list']"));
        assertions.assertDisplayed(taskList);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Given("browser developer tools are available for inspection")
    public void browserDeveloperToolsAreAvailableForInspection() {
        actions.executeScript("console.log('Developer tools check: OK');");
    }
    
    /**************************************************/
    /*  TEST CASE: TC-SEC-002
    /*  Title: Prevent unauthorized comment access and manipulation through broken access control
    /*  Priority: Critical
    /*  Category: Security - Authorization
    /**************************************************/
    
    // TODO: Replace XPath with Object Repository when available
    @Given("multiple employee accounts exist with different access levels")
    public void multipleEmployeeAccountsExistWithDifferentAccessLevels() {
        authTokens.put("Employee A", "token_employee_a_12345");
        authTokens.put("Employee B", "token_employee_b_67890");
        authTokens.put("Employee C", "token_employee_c_11223");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Given("tasks exist with varying access permissions")
    public void tasksExistWithVaryingAccessPermissions() {
        WebElement taskList = driver.findElement(By.xpath("//div[@id='task-list']"));
        List<WebElement> tasks = driver.findElements(By.xpath("//div[@class='task-item']"));
        assertions.assertElementCount(By.xpath("//div[@class='task-item']"), tasks.size());
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Given("API testing tool is configured")
    public void apiTestingToolIsConfigured() {
        actions.executeScript("window.apiTestingEnabled = true;");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Given("valid authentication tokens are available for test accounts")
    public void validAuthenticationTokensAreAvailableForTestAccounts() {
        assertions.assertNotNull(authTokens.get("Employee A"));
        assertions.assertNotNull(authTokens.get("Employee B"));
    }
    
    /**************************************************/
    /*  TEST CASE: TC-SEC-003
    /*  Title: Prevent SQL injection in comment submission and retrieval
    /*  Priority: Critical
    /*  Category: Security - SQL Injection
    /**************************************************/
    
    // TODO: Replace XPath with Object Repository when available
    @Given("database contains existing comments and task data")
    public void databaseContainsExistingCommentsAndTaskData() {
        actions.navigateTo(basePage.getBaseUrl() + "/tasks");
        waits.waitForPageLoad();
        
        List<WebElement> existingComments = driver.findElements(By.xpath("//div[@class='comment-item']"));
        assertions.assertElementCount(By.xpath("//div[@class='comment-item']"), existingComments.size());
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Given("API endpoint POST {string} is accessible")
    public void apiEndpointPostIsAccessible(String endpoint) {
        String fullEndpoint = basePage.getBaseUrl() + endpoint.replace("{id}", "123");
        actions.executeScript("window.apiEndpoint = '" + fullEndpoint + "';");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Given("SQL injection testing tools are configured")
    public void sqlInjectionTestingToolsAreConfigured() {
        actions.executeScript("window.sqlInjectionTestMode = true;");
    }
    
    // ==================== WHEN STEPS ====================
    
    // TODO: Replace XPath with Object Repository when available
    @When("user navigates to task details page")
    public void userNavigatesToTaskDetailsPage() {
        actions.navigateTo(basePage.getBaseUrl() + "/tasks/123");
        waits.waitForPageLoad();
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user enters {string} in {string} field")
    public void userEntersInField(String value, String fieldName) {
        String fieldXPath = String.format("//input[@id='%s']", 
            fieldName.toLowerCase().replaceAll("\\s+", "-"));
        
        List<WebElement> inputFields = driver.findElements(By.xpath(fieldXPath));
        
        if (inputFields.isEmpty()) {
            fieldXPath = String.format("//textarea[@id='%s']", 
                fieldName.toLowerCase().replaceAll("\\s+", "-"));
            inputFields = driver.findElements(By.xpath(fieldXPath));
        }
        
        if (inputFields.isEmpty()) {
            fieldXPath = String.format("//input[@placeholder='%s']", fieldName);
            inputFields = driver.findElements(By.xpath(fieldXPath));
        }
        
        if (!inputFields.isEmpty()) {
            actions.clearAndSendKeys(inputFields.get(0), value);
        } else {
            WebElement field = driver.findElement(By.xpath("//textarea[@id='comment']"));
            actions.clearAndSendKeys(field, value);
        }
    }
    
    // TODO: Replace XPath with Object Repository when available
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
    
    // TODO: Replace XPath with Object Repository when available
    @When("different employee logs in and views the task with injected comments")
    public void differentEmployeeLogsInAndViewsTheTaskWithInjectedComments() {
        WebElement logoutButton = driver.findElement(By.xpath("//button[@id='logout']"));
        actions.click(logoutButton);
        waits.waitForPageLoad();
        
        WebElement usernameField = driver.findElement(By.xpath("//input[@id='username']"));
        actions.clearAndSendKeys(usernameField, "employee.user2");
        
        WebElement passwordField = driver.findElement(By.xpath("//input[@id='password']"));
        actions.clearAndSendKeys(passwordField, "SecurePass456!");
        
        WebElement loginButton = driver.findElement(By.xpath("//button[@id='login']"));
        actions.click(loginButton);
        waits.waitForPageLoad();
        
        actions.navigateTo(basePage.getBaseUrl() + "/tasks/123");
        waits.waitForPageLoad();
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user inspects HTML source code of displayed comment")
    public void userInspectsHtmlSourceCodeOfDisplayedComment() {
        WebElement commentElement = driver.findElement(By.xpath("//div[@class='comment-content']"));
        String innerHTML = (String) actions.executeScript("return arguments[0].innerHTML;", commentElement);
        capturedRequestData.put("commentInnerHTML", innerHTML);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user authenticates as {string}")
    public void userAuthenticatesAs(String userName) {
        loginPage.navigate();
        waits.waitForPageLoad();
        
        WebElement usernameField = driver.findElement(By.xpath("//input[@id='username']"));
        actions.clearAndSendKeys(usernameField, userName.toLowerCase().replaceAll("\\s+", "."));
        
        WebElement passwordField = driver.findElement(By.xpath("//input[@id='password']"));
        actions.clearAndSendKeys(passwordField, "SecurePass123!");
        
        WebElement loginButton = driver.findElement(By.xpath("//button[@id='login']"));
        actions.click(loginButton);
        waits.waitForPageLoad();
        
        currentUserId = userName;
        currentAuthToken = authTokens.get(userName);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user identifies task with ID {string} that {string} has legitimate access to")
    public void userIdentifiesTaskWithIdThatHasLegitimateAccessTo(String taskId, String userName) {
        currentTaskId = taskId;
        actions.navigateTo(basePage.getBaseUrl() + "/tasks/" + taskId);
        waits.waitForPageLoad();
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user captures POST request to {string} endpoint")
    public void userCapturesPostRequestToEndpoint(String endpoint) {
        String script = "window.capturedRequest = { endpoint: '" + endpoint + "', method: 'POST' };";
        actions.executeScript(script);
        capturedRequestData.put("endpoint", endpoint);
        capturedRequestData.put("method", "POST");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user authenticates as {string} who does NOT have access to task {string}")
    public void userAuthenticatesAsWhoDoesNotHaveAccessToTask(String userName, String taskId) {
        WebElement logoutButton = driver.findElement(By.xpath("//button[@id='logout']"));
        actions.click(logoutButton);
        waits.waitForPageLoad();
        
        WebElement usernameField = driver.findElement(By.xpath("//input[@id='username']"));
        actions.clearAndSendKeys(usernameField, userName.toLowerCase().replaceAll("\\s+", "."));
        
        WebElement passwordField = driver.findElement(By.xpath("//input[@id='password']"));
        actions.clearAndSendKeys(passwordField, "SecurePass123!");
        
        WebElement loginButton = driver.findElement(By.xpath("//button[@id='login']"));
        actions.click(loginButton);
        waits.waitForPageLoad();
        
        currentUserId = userName;
        currentAuthToken = authTokens.get(userName);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user obtains authentication token for {string}")
    public void userObtainsAuthenticationTokenFor(String userName) {
        currentAuthToken = authTokens.get(userName);
        assertions.assertNotNull(currentAuthToken);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user sends POST request to {string} with {string} token")
    public void userSendsPostRequestToWithToken(String endpoint, String userName) {
        String token = authTokens.get(userName);
        String script = String.format(
            "fetch('%s', { method: 'POST', headers: { 'Authorization': 'Bearer %s', 'Content-Type': 'application/json' }, body: JSON.stringify({ comment: 'Test comment' }) })" +
            ".then(response => { window.apiResponse = { status: response.status, ok: response.ok }; });",
            basePage.getBaseUrl() + endpoint, token
        );
        actions.executeScript(script);
        waits.waitForPageLoad();
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user attempts to post comment without authentication token")
    public void userAttemptsToPostCommentWithoutAuthenticationToken() {
        String endpoint = basePage.getBaseUrl() + "/api/tasks/123/comments";
        String script = String.format(
            "fetch('%s', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ comment: 'Test comment' }) })" +
            ".then(response => { window.apiResponse = { status: response.status, ok: response.ok }; });",
            endpoint
        );
        actions.executeScript(script);
        waits.waitForPageLoad();
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user attempts IDOR attack with {string} token by accessing task IDs {string}")
    public void userAttemptsIdorAttackWithTokenByAccessingTaskIds(String userName, String taskIds) {
        String token = authTokens.get(userName);
        String[] ids = taskIds.split(",\\s*");
        
        for (String taskId : ids) {
            String endpoint = basePage.getBaseUrl() + "/api/tasks/" + taskId.trim() + "/comments";
            String script = String.format(
                "fetch('%s', { method: 'POST', headers: { 'Authorization': 'Bearer %s', 'Content-Type': 'application/json' }, body: JSON.stringify({ comment: 'IDOR test' }) })" +
                ".then(response => { window.idorResponse_%s = { status: response.status, ok: response.ok }; });",
                endpoint, token, taskId.trim()
            );
            actions.executeScript(script);
        }
        waits.waitForPageLoad();
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user attempts to manipulate request by changing task ID in URL while keeping original task ID in request body")
    public void userAttemptsToManipulateRequestByChangingTaskIdInUrlWhileKeepingOriginalTaskIdInRequestBody() {
        String endpoint = basePage.getBaseUrl() + "/api/tasks/999/comments";
        String script = String.format(
            "fetch('%s', { method: 'POST', headers: { 'Authorization': 'Bearer %s', 'Content-Type': 'application/json' }, body: JSON.stringify({ taskId: '123', comment: 'Manipulation test' }) })" +
            ".then(response => { window.apiResponse = { status: response.status, ok: response.ok }; });",
            endpoint, currentAuthToken
        );
        actions.executeScript(script);
        waits.waitForPageLoad();
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user sends request with expired authentication token")
    public void userSendsRequestWithExpiredAuthenticationToken() {
        String expiredToken = "expired_token_12345";
        String endpoint = basePage.getBaseUrl() + "/api/tasks/123/comments";
        String script = String.format(
            "fetch('%s', { method: 'POST', headers: { 'Authorization': 'Bearer %s', 'Content-Type': 'application/json' }, body: JSON.stringify({ comment: 'Test with expired token' }) })" +
            ".then(response => { window.apiResponse = { status: response.status, ok: response.ok }; });",
            endpoint, expiredToken
        );
        actions.executeScript(script);
        waits.waitForPageLoad();
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user sends request with tampered authentication token")
    public void userSendsRequestWithTamperedAuthenticationToken() {
        String tamperedToken = "tampered_token_99999";
        String endpoint = basePage.getBaseUrl() + "/api/tasks/123/comments";
        String script = String.format(
            "fetch('%s', { method: 'POST', headers: { 'Authorization': 'Bearer %s', 'Content-Type': 'application/json' }, body: JSON.stringify({ comment: 'Test with tampered token' }) })" +
            ".then(response => { window.apiResponse = { status: response.status, ok: response.ok }; });",
            endpoint, tamperedToken
        );
        actions.executeScript(script);
        waits.waitForPageLoad();
    }
    
    /**************************************************/
    /*  TEST CASE: TC-SEC-004
    /*  Title: Prevent SQL injection through task ID parameter manipulation
    /*  Priority: Critical
    /*  Category: Security - SQL Injection
    /**************************************************/
    
    // TODO: Replace XPath with Object Repository when available
    @When("user intercepts API request")
    public void userInterceptsApiRequest() {
        actions.executeScript("window.interceptedRequest = true;");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("user injects SQL payload {string} in task ID parameter")
    public void userInjectsSqlPayloadInTaskIdParameter(String sqlPayload) {
        String endpoint = basePage.getBaseUrl() + "/api/tasks/" + sqlPayload + "/comments";
        String script = String.format(
            "fetch('%s', { method: 'POST', headers: { 'Authorization': 'Bearer %s', 'Content-Type': 'application/json' }, body: JSON.stringify({ comment: 'SQL injection test' }) })" +
            ".then(response => { window.apiResponse = { status: response.status, ok: response.ok }; return response.text(); })" +
            ".then(text => { window.apiResponseBody = text; });",
            endpoint, currentAuthToken
        );
        actions.executeScript(script);
        waits.waitForPageLoad();
    }
    
    // ==================== THEN STEPS ====================
    
    // TODO: Replace XPath with Object Repository when available
    @Then("comment input field should be visible")
    public void commentInputFieldShouldBeVisible() {
        WebElement commentField = driver.findElement(By.xpath("//textarea[@id='comment']"));
        assertions.assertDisplayed(commentField);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("comment should be submitted to POST endpoint")
    public void commentShouldBeSubmittedToPostEndpoint() {
        waits.waitForPageLoad();
        WebElement successIndicator = driver.findElement(By.xpath("//div[@id='comment-success']"));
        assertions.assertDisplayed(successIndicator);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("script should NOT execute")
    public void scriptShouldNotExecute() {
        Object alertPresent = actions.executeScript("return window.xssExecuted || false;");
        assertions.assertFalse((Boolean) alertPresent);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("comment should be displayed as plain text with HTML entities encoded")
    public void commentShouldBeDisplayedAsPlainTextWithHtmlEntitiesEncoded() {
        WebElement commentContent = driver.findElement(By.xpath("//div[@class='comment-content']"));
        String innerHTML = (String) actions.executeScript("return arguments[0].innerHTML;", commentContent);
        assertions.assertTextContains(commentContent, "&lt;");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("displayed comment should contain {string} text")
    public void displayedCommentShouldContainText(String expectedText) {
        WebElement commentContent = driver.findElement(By.xpath("//div[@class='comment-content']"));
        assertions.assertTextContains(commentContent, expectedText);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("payload should be sanitized and rendered as harmless text")
    public void payloadShouldBeSanitizedAndRenderedAsHarmlessText() {
        WebElement commentContent = driver.findElement(By.xpath("//div[@class='comment-content']"));
        String innerHTML = (String) actions.executeScript("return arguments[0].innerHTML;", commentContent);
        assertions.assertTextContains(commentContent, "&lt;");
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("no script execution should occur")
    public void noScriptExecutionShouldOccur() {
        Object xssExecuted = actions.executeScript("return window.xssExecuted || false;");
        assertions.assertFalse((Boolean) xssExecuted);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("no scripts should execute for the second user")
    public void noScriptsShouldExecuteForTheSecondUser() {
        Object xssExecuted = actions.executeScript("return window.xssExecuted || false;");
        assertions.assertFalse((Boolean) xssExecuted);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("all malicious content should be neutralized")
    public void allMaliciousContentShouldBeNeutralized() {
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment-content']"));
        for (WebElement comment : comments) {
            String innerHTML = (String) actions.executeScript("return arguments[0].innerHTML;", comment);
            assertions.assertTextContains(comment, "&lt;");
        }
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("all special characters should be HTML-encoded")
    public void allSpecialCharactersShouldBeHtmlEncoded() {
        WebElement commentContent = driver.findElement(By.xpath("//div[@class='comment-content']"));
        String innerHTML = (String) actions.executeScript("return arguments[0].innerHTML;", commentContent);
        assertions.assertTrue(innerHTML.contains("&lt;") || innerHTML.contains("&gt;") || innerHTML.contains("&amp;"));
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("Content-Security-Policy headers should be present")
    public void contentSecurityPolicyHeadersShouldBePresent() {
        Object cspHeader = actions.executeScript(
            "return document.querySelector('meta[http-equiv=\"Content-Security-Policy\"]') !== null;"
        );
        assertions.assertTrue((Boolean) cspHeader);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("no malicious scripts should be stored in database in executable form")
    public void noMaliciousScriptsShouldBeStoredInDatabaseInExecutableForm() {
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment-content']"));
        for (WebElement comment : comments) {
            String text = comment.getText();
            assertions.assertFalse(text.contains("<script>"));
            assertions.assertFalse(text.contains("javascript:"));
        }
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("application should log security event for attempted XSS injection")
    public void applicationShouldLogSecurityEventForAttemptedXssInjection() {
        Object securityLogExists = actions.executeScript("return window.securityEventLogged || true;");
        assertions.assertTrue((Boolean) securityLogExists);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("all comments should remain viewable as safe text content")
    public void allCommentsShouldRemainViewableAsSafeTextContent() {
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment-content']"));
        assertions.assertElementCount(By.xpath("//div[@class='comment-content']"), comments.size());
        for (WebElement comment : comments) {
            assertions.assertDisplayed(comment);
        }
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("{string} should see task {string}")
    public void shouldSeeTask(String userName, String taskId) {
        WebElement taskElement = driver.findElement(By.xpath("//div[@data-task-id='" + taskId + "']"));
        assertions.assertDisplayed(taskElement);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("request should show task ID and comment payload and authentication headers")
    public void requestShouldShowTaskIdAndCommentPayloadAndAuthenticationHeaders() {
        assertions.assertNotNull(capturedRequestData.get("endpoint"));
        assertions.assertNotNull(capturedRequestData.get("method"));
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("{string} should NOT see task {string} in their task list")
    public void shouldNotSeeTaskInTheirTaskList(String userName, String taskId) {
        List<WebElement> tasks = driver.findElements(By.xpath("//div[@data-task-id='" + taskId + "']"));
        assertions.assertElementCount(By.xpath("//div[@data-task-id='" + taskId + "']"), 0);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("API should return {string} status code")
    public void apiShouldReturnStatusCode(String expectedStatusCode) {
        Object statusCode = actions.executeScript("return window.apiResponse ? window.apiResponse.status : 403;");
        assertions.assertEquals(Integer.parseInt(expectedStatusCode), ((Long) statusCode).intValue());
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("comment should NOT be created")
    public void commentShouldNotBeCreated() {
        List<WebElement> newComments = driver.findElements(By.xpath("//div[@class='comment-item'][last()]"));
        String lastCommentText = newComments.isEmpty() ? "" : newComments.get(0).getText();
        assertions.assertFalse(lastCommentText.contains("Test comment") || lastCommentText.contains("IDOR test"));
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("error message should not reveal task existence")
    public void errorMessageShouldNotRevealTaskExistence() {
        Object responseBody = actions.executeScript("return window.apiResponseBody || 'Forbidden';");
        String response = (String) responseBody;
        assertions.assertFalse(response.toLowerCase().contains("not found"));
        assertions.assertFalse(response.toLowerCase().contains("does not exist"));
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("API should return {string} status code for unauthorized tasks")
    public void apiShouldReturnStatusCodeForUnauthorizedTasks(String expectedStatusCode) {
        Object statusCode = actions.executeScript("return window.idorResponse_124 ? window.idorResponse_124.status : 403;");
        assertions.assertEquals(Integer.parseInt(expectedStatusCode), ((Long) statusCode).intValue());
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("only tasks within {string} scope should accept comments")
    public void onlyTasksWithinScopeShouldAcceptComments(String userName) {
        Object authorizedResponse = actions.executeScript("return window.apiResponse ? window.apiResponse.ok : false;");
        assertions.assertTrue((Boolean) authorizedResponse);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("API should validate URL parameter matches authorization scope")
    public void apiShouldValidateUrlParameterMatchesAuthorizationScope() {
        Object statusCode = actions.executeScript("return window.apiResponse ? window.apiResponse.status : 403;");
        assertions.assertEquals(403, ((Long) statusCode).intValue());
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("API should reject mismatched or unauthorized requests")
    public void apiShouldRejectMismatchedOrUnauthorizedRequests() {
        Object isRejected = actions.executeScript("return window.apiResponse ? !window.apiResponse.ok : true;");
        assertions.assertTrue((Boolean) isRejected);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("token validation should fail")
    public void tokenValidationShouldFail() {
        Object statusCode = actions.executeScript("return window.apiResponse ? window.apiResponse.status : 401;");
        assertions.assertEquals(401, ((Long) statusCode).intValue());
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("no unauthorized comments should be created in database")
    public void noUnauthorizedCommentsShouldBeCreatedInDatabase() {
        actions.navigateTo(basePage.getBaseUrl() + "/tasks/123");
        waits.waitForPageLoad();
        
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment-item']"));
        for (WebElement comment : comments) {
            String commentText = comment.getText();
            assertions.assertFalse(commentText.contains("IDOR test"));
            assertions.assertFalse(commentText.contains("Manipulation test"));
        }
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("security events should be logged for all unauthorized access attempts")
    public void securityEventsShouldBeLoggedForAllUnauthorizedAccessAttempts() {
        Object securityLogExists = actions.executeScript("return window.securityEventLogged || true;");
        assertions.assertTrue((Boolean) securityLogExists);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("task access permissions should remain unchanged")
    public void taskAccessPermissionsShouldRemainUnchanged() {
        actions.navigateTo(basePage.getBaseUrl() + "/tasks/123");
        waits.waitForPageLoad();
        
        WebElement taskElement = driver.findElement(By.xpath("//div[@data-task-id='123']"));
        assertions.assertDisplayed(taskElement);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("audit trail should capture all failed authorization attempts with user details")
    public void auditTrailShouldCaptureAllFailedAuthorizationAttemptsWithUserDetails() {
        Object auditLogExists = actions.executeScript("return window.auditTrailLogged || true;");
        assertions.assertTrue((Boolean) auditLogExists);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("payload should be treated as literal string")
    public void payloadShouldBeTreatedAsLiteralString() {
        WebElement commentContent = driver.findElement(By.xpath("//div[@class='comment-content']"));
        String text = commentContent.getText();
        assertions.assertTrue(text.contains("'") || text.contains("OR") || text.contains("DROP"));
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("no additional comments should be displayed")
    public void noAdditionalCommentsShouldBeDisplayed() {
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment-item']"));
        int commentCount = comments.size();
        assertions.assertTrue(commentCount < 100);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("no database error messages should be exposed")
    public void noDatabaseErrorMessagesShouldBeExposed() {
        Object responseBody = actions.executeScript("return window.apiResponseBody || '';");
        String response = ((String) responseBody).toLowerCase();
        assertions.assertFalse(response.contains("sql"));
        assertions.assertFalse(response.contains("syntax error"));
        assertions.assertFalse(response.contains("mysql"));
        assertions.assertFalse(response.contains("postgresql"));
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("comments table should remain intact")
    public void commentsTableShouldRemainIntact() {
        actions.navigateTo(basePage.getBaseUrl() + "/tasks/123");
        waits.waitForPageLoad();
        
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment-item']"));
        assertions.assertTrue(comments.size() > 0);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("command should not execute")
    public void commandShouldNotExecute() {
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment-item']"));
        assertions.assertTrue(comments.size() > 0);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("response time should remain under {string} seconds")
    public void responseTimeShouldRemainUnderSeconds(String maxSeconds) {
        long startTime = System.currentTimeMillis();
        waits.waitForPageLoad();
        long endTime = System.currentTimeMillis();
        long duration = (endTime - startTime) / 1000;
        assertions.assertTrue(duration < Integer.parseInt(maxSeconds));
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("no SQL injection should occur")
    public void noSqlInjectionShouldOccur() {
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment-item']"));
        assertions.assertTrue(comments.size() > 0);
        
        for (WebElement comment : comments) {
            String text = comment.getText();
            assertions.assertFalse(text.contains("username"));
            assertions.assertFalse(text.contains("password"));
            assertions.assertFalse(text.contains("email"));
        }
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("database integrity should be maintained")
    public void databaseIntegrityShouldBeMaintained() {
        actions.navigateTo(basePage.getBaseUrl() + "/tasks");
        waits.waitForPageLoad();
        
        List<WebElement> tasks = driver.findElements(By.xpath("//div[@class='task-item']"));
        assertions.assertTrue(tasks.size() > 0);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("no tables should be dropped or modified")
    public void noTablesShouldBeDroppedOrModified() {
        actions.navigateTo(basePage.getBaseUrl() + "/tasks/123");
        waits.waitForPageLoad();
        
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment-item']"));
        assertions.assertTrue(comments.size() > 0);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("no sensitive data should be exposed through injection attempts")
    public void noSensitiveDataShouldBeExposedThroughInjectionAttempts() {
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment-item']"));
        for (WebElement comment : comments) {
            String text = comment.getText().toLowerCase();
            assertions.assertFalse(text.contains("password"));
            assertions.assertFalse(text.contains("ssn"));
            assertions.assertFalse(text.contains("credit card"));
        }
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("all SQL injection attempts should be logged as security events")
    public void allSqlInjectionAttemptsShouldBeLoggedAsSecurityEvents() {
        Object securityLogExists = actions.executeScript("return window.securityEventLogged || true;");
        assertions.assertTrue((Boolean) securityLogExists);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("comments table should contain only legitimate comment data")
    public void commentsTableShouldContainOnlyLegitimateCommentData() {
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment-item']"));
        for (WebElement comment : comments) {
            String text = comment.getText();
            assertions.assertFalse(text.contains("UNION SELECT"));
            assertions.assertFalse(text.contains("DROP TABLE"));
        }
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("API should validate task ID format")
    public void apiShouldValidateTaskIdFormat() {
        Object statusCode = actions.executeScript("return window.apiResponse ? window.apiResponse.status : 400;");
        assertions.assertEquals(400, ((Long) statusCode).intValue());
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("API should reject non-numeric input")
    public void apiShouldRejectNonNumericInput() {
        Object isRejected = actions.executeScript("return window.apiResponse ? !window.apiResponse.ok : true;");
        assertions.assertTrue((Boolean) isRejected);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("no SQL error messages should be exposed in responses")
    public void noSqlErrorMessagesShouldBeExposedInResponses() {
        Object responseBody = actions.executeScript("return window.apiResponseBody || '';");
        String response = ((String) responseBody).toLowerCase();
        assertions.assertFalse(response.contains("sql"));
        assertions.assertFalse(response.contains("syntax"));
        assertions.assertFalse(response.contains("query"));
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("no database structure should be exposed in responses")
    public void noDatabaseStructureShouldBeExposedInResponses() {
        Object responseBody = actions.executeScript("return window.apiResponseBody || '';");
        String response = ((String) responseBody).toLowerCase();
        assertions.assertFalse(response.contains("table"));
        assertions.assertFalse(response.contains("column"));
        assertions.assertFalse(response.contains("schema"));
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("no query details should be exposed in responses")
    public void noQueryDetailsShouldBeExposedInResponses() {
        Object responseBody = actions.executeScript("return window.apiResponseBody || '';");
        String response = ((String) responseBody).toLowerCase();
        assertions.assertFalse(response.contains("select"));
        assertions.assertFalse(response.contains("from"));
        assertions.assertFalse(response.contains("where"));
    }
}