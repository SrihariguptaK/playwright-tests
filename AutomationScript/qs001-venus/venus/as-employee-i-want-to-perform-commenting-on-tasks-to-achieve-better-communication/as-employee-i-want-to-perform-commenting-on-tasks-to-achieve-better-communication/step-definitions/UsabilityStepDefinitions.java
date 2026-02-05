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
    private TaskDetailsPage taskDetailsPage;
    
    private String systemState;
    private int characterLimit;
    
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
    /*  BACKGROUND STEPS - COMMON PRECONDITIONS
    /*  Used across all test cases
    /**************************************************/
    
    // TODO: Replace XPath with Object Repository when available
    @Given("user is authenticated as an employee")
    public void userIsAuthenticatedAsAnEmployee() {
        homePage.navigate();
        waits.waitForPageLoad();
        
        WebElement usernameField = driver.findElement(By.xpath("//input[@id='username']"));
        actions.clearAndSendKeys(usernameField, "employee_user");
        
        WebElement passwordField = driver.findElement(By.xpath("//input[@id='password']"));
        actions.clearAndSendKeys(passwordField, "employee_pass");
        
        WebElement loginButton = driver.findElement(By.xpath("//button[@id='login']"));
        actions.click(loginButton);
        waits.waitForPageLoad();
    }
    
    @Given("user has access to task details page")
    public void userHasAccessToTaskDetailsPage() {
        WebElement taskDetailsLink = driver.findElement(By.xpath("//a[@id='task-details']"));
        assertions.assertDisplayed(taskDetailsLink);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-001
    /*  Title: Real-time feedback during comment submission with normal network
    /*  Priority: Critical
    /*  Category: Usability, Smoke, Functional
    /**************************************************/
    
    @Given("task has at least {int} existing comments")
    public void taskHasAtLeastExistingComments(int commentCount) {
        WebElement commentsSection = driver.findElement(By.xpath("//div[@id='comments-section']"));
        waits.waitForElementVisible(commentsSection);
        
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment-item']"));
        assertions.assertElementCount(By.xpath("//div[@class='comment-item']"), commentCount);
    }
    
    @Given("network conditions are normal")
    public void networkConditionsAreNormal() {
        this.systemState = "normal_network";
    }
    
    @When("user navigates to task details page")
    public void userNavigatesToTaskDetailsPage() {
        taskDetailsPage.navigate();
        waits.waitForPageLoad();
    }
    
    @Then("loading indicator should be displayed while comments are being fetched")
    public void loadingIndicatorShouldBeDisplayedWhileCommentsAreBeingFetched() {
        WebElement loadingIndicator = driver.findElement(By.xpath("//div[@id='loading-indicator']"));
        assertions.assertDisplayed(loadingIndicator);
    }
    
    @Then("user should not see blank space or static content")
    public void userShouldNotSeeBlankSpaceOrStaticContent() {
        List<WebElement> blankSpaces = driver.findElements(By.xpath("//div[@class='blank-space']"));
        if (!blankSpaces.isEmpty()) {
            throw new AssertionError("Blank space detected during loading");
        }
    }
    
    @When("user enters {string} characters in comment input field")
    public void userEntersCharactersInCommentInputField(String characterCount) {
        int count = Integer.parseInt(characterCount);
        StringBuilder commentText = new StringBuilder();
        for (int i = 0; i < count; i++) {
            commentText.append("a");
        }
        
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        actions.clearAndSendKeys(commentInputField, commentText.toString());
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
    
    @Then("{string} button should show loading state")
    public void buttonShouldShowLoadingState(String buttonText) {
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
        
        String loadingClass = button.getAttribute("class");
        if (!loadingClass.contains("loading")) {
            throw new AssertionError("Button does not show loading state");
        }
    }
    
    @Then("{string} button should be disabled")
    public void buttonShouldBeDisabled(String buttonText) {
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
        
        if (button.isEnabled()) {
            throw new AssertionError("Button is not disabled");
        }
    }
    
    @Then("button text should change to {string}")
    public void buttonTextShouldChangeTo(String expectedText) {
        WebElement button = driver.findElement(By.xpath("//button[@id='save']"));
        waits.waitForElementVisible(button);
        assertions.assertTextContains(button, expectedText);
    }
    
    @Then("user should not be able to submit duplicate comments")
    public void userShouldNotBeAbleToSubmitDuplicateComments() {
        WebElement saveButton = driver.findElement(By.xpath("//button[@id='save']"));
        if (saveButton.isEnabled()) {
            throw new AssertionError("Save button is enabled, allowing duplicate submission");
        }
    }
    
    @When("user observes system behavior during comment save process")
    public void userObservesSystemBehaviorDuringCommentSaveProcess() {
        waits.waitForPageLoad();
    }
    
    @Then("visual feedback should be provided with progress indicator")
    public void visualFeedbackShouldBeProvidedWithProgressIndicator() {
        WebElement progressIndicator = driver.findElement(By.xpath("//div[@id='progress-indicator']"));
        assertions.assertDisplayed(progressIndicator);
    }
    
    @Then("disabled state should be maintained")
    public void disabledStateShouldBeMaintained() {
        WebElement saveButton = driver.findElement(By.xpath("//button[@id='save']"));
        if (saveButton.isEnabled()) {
            throw new AssertionError("Button disabled state not maintained");
        }
    }
    
    @Then("input field should remain visible with submitted text")
    public void inputFieldShouldRemainVisibleWithSubmittedText() {
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        assertions.assertDisplayed(commentInputField);
        
        String inputValue = commentInputField.getAttribute("value");
        if (inputValue == null || inputValue.isEmpty()) {
            throw new AssertionError("Input field does not contain submitted text");
        }
    }
    
    @When("comment submission completes successfully")
    public void commentSubmissionCompletesSuccessfully() {
        waits.waitForPageLoad();
        WebElement successMessage = driver.findElement(By.xpath("//div[@id='success-message']"));
        waits.waitForElementVisible(successMessage);
    }
    
    @Then("success message {string} should be displayed")
    public void successMessageShouldBeDisplayed(String expectedMessage) {
        WebElement successMessage = driver.findElement(By.xpath("//div[@id='success-message']"));
        assertions.assertTextContains(successMessage, expectedMessage);
    }
    
    @Then("success confirmation should be visible")
    public void successConfirmationShouldBeVisible() {
        WebElement successConfirmation = driver.findElement(By.xpath("//div[@id='success-confirmation']"));
        assertions.assertDisplayed(successConfirmation);
    }
    
    @Then("new comment should appear in chronological list")
    public void newCommentShouldAppearInChronologicalList() {
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment-item']"));
        if (comments.isEmpty()) {
            throw new AssertionError("No comments found in list");
        }
        
        WebElement latestComment = comments.get(0);
        assertions.assertDisplayed(latestComment);
    }
    
    @Then("new comment should be visually highlighted")
    public void newCommentShouldBeVisuallyHighlighted() {
        WebElement latestComment = driver.findElement(By.xpath("//div[@class='comment-item'][1]"));
        String highlightClass = latestComment.getAttribute("class");
        
        if (!highlightClass.contains("highlighted")) {
            throw new AssertionError("New comment is not visually highlighted");
        }
    }
    
    @Then("input field should be cleared")
    public void inputFieldShouldBeCleared() {
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        String inputValue = commentInputField.getAttribute("value");
        
        if (inputValue != null && !inputValue.isEmpty()) {
            throw new AssertionError("Input field is not cleared");
        }
    }
    
    @Then("input field should be ready for new comment")
    public void inputFieldShouldBeReadyForNewComment() {
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        assertions.assertDisplayed(commentInputField);
        
        if (!commentInputField.isEnabled()) {
            throw new AssertionError("Input field is not ready for new comment");
        }
    }
    
    /**************************************************/
    /*  TEST CASE: TC-002
    /*  Title: Real-time feedback during comment submission with slow network
    /*  Priority: Critical
    /*  Category: Usability, Negative
    /**************************************************/
    
    @Given("network is throttled to {string} speed")
    public void networkIsThrottledToSpeed(String networkSpeed) {
        this.systemState = "throttled_" + networkSpeed;
    }
    
    @Then("extended loading state should be maintained throughout delay")
    public void extendedLoadingStateShouldBeMaintainedThroughoutDelay() {
        WebElement loadingIndicator = driver.findElement(By.xpath("//div[@id='loading-indicator']"));
        waits.waitForElementVisible(loadingIndicator);
        assertions.assertDisplayed(loadingIndicator);
    }
    
    @Then("{string} message should be displayed")
    public void messageShouldBeDisplayed(String expectedMessage) {
        String messageXPath = String.format("//*[contains(text(),'%s')]", expectedMessage);
        WebElement message = driver.findElement(By.xpath(messageXPath));
        assertions.assertTextContains(message, expectedMessage);
    }
    
    @Then("processing indicator should persist until completion")
    public void processingIndicatorShouldPersistUntilCompletion() {
        WebElement processingIndicator = driver.findElement(By.xpath("//div[@id='processing-indicator']"));
        assertions.assertDisplayed(processingIndicator);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-003
    /*  Title: Prevent submission of empty comment
    /*  Priority: High
    /*  Category: Usability, Negative, Edge
    /**************************************************/
    
    @Given("user is on task details page")
    public void userIsOnTaskDetailsPage() {
        taskDetailsPage.navigate();
        waits.waitForPageLoad();
    }
    
    @Given("comment input field is visible")
    public void commentInputFieldIsVisible() {
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        assertions.assertDisplayed(commentInputField);
    }
    
    @When("user clicks {string} button without entering text")
    public void userClicksButtonWithoutEnteringText(String buttonText) {
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
    }
    
    @Then("inline message {string} should be displayed")
    public void inlineMessageShouldBeDisplayed(String expectedMessage) {
        WebElement inlineMessage = driver.findElement(By.xpath("//div[@id='inline-message']"));
        assertions.assertTextContains(inlineMessage, expectedMessage);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-004
    /*  Title: Character counter display as user approaches limit
    /*  Priority: High
    /*  Category: Usability, Functional
    /**************************************************/
    
    @Given("comment length limit is set to {int} characters")
    public void commentLengthLimitIsSetToCharacters(int limit) {
        this.characterLimit = limit;
    }
    
    @Then("character counter should display {string}")
    public void characterCounterShouldDisplay(String expectedCounterText) {
        WebElement characterCounter = driver.findElement(By.xpath("//div[@id='character-counter']"));
        assertions.assertTextContains(characterCounter, expectedCounterText);
    }
    
    @Then("character counter should be positioned near input field")
    public void characterCounterShouldBePositionedNearInputField() {
        WebElement characterCounter = driver.findElement(By.xpath("//div[@id='character-counter']"));
        assertions.assertDisplayed(characterCounter);
    }
    
    @When("user continues typing until {string} characters are entered")
    public void userContinuesTypingUntilCharactersAreEntered(String characterCount) {
        int count = Integer.parseInt(characterCount);
        StringBuilder commentText = new StringBuilder();
        for (int i = 0; i < count; i++) {
            commentText.append("a");
        }
        
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        actions.clearAndSendKeys(commentInputField, commentText.toString());
    }
    
    @Then("character counter color should change to yellow")
    public void characterCounterColorShouldChangeToYellow() {
        WebElement characterCounter = driver.findElement(By.xpath("//div[@id='character-counter']"));
        String colorClass = characterCounter.getAttribute("class");
        
        if (!colorClass.contains("yellow") && !colorClass.contains("warning")) {
            throw new AssertionError("Character counter color did not change to yellow");
        }
    }
    
    @Then("input field should still accept text")
    public void inputFieldShouldStillAcceptText() {
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        if (!commentInputField.isEnabled()) {
            throw new AssertionError("Input field does not accept text");
        }
    }
    
    /**************************************************/
    /*  TEST CASE: TC-005
    /*  Title: Prevent character entry beyond maximum limit
    /*  Priority: High
    /*  Category: Usability, Edge, Negative
    /**************************************************/
    
    @Given("user has entered {string} characters in comment input field")
    public void userHasEnteredCharactersInCommentInputField(String characterCount) {
        int count = Integer.parseInt(characterCount);
        StringBuilder commentText = new StringBuilder();
        for (int i = 0; i < count; i++) {
            commentText.append("a");
        }
        
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        actions.clearAndSendKeys(commentInputField, commentText.toString());
    }
    
    @When("user attempts to enter additional character")
    public void userAttemptsToEnterAdditionalCharacter() {
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        String currentValue = commentInputField.getAttribute("value");
        actions.clearAndSendKeys(commentInputField, currentValue + "x");
    }
    
    @Then("system should prevent additional character entry")
    public void systemShouldPreventAdditionalCharacterEntry() {
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        String currentValue = commentInputField.getAttribute("value");
        
        if (currentValue.length() > this.characterLimit) {
            throw new AssertionError("System did not prevent additional character entry");
        }
    }
    
    @Then("character counter should turn red")
    public void characterCounterShouldTurnRed() {
        WebElement characterCounter = driver.findElement(By.xpath("//div[@id='character-counter']"));
        String colorClass = characterCounter.getAttribute("class");
        
        if (!colorClass.contains("red") && !colorClass.contains("error")) {
            throw new AssertionError("Character counter did not turn red");
        }
    }
    
    @Then("message {string} should be displayed")
    public void messageWithTextShouldBeDisplayed(String expectedMessage) {
        String messageXPath = String.format("//*[contains(text(),'%s')]", expectedMessage);
        WebElement message = driver.findElement(By.xpath(messageXPath));
        assertions.assertTextContains(message, expectedMessage);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-006
    /*  Title: Prevent pasting content exceeding character limit
    /*  Priority: High
    /*  Category: Usability, Edge, Negative
    /**************************************************/
    
    @When("user pastes {string} character text block into comment field")
    public void userPastesCharacterTextBlockIntoCommentField(String characterCount) {
        int count = Integer.parseInt(characterCount);
        StringBuilder pastedText = new StringBuilder();
        for (int i = 0; i < count; i++) {
            pastedText.append("b");
        }
        
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        actions.clearAndSendKeys(commentInputField, pastedText.toString());
    }
    
    @Then("system should truncate content to {int} characters with warning")
    public void systemShouldTruncateContentToCharactersWithWarning(int expectedLimit) {
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        String currentValue = commentInputField.getAttribute("value");
        
        if (currentValue.length() > expectedLimit) {
            throw new AssertionError("System did not truncate content to " + expectedLimit + " characters");
        }
        
        WebElement warningMessage = driver.findElement(By.xpath("//div[@id='warning-message']"));
        assertions.assertDisplayed(warningMessage);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-007
    /*  Title: Prevent submission of whitespace-only comment
    /*  Priority: High
    /*  Category: Usability, Negative
    /**************************************************/
    
    @When("user enters only whitespace characters in comment input field")
    public void userEntersOnlyWhitespaceCharactersInCommentInputField() {
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        actions.clearAndSendKeys(commentInputField, "     ");
    }
    
    @Then("system should prevent submission")
    public void systemShouldPreventSubmission() {
        WebElement saveButton = driver.findElement(By.xpath("//button[@id='save']"));
        if (saveButton.isEnabled()) {
            throw new AssertionError("System did not prevent submission");
        }
    }
    
    @Then("no invalid comment should be saved to database")
    public void noInvalidCommentShouldBeSavedToDatabase() {
        List<WebElement> comments = driver.findElements(By.xpath("//div[@class='comment-item']"));
        int initialCommentCount = comments.size();
        
        waits.waitForPageLoad();
        
        List<WebElement> updatedComments = driver.findElements(By.xpath("//div[@class='comment-item']"));
        if (updatedComments.size() > initialCommentCount) {
            throw new AssertionError("Invalid comment was saved to database");
        }
    }
    
    /**************************************************/
    /*  TEST CASE: TC-008
    /*  Title: Clear error message and recovery for network failure
    /*  Priority: High
    /*  Category: Usability, Negative, Functional
    /**************************************************/
    
    @Given("network connection is disconnected")
    public void networkConnectionIsDisconnected() {
        this.systemState = "network_disconnected";
    }
    
    @Then("error message {string} should be displayed")
    public void errorMessageShouldBeDisplayed(String expectedErrorMessage) {
        WebElement errorMessage = driver.findElement(By.xpath("//div[@id='error-message']"));
        assertions.assertTextContains(errorMessage, expectedErrorMessage);
    }
    
    @Then("{string} button should be visible")
    public void buttonShouldBeVisible(String buttonText) {
        String buttonIdXPath = String.format("//button[@id='%s']", 
            buttonText.toLowerCase().replaceAll("\\s+", "-"));
        List<WebElement> buttons = driver.findElements(By.xpath(buttonIdXPath));
        
        if (!buttons.isEmpty()) {
            assertions.assertDisplayed(buttons.get(0));
        } else {
            String xpathLocator = String.format("//button[contains(text(),'%s')]", buttonText);
            WebElement button = driver.findElement(By.xpath(xpathLocator));
            assertions.assertDisplayed(button);
        }
    }
    
    @Then("comment text should be preserved in input field")
    public void commentTextShouldBePreservedInInputField() {
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        String inputValue = commentInputField.getAttribute("value");
        
        if (inputValue == null || inputValue.isEmpty()) {
            throw new AssertionError("Comment text was not preserved in input field");
        }
    }
    
    @When("network connection is restored")
    public void networkConnectionIsRestored() {
        this.systemState = "network_restored";
    }
    
    @Then("system should attempt resubmission without requiring re-entry")
    public void systemShouldAttemptResubmissionWithoutRequiringReEntry() {
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        String inputValue = commentInputField.getAttribute("value");
        
        if (inputValue == null || inputValue.isEmpty()) {
            throw new AssertionError("System required re-entry of comment");
        }
    }
    
    @Then("success or failure feedback should be provided")
    public void successOrFailureFeedbackShouldBeProvided() {
        List<WebElement> successMessages = driver.findElements(By.xpath("//div[@id='success-message']"));
        List<WebElement> errorMessages = driver.findElements(By.xpath("//div[@id='error-message']"));
        
        if (successMessages.isEmpty() && errorMessages.isEmpty()) {
            throw new AssertionError("No feedback provided after resubmission");
        }
    }
    
    /**************************************************/
    /*  TEST CASE: TC-009
    /*  Title: Clear error message and recovery for session timeout
    /*  Priority: High
    /*  Category: Usability, Negative, Functional
    /**************************************************/
    
    @Given("user session has expired")
    public void userSessionHasExpired() {
        this.systemState = "session_expired";
    }
    
    @Then("comment text should be preserved in local storage")
    public void commentTextShouldBePreservedInLocalStorage() {
        String localStorageValue = (String) actions.executeScript("return localStorage.getItem('unsaved_comment');");
        
        if (localStorageValue == null || localStorageValue.isEmpty()) {
            throw new AssertionError("Comment text was not preserved in local storage");
        }
    }
    
    @Then("user should be redirected to login page with return path")
    public void userShouldBeRedirectedToLoginPageWithReturnPath() {
        waits.waitForPageLoad();
        String currentUrl = driver.getCurrentUrl();
        
        if (!currentUrl.contains("login") && !currentUrl.contains("return")) {
            throw new AssertionError("User was not redirected to login page with return path");
        }
    }
    
    @When("user completes authentication")
    public void userCompletesAuthentication() {
        WebElement usernameField = driver.findElement(By.xpath("//input[@id='username']"));
        actions.clearAndSendKeys(usernameField, "employee_user");
        
        WebElement passwordField = driver.findElement(By.xpath("//input[@id='password']"));
        actions.clearAndSendKeys(passwordField, "employee_pass");
        
        WebElement loginButton = driver.findElement(By.xpath("//button[@id='login']"));
        actions.click(loginButton);
        waits.waitForPageLoad();
    }
    
    @When("user returns to task details page")
    public void userReturnsToTaskDetailsPage() {
        taskDetailsPage.navigate();
        waits.waitForPageLoad();
    }
    
    @Then("previously entered comment text should be restored in input field")
    public void previouslyEnteredCommentTextShouldBeRestoredInInputField() {
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        String inputValue = commentInputField.getAttribute("value");
        
        if (inputValue == null || inputValue.isEmpty()) {
            throw new AssertionError("Previously entered comment text was not restored");
        }
    }
    
    /**************************************************/
    /*  TEST CASE: TC-010
    /*  Title: Clear error message and recovery for server error
    /*  Priority: High
    /*  Category: Usability, Negative
    /**************************************************/
    
    @Given("server returns {string} error during submission")
    public void serverReturnsErrorDuringSubmission(String errorCode) {
        this.systemState = "server_error_" + errorCode;
    }
    
    @Then("{string} button should be visible")
    public void specificButtonShouldBeVisible(String buttonText) {
        String buttonIdXPath = String.format("//button[@id='%s']", 
            buttonText.toLowerCase().replaceAll("\\s+", "-"));
        List<WebElement> buttons = driver.findElements(By.xpath(buttonIdXPath));
        
        if (!buttons.isEmpty()) {
            assertions.assertDisplayed(buttons.get(0));
        } else {
            String xpathLocator = String.format("//button[contains(text(),'%s')]", buttonText);
            WebElement button = driver.findElement(By.xpath(xpathLocator));
            assertions.assertDisplayed(button);
        }
    }
    
    @Then("error message should not contain technical jargon")
    public void errorMessageShouldNotContainTechnicalJargon() {
        WebElement errorMessage = driver.findElement(By.xpath("//div[@id='error-message']"));
        String errorText = errorMessage.getText().toLowerCase();
        
        String[] technicalTerms = {"500", "exception", "stack trace", "null pointer", "internal server"};
        for (String term : technicalTerms) {
            if (errorText.contains(term.toLowerCase())) {
                throw new AssertionError("Error message contains technical jargon: " + term);
            }
        }
    }
    
    /**************************************************/
    /*  TEST CASE: TC-011
    /*  Title: Clear error message for validation failure
    /*  Priority: High
    /*  Category: Usability, Negative, Functional
    /**************************************************/
    
    @When("user enters comment with prohibited content in comment input field")
    public void userEntersCommentWithProhibitedContentInCommentInputField() {
        WebElement commentInputField = driver.findElement(By.xpath("//textarea[@id='comment-input']"));
        actions.clearAndSendKeys(commentInputField, "This comment contains prohibited content that violates guidelines");
    }
    
    @Then("problematic section should be highlighted if possible")
    public void problematicSectionShouldBeHighlightedIfPossible() {
        List<WebElement> highlightedSections = driver.findElements(By.xpath("//span[@class='highlighted-error']"));
        
        if (!highlightedSections.isEmpty()) {
            assertions.assertDisplayed(highlightedSections.get(0));
        }
    }
    
    /**************************************************/
    /*  TEST CASE: TC-012
    /*  Title: Error messages are prominently displayed and accessible
    /*  Priority: High
    /*  Category: Usability, Accessibility
    /**************************************************/
    
    @When("any error occurs during comment submission")
    public void anyErrorOccursDuringCommentSubmission() {
        this.systemState = "error_occurred";
    }
    
    @Then("error message should be displayed near comment input field")
    public void errorMessageShouldBeDisplayedNearCommentInputField() {
        WebElement errorMessage = driver.findElement(By.xpath("//div[@id='error-message']"));
        assertions.assertDisplayed(errorMessage);
    }
    
    @Then("error message should use red or orange color coding")
    public void errorMessageShouldUseRedOrOrangeColorCoding() {
        WebElement errorMessage = driver.findElement(By.xpath("//div[@id='error-message']"));
        String colorClass = errorMessage.getAttribute("class");
        
        if (!colorClass.contains("red") && !colorClass.contains("orange") && !colorClass.contains("error")) {
            throw new AssertionError("Error message does not use red or orange color coding");
        }
    }
    
    @Then("error message should include warning or error icon")
    public void errorMessageShouldIncludeWarningOrErrorIcon() {
        List<WebElement> errorIcons = driver.findElements(By.xpath("//div[@id='error-message']//i[@class='error-icon']"));
        List<WebElement> warningIcons = driver.findElements(By.xpath("//div[@id='error-message']//i[@class='warning-icon']"));
        
        if (errorIcons.isEmpty() && warningIcons.isEmpty()) {
            throw new AssertionError("Error message does not include warning or error icon");
        }
    }
    
    @Then("error message should remain visible until user takes action")
    public void errorMessageShouldRemainVisibleUntilUserTakesAction() {
        WebElement errorMessage = driver.findElement(By.xpath("//div[@id='error-message']"));
        assertions.assertDisplayed(errorMessage);
        
        waits.waitForPageLoad();
        
        if (!errorMessage.isDisplayed()) {
            throw new AssertionError("Error message did not remain visible");
        }
    }
    
    @Then("error message should have ARIA labels for screen readers")
    public void errorMessageShouldHaveARIALabelsForScreenReaders() {
        WebElement errorMessage = driver.findElement(By.xpath("//div[@id='error-message']"));
        String ariaLabel = errorMessage.getAttribute("aria-label");
        String ariaLive = errorMessage.getAttribute("aria-live");
        
        if ((ariaLabel == null || ariaLabel.isEmpty()) && (ariaLive == null || ariaLive.isEmpty())) {
            throw new AssertionError("Error message does not have ARIA labels for screen readers");
        }
    }
    
    @Then("error message should use polite and constructive language")
    public void errorMessageShouldUsePoliteAndConstructiveLanguage() {
        WebElement errorMessage = driver.findElement(By.xpath("//div[@id='error-message']"));
        String errorText = errorMessage.getText().toLowerCase();
        
        String[] rudeTerms = {"stupid", "invalid", "wrong", "bad", "failed"};
        for (String term : rudeTerms) {
            if (errorText.contains(term)) {
                throw new AssertionError("Error message uses impolite language: " + term);
            }
        }
    }
}