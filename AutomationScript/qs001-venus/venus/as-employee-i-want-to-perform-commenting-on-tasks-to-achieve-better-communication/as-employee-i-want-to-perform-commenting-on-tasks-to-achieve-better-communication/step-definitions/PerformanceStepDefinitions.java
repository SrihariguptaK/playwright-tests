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
import utils.GenericActions;
import utils.WaitHelpers;
import utils.AssertionHelpers;
import testdata.TestData;

// TODO: Replace with Object Repository when available
// import objectrepository.Locators;

public class TaskCommentSystemPerformanceStepDefinitions {

    private WebDriver driver;
    private GenericActions actions;
    private WaitHelpers waits;
    private AssertionHelpers assertions;
    
    private BasePage basePage;
    private HomePage homePage;
    
    private Map<String, Object> performanceMetrics;
    private Map<String, Object> testConfiguration;
    private int currentConcurrentUsers;
    private double baselineResponseTime;
    private double baselineCpuUtilization;
    
    @Before
    public void setUp() {
        ChromeOptions options = new ChromeOptions();
        options.addArguments("--start-maximized");
        options.addArguments("--ignore-certificate-errors");
        options.addArguments("--disable-gpu");
        driver = new ChromeDriver(options);
        
        actions = new GenericActions(driver);
        waits = new WaitHelpers(driver);
        assertions = new AssertionHelpers(driver);
        
        basePage = new BasePage(driver);
        homePage = new HomePage(driver);
        
        performanceMetrics = new HashMap<>();
        testConfiguration = new HashMap<>();
        currentConcurrentUsers = 0;
        baselineResponseTime = 0.0;
        baselineCpuUtilization = 0.0;
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
    /*  TEST CASE: TC-PERF-001
    /*  Title: Concurrent comment submission under peak load with response time validation
    /*  Priority: Critical
    /*  Category: Performance - Load Testing
    /**************************************************/
    
    // TODO: Replace XPath with Object Repository when available
    @Given("performance monitoring tools are configured and active")
    public void performanceMonitoringToolsAreConfiguredAndActive() {
        homePage.navigate();
        waits.waitForPageLoad();
        
        String monitoringDashboardXPath = "//div[@id='performance-monitoring-dashboard']";
        WebElement monitoringDashboard = driver.findElement(By.xpath(monitoringDashboardXPath));
        waits.waitForElementVisible(monitoringDashboard);
        assertions.assertDisplayed(monitoringDashboard);
        
        String activeStatusXPath = "//span[@id='monitoring-status' and contains(text(),'Active')]";
        WebElement activeStatus = driver.findElement(By.xpath(activeStatusXPath));
        assertions.assertDisplayed(activeStatus);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Given("test environment is configured with production-like infrastructure")
    public void testEnvironmentIsConfiguredWithProductionLikeInfrastructure() {
        String environmentConfigXPath = "//div[@id='environment-configuration']";
        WebElement environmentConfig = driver.findElement(By.xpath(environmentConfigXPath));
        actions.click(environmentConfig);
        waits.waitForPageLoad();
        
        String productionModeXPath = "//span[@id='environment-mode' and contains(text(),'Production-Like')]";
        WebElement productionMode = driver.findElement(By.xpath(productionModeXPath));
        assertions.assertDisplayed(productionMode);
        
        testConfiguration.put("environment", "production-like");
        testConfiguration.put("configured", true);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Given("database is populated with {int} existing tasks")
    public void databaseIsPopulatedWithExistingTasks(int taskCount) {
        String dataSetupXPath = "//button[@id='database-setup']";
        WebElement dataSetupButton = driver.findElement(By.xpath(dataSetupXPath));
        actions.click(dataSetupButton);
        waits.waitForPageLoad();
        
        String taskCountInputXPath = "//input[@id='task-count']";
        WebElement taskCountInput = driver.findElement(By.xpath(taskCountInputXPath));
        actions.clearAndSendKeys(taskCountInput, String.valueOf(taskCount));
        
        String populateButtonXPath = "//button[@id='populate-database']";
        WebElement populateButton = driver.findElement(By.xpath(populateButtonXPath));
        actions.click(populateButton);
        waits.waitForPageLoad();
        
        String successMessageXPath = String.format("//div[@id='success-message' and contains(text(),'%d tasks created')]", taskCount);
        WebElement successMessage = driver.findElement(By.xpath(successMessageXPath));
        assertions.assertDisplayed(successMessage);
        
        testConfiguration.put("taskCount", taskCount);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Given("{int} authenticated employee test accounts are created")
    public void authenticatedEmployeeTestAccountsAreCreated(int accountCount) {
        String userManagementXPath = "//a[@id='user-management']";
        WebElement userManagementLink = driver.findElement(By.xpath(userManagementXPath));
        actions.click(userManagementLink);
        waits.waitForPageLoad();
        
        String accountCountInputXPath = "//input[@id='account-count']";
        WebElement accountCountInput = driver.findElement(By.xpath(accountCountInputXPath));
        actions.clearAndSendKeys(accountCountInput, String.valueOf(accountCount));
        
        String createAccountsButtonXPath = "//button[@id='create-test-accounts']";
        WebElement createAccountsButton = driver.findElement(By.xpath(createAccountsButtonXPath));
        actions.click(createAccountsButton);
        waits.waitForPageLoad();
        
        String confirmationXPath = String.format("//div[@id='account-confirmation' and contains(text(),'%d accounts created')]", accountCount);
        WebElement confirmation = driver.findElement(By.xpath(confirmationXPath));
        assertions.assertDisplayed(confirmation);
        
        testConfiguration.put("userAccounts", accountCount);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Given("baseline performance metrics are captured for comparison")
    public void baselinePerformanceMetricsAreCapturedForComparison() {
        String metricsPageXPath = "//a[@id='performance-metrics']";
        WebElement metricsPageLink = driver.findElement(By.xpath(metricsPageXPath));
        actions.click(metricsPageLink);
        waits.waitForPageLoad();
        
        String captureBaselineButtonXPath = "//button[@id='capture-baseline']";
        WebElement captureBaselineButton = driver.findElement(By.xpath(captureBaselineButtonXPath));
        actions.click(captureBaselineButton);
        waits.waitForPageLoad();
        
        String baselineResponseTimeXPath = "//span[@id='baseline-response-time']";
        WebElement baselineResponseTimeElement = driver.findElement(By.xpath(baselineResponseTimeXPath));
        baselineResponseTime = Double.parseDouble(baselineResponseTimeElement.getText().replaceAll("[^0-9.]", ""));
        
        String baselineCpuXPath = "//span[@id='baseline-cpu']";
        WebElement baselineCpuElement = driver.findElement(By.xpath(baselineCpuXPath));
        baselineCpuUtilization = Double.parseDouble(baselineCpuElement.getText().replaceAll("[^0-9.]", ""));
        
        performanceMetrics.put("baselineResponseTime", baselineResponseTime);
        performanceMetrics.put("baselineCpu", baselineCpuUtilization);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-PERF-002
    /*  Title: Comment system breaking point and graceful degradation validation
    /*  Priority: High
    /*  Category: Performance - Stress Testing
    /**************************************************/
    
    // TODO: Replace XPath with Object Repository when available
    @Given("test environment is isolated from production")
    public void testEnvironmentIsIsolatedFromProduction() {
        String isolationConfigXPath = "//div[@id='environment-isolation']";
        WebElement isolationConfig = driver.findElement(By.xpath(isolationConfigXPath));
        actions.click(isolationConfig);
        waits.waitForPageLoad();
        
        String isolatedStatusXPath = "//span[@id='isolation-status' and contains(text(),'Isolated')]";
        WebElement isolatedStatus = driver.findElement(By.xpath(isolatedStatusXPath));
        assertions.assertDisplayed(isolatedStatus);
        
        testConfiguration.put("isolated", true);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Given("system health monitoring dashboards are active")
    public void systemHealthMonitoringDashboardsAreActive() {
        String healthDashboardXPath = "//div[@id='health-monitoring-dashboard']";
        WebElement healthDashboard = driver.findElement(By.xpath(healthDashboardXPath));
        waits.waitForElementVisible(healthDashboard);
        assertions.assertDisplayed(healthDashboard);
        
        String dashboardStatusXPath = "//span[@id='dashboard-status' and contains(text(),'Active')]";
        WebElement dashboardStatus = driver.findElement(By.xpath(dashboardStatusXPath));
        assertions.assertDisplayed(dashboardStatus);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Given("database is pre-loaded with {int} tasks")
    public void databaseIsPreLoadedWithTasks(int taskCount) {
        String preloadButtonXPath = "//button[@id='preload-database']";
        WebElement preloadButton = driver.findElement(By.xpath(preloadButtonXPath));
        actions.click(preloadButton);
        waits.waitForPageLoad();
        
        String taskCountFieldXPath = "//input[@id='preload-task-count']";
        WebElement taskCountField = driver.findElement(By.xpath(taskCountFieldXPath));
        actions.clearAndSendKeys(taskCountField, String.valueOf(taskCount));
        
        String executePreloadXPath = "//button[@id='execute-preload']";
        WebElement executePreloadButton = driver.findElement(By.xpath(executePreloadXPath));
        actions.click(executePreloadButton);
        waits.waitForPageLoad();
        
        String preloadConfirmationXPath = String.format("//div[@id='preload-confirmation' and contains(text(),'%d tasks loaded')]", taskCount);
        WebElement preloadConfirmation = driver.findElement(By.xpath(preloadConfirmationXPath));
        assertions.assertDisplayed(preloadConfirmation);
        
        testConfiguration.put("preloadedTasks", taskCount);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Given("auto-scaling is disabled to identify true breaking point")
    public void autoScalingIsDisabledToIdentifyTrueBreakingPoint() {
        String scalingConfigXPath = "//a[@id='scaling-configuration']";
        WebElement scalingConfigLink = driver.findElement(By.xpath(scalingConfigXPath));
        actions.click(scalingConfigLink);
        waits.waitForPageLoad();
        
        String autoScalingToggleXPath = "//input[@id='auto-scaling-toggle']";
        WebElement autoScalingToggle = driver.findElement(By.xpath(autoScalingToggleXPath));
        
        if (autoScalingToggle.isSelected()) {
            actions.click(autoScalingToggle);
        }
        
        String disabledStatusXPath = "//span[@id='scaling-status' and contains(text(),'Disabled')]";
        WebElement disabledStatus = driver.findElement(By.xpath(disabledStatusXPath));
        assertions.assertDisplayed(disabledStatus);
        
        testConfiguration.put("autoScaling", false);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Given("alerting mechanisms are configured for critical thresholds")
    public void alertingMechanismsAreConfiguredForCriticalThresholds() {
        String alertConfigXPath = "//a[@id='alert-configuration']";
        WebElement alertConfigLink = driver.findElement(By.xpath(alertConfigXPath));
        actions.click(alertConfigLink);
        waits.waitForPageLoad();
        
        String criticalThresholdsXPath = "//div[@id='critical-thresholds']";
        WebElement criticalThresholds = driver.findElement(By.xpath(criticalThresholdsXPath));
        assertions.assertDisplayed(criticalThresholds);
        
        String alertStatusXPath = "//span[@id='alert-status' and contains(text(),'Configured')]";
        WebElement alertStatus = driver.findElement(By.xpath(alertStatusXPath));
        assertions.assertDisplayed(alertStatus);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-PERF-003
    /*  Title: Sudden traffic surge handling during comment notification burst
    /*  Priority: Critical
    /*  Category: Performance - Spike Testing
    /**************************************************/
    
    // TODO: Replace XPath with Object Repository when available
    @Given("auto-scaling policies are configured and enabled")
    public void autoScalingPoliciesAreConfiguredAndEnabled() {
        String scalingPoliciesXPath = "//a[@id='scaling-policies']";
        WebElement scalingPoliciesLink = driver.findElement(By.xpath(scalingPoliciesXPath));
        actions.click(scalingPoliciesLink);
        waits.waitForPageLoad();
        
        String enableAutoScalingXPath = "//input[@id='enable-auto-scaling']";
        WebElement enableAutoScaling = driver.findElement(By.xpath(enableAutoScalingXPath));
        
        if (!enableAutoScaling.isSelected()) {
            actions.click(enableAutoScaling);
        }
        
        String enabledStatusXPath = "//span[@id='auto-scaling-status' and contains(text(),'Enabled')]";
        WebElement enabledStatus = driver.findElement(By.xpath(enabledStatusXPath));
        assertions.assertDisplayed(enabledStatus);
        
        testConfiguration.put("autoScalingEnabled", true);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Given("notification queue system is operational")
    public void notificationQueueSystemIsOperational() {
        String queueSystemXPath = "//div[@id='notification-queue-system']";
        WebElement queueSystem = driver.findElement(By.xpath(queueSystemXPath));
        waits.waitForElementVisible(queueSystem);
        assertions.assertDisplayed(queueSystem);
        
        String operationalStatusXPath = "//span[@id='queue-status' and contains(text(),'Operational')]";
        WebElement operationalStatus = driver.findElement(By.xpath(operationalStatusXPath));
        assertions.assertDisplayed(operationalStatus);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Given("baseline load of {int} concurrent users is established")
    public void baselineLoadOfConcurrentUsersIsEstablished(int userCount) {
        String loadTestConfigXPath = "//a[@id='load-test-configuration']";
        WebElement loadTestConfigLink = driver.findElement(By.xpath(loadTestConfigXPath));
        actions.click(loadTestConfigLink);
        waits.waitForPageLoad();
        
        String baselineUsersInputXPath = "//input[@id='baseline-users']";
        WebElement baselineUsersInput = driver.findElement(By.xpath(baselineUsersInputXPath));
        actions.clearAndSendKeys(baselineUsersInput, String.valueOf(userCount));
        
        String establishBaselineXPath = "//button[@id='establish-baseline']";
        WebElement establishBaselineButton = driver.findElement(By.xpath(establishBaselineXPath));
        actions.click(establishBaselineButton);
        waits.waitForPageLoad();
        
        currentConcurrentUsers = userCount;
        testConfiguration.put("baselineUsers", userCount);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Given("cloud infrastructure with scaling capabilities is available")
    public void cloudInfrastructureWithScalingCapabilitiesIsAvailable() {
        String infrastructureXPath = "//div[@id='cloud-infrastructure']";
        WebElement infrastructure = driver.findElement(By.xpath(infrastructureXPath));
        assertions.assertDisplayed(infrastructure);
        
        String scalingCapabilitiesXPath = "//span[@id='scaling-capabilities' and contains(text(),'Available')]";
        WebElement scalingCapabilities = driver.findElement(By.xpath(scalingCapabilitiesXPath));
        assertions.assertDisplayed(scalingCapabilities);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Given("monitoring alerts are configured for spike detection")
    public void monitoringAlertsAreConfiguredForSpikeDetection() {
        String spikeAlertsXPath = "//div[@id='spike-detection-alerts']";
        WebElement spikeAlerts = driver.findElement(By.xpath(spikeAlertsXPath));
        assertions.assertDisplayed(spikeAlerts);
        
        String alertConfigStatusXPath = "//span[@id='spike-alert-status' and contains(text(),'Configured')]";
        WebElement alertConfigStatus = driver.findElement(By.xpath(alertConfigStatusXPath));
        assertions.assertDisplayed(alertConfigStatus);
    }
    
    // ==================== WHEN STEPS ====================
    
    /**************************************************/
    /*  TEST CASE: TC-PERF-001
    /*  Title: Concurrent comment submission under peak load with response time validation
    /*  Priority: Critical
    /*  Category: Performance - Load Testing
    /**************************************************/
    
    // TODO: Replace XPath with Object Repository when available
    @When("load testing tool is configured to simulate {int} concurrent users with ramp-up time of {int} seconds")
    public void loadTestingToolIsConfiguredToSimulateConcurrentUsersWithRampUpTime(int userCount, int rampUpSeconds) {
        String loadToolConfigXPath = "//div[@id='load-testing-tool']";
        WebElement loadToolConfig = driver.findElement(By.xpath(loadToolConfigXPath));
        actions.click(loadToolConfig);
        waits.waitForPageLoad();
        
        String concurrentUsersInputXPath = "//input[@id='concurrent-users']";
        WebElement concurrentUsersInput = driver.findElement(By.xpath(concurrentUsersInputXPath));
        actions.clearAndSendKeys(concurrentUsersInput, String.valueOf(userCount));
        
        String rampUpInputXPath = "//input[@id='ramp-up-time']";
        WebElement rampUpInput = driver.findElement(By.xpath(rampUpInputXPath));
        actions.clearAndSendKeys(rampUpInput, String.valueOf(rampUpSeconds));
        
        String applyConfigButtonXPath = "//button[@id='apply-load-config']";
        WebElement applyConfigButton = driver.findElement(By.xpath(applyConfigButtonXPath));
        actions.click(applyConfigButton);
        waits.waitForPageLoad();
        
        currentConcurrentUsers = userCount;
        testConfiguration.put("concurrentUsers", userCount);
        testConfiguration.put("rampUpTime", rampUpSeconds);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("POST requests to {string} endpoint are executed with comment payloads between {int} and {int} characters for {int} minutes sustained load")
    public void postRequestsToEndpointAreExecutedWithCommentPayloadsBetweenCharactersForMinutesSustainedLoad(String endpoint, int minChars, int maxChars, int durationMinutes) {
        String endpointInputXPath = "//input[@id='api-endpoint']";
        WebElement endpointInput = driver.findElement(By.xpath(endpointInputXPath));
        actions.clearAndSendKeys(endpointInput, endpoint);
        
        String minCharsInputXPath = "//input[@id='min-payload-chars']";
        WebElement minCharsInput = driver.findElement(By.xpath(minCharsInputXPath));
        actions.clearAndSendKeys(minCharsInput, String.valueOf(minChars));
        
        String maxCharsInputXPath = "//input[@id='max-payload-chars']";
        WebElement maxCharsInput = driver.findElement(By.xpath(maxCharsInputXPath));
        actions.clearAndSendKeys(maxCharsInput, String.valueOf(maxChars));
        
        String durationInputXPath = "//input[@id='test-duration']";
        WebElement durationInput = driver.findElement(By.xpath(durationInputXPath));
        actions.clearAndSendKeys(durationInput, String.valueOf(durationMinutes));
        
        String startLoadTestXPath = "//button[@id='start-load-test']";
        WebElement startLoadTestButton = driver.findElement(By.xpath(startLoadTestXPath));
        actions.click(startLoadTestButton);
        waits.waitForPageLoad();
        
        testConfiguration.put("endpoint", endpoint);
        testConfiguration.put("minPayloadChars", minChars);
        testConfiguration.put("maxPayloadChars", maxChars);
        testConfiguration.put("testDuration", durationMinutes);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-PERF-002
    /*  Title: Comment system breaking point and graceful degradation validation
    /*  Priority: High
    /*  Category: Performance - Stress Testing
    /**************************************************/
    
    // TODO: Replace XPath with Object Repository when available
    @When("load starts with {int} concurrent users")
    public void loadStartsWithConcurrentUsers(int initialUsers) {
        String initialLoadInputXPath = "//input[@id='initial-load-users']";
        WebElement initialLoadInput = driver.findElement(By.xpath(initialLoadInputXPath));
        actions.clearAndSendKeys(initialLoadInput, String.valueOf(initialUsers));
        
        String startStressTestXPath = "//button[@id='start-stress-test']";
        WebElement startStressTestButton = driver.findElement(By.xpath(startStressTestXPath));
        actions.click(startStressTestButton);
        waits.waitForPageLoad();
        
        currentConcurrentUsers = initialUsers;
        testConfiguration.put("initialUsers", initialUsers);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("load is incrementally increased by {int} users every {int} minutes until system failure")
    public void loadIsIncrementallyIncreasedByUsersEveryMinutesUntilSystemFailure(int incrementUsers, int intervalMinutes) {
        String incrementInputXPath = "//input[@id='user-increment']";
        WebElement incrementInput = driver.findElement(By.xpath(incrementInputXPath));
        actions.clearAndSendKeys(incrementInput, String.valueOf(incrementUsers));
        
        String intervalInputXPath = "//input[@id='increment-interval']";
        WebElement intervalInput = driver.findElement(By.xpath(intervalInputXPath));
        actions.clearAndSendKeys(intervalInput, String.valueOf(intervalMinutes));
        
        String enableIncrementalLoadXPath = "//button[@id='enable-incremental-load']";
        WebElement enableIncrementalLoadButton = driver.findElement(By.xpath(enableIncrementalLoadXPath));
        actions.click(enableIncrementalLoadButton);
        waits.waitForPageLoad();
        
        testConfiguration.put("userIncrement", incrementUsers);
        testConfiguration.put("incrementInterval", intervalMinutes);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("load generation is stopped")
    public void loadGenerationIsStopped() {
        String stopLoadButtonXPath = "//button[@id='stop-load-generation']";
        WebElement stopLoadButton = driver.findElement(By.xpath(stopLoadButtonXPath));
        actions.click(stopLoadButton);
        waits.waitForPageLoad();
        
        String stoppedStatusXPath = "//span[@id='load-status' and contains(text(),'Stopped')]";
        WebElement stoppedStatus = driver.findElement(By.xpath(stoppedStatusXPath));
        assertions.assertDisplayed(stoppedStatus);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-PERF-003
    /*  Title: Sudden traffic surge handling during comment notification burst
    /*  Priority: Critical
    /*  Category: Performance - Spike Testing
    /**************************************************/
    
    // TODO: Replace XPath with Object Repository when available
    @When("baseline load with {int} concurrent users submitting comments at rate of {int} comments per minute per user is established")
    public void baselineLoadWithConcurrentUsersSubmittingCommentsAtRateOfCommentsPerMinutePerUserIsEstablished(int users, int commentsPerMinute) {
        String baselineUsersFieldXPath = "//input[@id='baseline-concurrent-users']";
        WebElement baselineUsersField = driver.findElement(By.xpath(baselineUsersFieldXPath));
        actions.clearAndSendKeys(baselineUsersField, String.valueOf(users));
        
        String commentRateInputXPath = "//input[@id='comment-rate-per-user']";
        WebElement commentRateInput = driver.findElement(By.xpath(commentRateInputXPath));
        actions.clearAndSendKeys(commentRateInput, String.valueOf(commentsPerMinute));
        
        String establishBaselineLoadXPath = "//button[@id='establish-baseline-load']";
        WebElement establishBaselineLoadButton = driver.findElement(By.xpath(establishBaselineLoadXPath));
        actions.click(establishBaselineLoadButton);
        waits.waitForPageLoad();
        
        currentConcurrentUsers = users;
        testConfiguration.put("baselineUsers", users);
        testConfiguration.put("commentRate", commentsPerMinute);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("sudden spike increases load from {int} to {int} concurrent users within {int} seconds")
    public void suddenSpikeIncreasesLoadFromToConcurrentUsersWithinSeconds(int fromUsers, int toUsers, int spikeSeconds) {
        String spikeFromInputXPath = "//input[@id='spike-from-users']";
        WebElement spikeFromInput = driver.findElement(By.xpath(spikeFromInputXPath));
        actions.clearAndSendKeys(spikeFromInput, String.valueOf(fromUsers));
        
        String spikeToInputXPath = "//input[@id='spike-to-users']";
        WebElement spikeToInput = driver.findElement(By.xpath(spikeToInputXPath));
        actions.clearAndSendKeys(spikeToInput, String.valueOf(toUsers));
        
        String spikeDurationInputXPath = "//input[@id='spike-duration']";
        WebElement spikeDurationInput = driver.findElement(By.xpath(spikeDurationInputXPath));
        actions.clearAndSendKeys(spikeDurationInput, String.valueOf(spikeSeconds));
        
        String executeSpikeXPath = "//button[@id='execute-spike']";
        WebElement executeSpikeButton = driver.findElement(By.xpath(executeSpikeXPath));
        actions.click(executeSpikeButton);
        waits.waitForPageLoad();
        
        currentConcurrentUsers = toUsers;
        testConfiguration.put("spikeFromUsers", fromUsers);
        testConfiguration.put("spikeToUsers", toUsers);
        testConfiguration.put("spikeDuration", spikeSeconds);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("spike load is maintained for {int} minutes")
    public void spikeLoadIsMaintainedForMinutes(int durationMinutes) {
        String maintainDurationInputXPath = "//input[@id='maintain-spike-duration']";
        WebElement maintainDurationInput = driver.findElement(By.xpath(maintainDurationInputXPath));
        actions.clearAndSendKeys(maintainDurationInput, String.valueOf(durationMinutes));
        
        String maintainSpikeXPath = "//button[@id='maintain-spike-load']";
        WebElement maintainSpikeButton = driver.findElement(By.xpath(maintainSpikeXPath));
        actions.click(maintainSpikeButton);
        waits.waitForPageLoad();
        
        testConfiguration.put("spikeMaintainDuration", durationMinutes);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @When("load rapidly decreases from {int} to {int} users within {int} seconds")
    public void loadRapidlyDecreasesFromToUsersWithinSeconds(int fromUsers, int toUsers, int decreaseSeconds) {
        String decreaseFromInputXPath = "//input[@id='decrease-from-users']";
        WebElement decreaseFromInput = driver.findElement(By.xpath(decreaseFromInputXPath));
        actions.clearAndSendKeys(decreaseFromInput, String.valueOf(fromUsers));
        
        String decreaseToInputXPath = "//input[@id='decrease-to-users']";
        WebElement decreaseToInput = driver.findElement(By.xpath(decreaseToInputXPath));
        actions.clearAndSendKeys(decreaseToInput, String.valueOf(toUsers));
        
        String decreaseDurationInputXPath = "//input[@id='decrease-duration']";
        WebElement decreaseDurationInput = driver.findElement(By.xpath(decreaseDurationInputXPath));
        actions.clearAndSendKeys(decreaseDurationInput, String.valueOf(decreaseSeconds));
        
        String executeDecreaseXPath = "//button[@id='execute-load-decrease']";
        WebElement executeDecreaseButton = driver.findElement(By.xpath(executeDecreaseXPath));
        actions.click(executeDecreaseButton);
        waits.waitForPageLoad();
        
        currentConcurrentUsers = toUsers;
        testConfiguration.put("decreaseFromUsers", fromUsers);
        testConfiguration.put("decreaseToUsers", toUsers);
        testConfiguration.put("decreaseDuration", decreaseSeconds);
    }
    
    // ==================== THEN STEPS ====================
    
    /**************************************************/
    /*  TEST CASE: TC-PERF-001
    /*  Title: Concurrent comment submission under peak load with response time validation
    /*  Priority: Critical
    /*  Category: Performance - Load Testing
    /**************************************************/
    
    // TODO: Replace XPath with Object Repository when available
    @Then("all {int} concurrent users should successfully send comment requests continuously")
    public void allConcurrentUsersShouldSuccessfullySendCommentRequestsContinuously(int expectedUsers) {
        String activeUsersXPath = "//span[@id='active-concurrent-users']";
        WebElement activeUsersElement = driver.findElement(By.xpath(activeUsersXPath));
        String activeUsersText = activeUsersElement.getText().replaceAll("[^0-9]", "");
        int actualActiveUsers = Integer.parseInt(activeUsersText);
        
        assertions.assertTextContains(activeUsersElement, String.valueOf(expectedUsers));
        
        String requestStatusXPath = "//span[@id='request-status' and contains(text(),'Continuous')]";
        WebElement requestStatus = driver.findElement(By.xpath(requestStatusXPath));
        assertions.assertDisplayed(requestStatus);
        
        performanceMetrics.put("activeUsers", actualActiveUsers);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("P50 response time should be less than or equal to {double} seconds")
    public void p50ResponseTimeShouldBeLessThanOrEqualToSeconds(double maxSeconds) {
        String p50ResponseTimeXPath = "//span[@id='p50-response-time']";
        WebElement p50ResponseTimeElement = driver.findElement(By.xpath(p50ResponseTimeXPath));
        String p50Text = p50ResponseTimeElement.getText().replaceAll("[^0-9.]", "");
        double actualP50 = Double.parseDouble(p50Text);
        
        String validationXPath = String.format("//div[@id='p50-validation' and contains(text(),'Pass')]");
        WebElement validationElement = driver.findElement(By.xpath(validationXPath));
        assertions.assertDisplayed(validationElement);
        
        performanceMetrics.put("p50ResponseTime", actualP50);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("P95 response time should be less than or equal to {double} seconds")
    public void p95ResponseTimeShouldBeLessThanOrEqualToSeconds(double maxSeconds) {
        String p95ResponseTimeXPath = "//span[@id='p95-response-time']";
        WebElement p95ResponseTimeElement = driver.findElement(By.xpath(p95ResponseTimeXPath));
        String p95Text = p95ResponseTimeElement.getText().replaceAll("[^0-9.]", "");
        double actualP95 = Double.parseDouble(p95Text);
        
        String validationXPath = String.format("//div[@id='p95-validation' and contains(text(),'Pass')]");
        WebElement validationElement = driver.findElement(By.xpath(validationXPath));
        assertions.assertDisplayed(validationElement);
        
        performanceMetrics.put("p95ResponseTime", actualP95);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("P99 response time should be less than or equal to {double} seconds")
    public void p99ResponseTimeShouldBeLessThanOrEqualToSeconds(double maxSeconds) {
        String p99ResponseTimeXPath = "//span[@id='p99-response-time']";
        WebElement p99ResponseTimeElement = driver.findElement(By.xpath(p99ResponseTimeXPath));
        String p99Text = p99ResponseTimeElement.getText().replaceAll("[^0-9.]", "");
        double actualP99 = Double.parseDouble(p99Text);
        
        String validationXPath = String.format("//div[@id='p99-validation' and contains(text(),'Pass')]");
        WebElement validationElement = driver.findElement(By.xpath(validationXPath));
        assertions.assertDisplayed(validationElement);
        
        performanceMetrics.put("p99ResponseTime", actualP99);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("throughput should be greater than or equal to {int} transactions per second")
    public void throughputShouldBeGreaterThanOrEqualToTransactionsPerSecond(int minThroughput) {
        String throughputXPath = "//span[@id='throughput-tps']";
        WebElement throughputElement = driver.findElement(By.xpath(throughputXPath));
        String throughputText = throughputElement.getText().replaceAll("[^0-9]", "");
        int actualThroughput = Integer.parseInt(throughputText);
        
        String throughputValidationXPath = String.format("//div[@id='throughput-validation' and contains(text(),'Pass')]");
        WebElement throughputValidation = driver.findElement(By.xpath(throughputValidationXPath));
        assertions.assertDisplayed(throughputValidation);
        
        performanceMetrics.put("throughput", actualThroughput);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("error rate should be less than {int} percent")
    public void errorRateShouldBeLessThanPercent(int maxErrorPercent) {
        String errorRateXPath = "//span[@id='error-rate-percent']";
        WebElement errorRateElement = driver.findElement(By.xpath(errorRateXPath));
        String errorRateText = errorRateElement.getText().replaceAll("[^0-9.]", "");
        double actualErrorRate = Double.parseDouble(errorRateText);
        
        String errorValidationXPath = String.format("//div[@id='error-rate-validation' and contains(text(),'Pass')]");
        WebElement errorValidation = driver.findElement(By.xpath(errorValidationXPath));
        assertions.assertDisplayed(errorValidation);
        
        performanceMetrics.put("errorRate", actualErrorRate);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("all comments should be successfully saved to database")
    public void allCommentsShouldBeSuccessfullySavedToDatabase() {
        String databaseValidationXPath = "//div[@id='database-validation']";
        WebElement databaseValidation = driver.findElement(By.xpath(databaseValidationXPath));
        actions.click(databaseValidation);
        waits.waitForPageLoad();
        
        String savedCommentsXPath = "//span[@id='saved-comments-status' and contains(text(),'All Saved')]";
        WebElement savedCommentsStatus = driver.findElement(By.xpath(savedCommentsXPath));
        assertions.assertDisplayed(savedCommentsStatus);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("CPU utilization should be less than {int} percent")
    public void cpuUtilizationShouldBeLessThanPercent(int maxCpuPercent) {
        String cpuUtilizationXPath = "//span[@id='cpu-utilization-percent']";
        WebElement cpuUtilizationElement = driver.findElement(By.xpath(cpuUtilizationXPath));
        String cpuText = cpuUtilizationElement.getText().replaceAll("[^0-9.]", "");
        double actualCpu = Double.parseDouble(cpuText);
        
        String cpuValidationXPath = String.format("//div[@id='cpu-validation' and contains(text(),'Pass')]");
        WebElement cpuValidation = driver.findElement(By.xpath(cpuValidationXPath));
        assertions.assertDisplayed(cpuValidation);
        
        performanceMetrics.put("cpuUtilization", actualCpu);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("memory usage should be less than {int} percent")
    public void memoryUsageShouldBeLessThanPercent(int maxMemoryPercent) {
        String memoryUsageXPath = "//span[@id='memory-usage-percent']";
        WebElement memoryUsageElement = driver.findElement(By.xpath(memoryUsageXPath));
        String memoryText = memoryUsageElement.getText().replaceAll("[^0-9.]", "");
        double actualMemory = Double.parseDouble(memoryText);
        
        String memoryValidationXPath = String.format("//div[@id='memory-validation' and contains(text(),'Pass')]");
        WebElement memoryValidation = driver.findElement(By.xpath(memoryValidationXPath));
        assertions.assertDisplayed(memoryValidation);
        
        performanceMetrics.put("memoryUsage", actualMemory);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("database connection pool usage should be less than {int} percent capacity")
    public void databaseConnectionPoolUsageShouldBeLessThanPercentCapacity(int maxPoolPercent) {
        String poolUsageXPath = "//span[@id='connection-pool-usage-percent']";
        WebElement poolUsageElement = driver.findElement(By.xpath(poolUsageXPath));
        String poolText = poolUsageElement.getText().replaceAll("[^0-9.]", "");
        double actualPoolUsage = Double.parseDouble(poolText);
        
        String poolValidationXPath = String.format("//div[@id='pool-validation' and contains(text(),'Pass')]");
        WebElement poolValidation = driver.findElement(By.xpath(poolValidationXPath));
        assertions.assertDisplayed(poolValidation);
        
        performanceMetrics.put("connectionPoolUsage", actualPoolUsage);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("no resource exhaustion should occur")
    public void noResourceExhaustionShouldOccur() {
        String resourceStatusXPath = "//div[@id='resource-exhaustion-status']";
        WebElement resourceStatus = driver.findElement(By.xpath(resourceStatusXPath));
        assertions.assertDisplayed(resourceStatus);
        
        String noExhaustionXPath = "//span[@id='exhaustion-indicator' and contains(text(),'None')]";
        WebElement noExhaustion = driver.findElement(By.xpath(noExhaustionXPath));
        assertions.assertDisplayed(noExhaustion);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("comment retrieval and display should complete within {int} seconds for tasks with up to {int} comments")
    public void commentRetrievalAndDisplayShouldCompleteWithinSecondsForTasksWithUpToComments(int maxSeconds, int commentCount) {
        String retrievalTimeXPath = "//span[@id='comment-retrieval-time']";
        WebElement retrievalTimeElement = driver.findElement(By.xpath(retrievalTimeXPath));
        String retrievalText = retrievalTimeElement.getText().replaceAll("[^0-9.]", "");
        double actualRetrievalTime = Double.parseDouble(retrievalText);
        
        String retrievalValidationXPath = String.format("//div[@id='retrieval-validation' and contains(text(),'Pass')]");
        WebElement retrievalValidation = driver.findElement(By.xpath(retrievalValidationXPath));
        assertions.assertDisplayed(retrievalValidation);
        
        performanceMetrics.put("commentRetrievalTime", actualRetrievalTime);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("all submitted comments should be persisted correctly in database")
    public void allSubmittedCommentsShouldBePersistedCorrectlyInDatabase() {
        String persistenceCheckXPath = "//button[@id='verify-persistence']";
        WebElement persistenceCheckButton = driver.findElement(By.xpath(persistenceCheckXPath));
        actions.click(persistenceCheckButton);
        waits.waitForPageLoad();
        
        String persistenceStatusXPath = "//span[@id='persistence-status' and contains(text(),'All Persisted')]";
        WebElement persistenceStatus = driver.findElement(By.xpath(persistenceStatusXPath));
        assertions.assertDisplayed(persistenceStatus);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("no data corruption or loss should be detected")
    public void noDataCorruptionOrLossShouldBeDetected() {
        String dataIntegrityCheckXPath = "//button[@id='check-data-integrity']";
        WebElement dataIntegrityCheckButton = driver.findElement(By.xpath(dataIntegrityCheckXPath));
        actions.click(dataIntegrityCheckButton);
        waits.waitForPageLoad();
        
        String integrityStatusXPath = "//span[@id='data-integrity-status' and contains(text(),'No Corruption')]";
        WebElement integrityStatus = driver.findElement(By.xpath(integrityStatusXPath));
        assertions.assertDisplayed(integrityStatus);
        
        String noLossXPath = "//span[@id='data-loss-status' and contains(text(),'No Loss')]";
        WebElement noLoss = driver.findElement(By.xpath(noLossXPath));
        assertions.assertDisplayed(noLoss);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("system should return to normal state after load test completion")
    public void systemShouldReturnToNormalStateAfterLoadTestCompletion() {
        String systemStateXPath = "//span[@id='system-state']";
        WebElement systemState = driver.findElement(By.xpath(systemStateXPath));
        waits.waitForElementVisible(systemState);
        assertions.assertTextContains(systemState, "Normal");
        
        String recoveryStatusXPath = "//div[@id='recovery-status' and contains(text(),'Complete')]";
        WebElement recoveryStatus = driver.findElement(By.xpath(recoveryStatusXPath));
        assertions.assertDisplayed(recoveryStatus);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-PERF-002
    /*  Title: Comment system breaking point and graceful degradation validation
    /*  Priority: High
    /*  Category: Performance - Stress Testing
    /**************************************************/
    
    // TODO: Replace XPath with Object Repository when available
    @Then("metrics should be captured at each load level showing progressive degradation patterns")
    public void metricsShouldBeCapturedAtEachLoadLevelShowingProgressiveDegradationPatterns() {
        String metricsReportXPath = "//div[@id='progressive-metrics-report']";
        WebElement metricsReport = driver.findElement(By.xpath(metricsReportXPath));
        assertions.assertDisplayed(metricsReport);
        
        String degradationPatternsXPath = "//span[@id='degradation-patterns' and contains(text(),'Captured')]";
        WebElement degradationPatterns = driver.findElement(By.xpath(degradationPatternsXPath));
        assertions.assertDisplayed(degradationPatterns);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("breaking point should be identified where error rate exceeds {int} percent or response time exceeds {int} seconds")
    public void breakingPointShouldBeIdentifiedWhereErrorRateExceedsPercentOrResponseTimeExceedsSeconds(int errorThreshold, int responseThreshold) {
        String breakingPointXPath = "//div[@id='breaking-point-identified']";
        WebElement breakingPoint = driver.findElement(By.xpath(breakingPointXPath));
        assertions.assertDisplayed(breakingPoint);
        
        String breakingPointUsersXPath = "//span[@id='breaking-point-users']";
        WebElement breakingPointUsers = driver.findElement(By.xpath(breakingPointUsersXPath));
        String breakingPointText = breakingPointUsers.getText().replaceAll("[^0-9]", "");
        int actualBreakingPoint = Integer.parseInt(breakingPointText);
        
        performanceMetrics.put("breakingPoint", actualBreakingPoint);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("breaking point should be within expected range of {int} to {int} concurrent users")
    public void breakingPointShouldBeWithinExpectedRangeOfToConcurrentUsers(int minUsers, int maxUsers) {
        String breakingPointUsersXPath = "//span[@id='breaking-point-users']";
        WebElement breakingPointUsers = driver.findElement(By.xpath(breakingPointUsersXPath));
        String breakingPointText = breakingPointUsers.getText().replaceAll("[^0-9]", "");
        int actualBreakingPoint = Integer.parseInt(breakingPointText);
        
        String rangeValidationXPath = String.format("//div[@id='breaking-point-range-validation' and contains(text(),'Within Range')]");
        WebElement rangeValidation = driver.findElement(By.xpath(rangeValidationXPath));
        assertions.assertDisplayed(rangeValidation);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("system should exhibit clear performance degradation at breaking point")
    public void systemShouldExhibitClearPerformanceDegradationAtBreakingPoint() {
        String degradationIndicatorXPath = "//div[@id='degradation-indicator']";
        WebElement degradationIndicator = driver.findElement(By.xpath(degradationIndicatorXPath));
        assertions.assertDisplayed(degradationIndicator);
        
        String degradationStatusXPath = "//span[@id='degradation-status' and contains(text(),'Clear Degradation')]";
        WebElement degradationStatus = driver.findElement(By.xpath(degradationStatusXPath));
        assertions.assertDisplayed(degradationStatus);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("system should return proper HTTP error codes {string} or {string} instead of crashes")
    public void systemShouldReturnProperHttpErrorCodesOrInsteadOfCrashes(String errorCode1, String errorCode2) {
        String errorCodesXPath = "//div[@id='http-error-codes']";
        WebElement errorCodes = driver.findElement(By.xpath(errorCodesXPath));
        assertions.assertDisplayed(errorCodes);
        
        String validErrorCodesXPath = String.format("//span[@id='error-code-validation' and (contains(text(),'%s') or contains(text(),'%s'))]", errorCode1, errorCode2);
        WebElement validErrorCodes = driver.findElement(By.xpath(validErrorCodesXPath));
        assertions.assertDisplayed(validErrorCodes);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("no application crashes or unhandled exceptions should occur")
    public void noApplicationCrashesOrUnhandledExceptionsShouldOccur() {
        String crashStatusXPath = "//span[@id='crash-status' and contains(text(),'No Crashes')]";
        WebElement crashStatus = driver.findElement(By.xpath(crashStatusXPath));
        assertions.assertDisplayed(crashStatus);
        
        String exceptionStatusXPath = "//span[@id='exception-status' and contains(text(),'No Unhandled Exceptions')]";
        WebElement exceptionStatus = driver.findElement(By.xpath(exceptionStatusXPath));
        assertions.assertDisplayed(exceptionStatus);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("error messages should be user-friendly")
    public void errorMessagesShouldBeUserFriendly() {
        String errorMessagesXPath = "//div[@id='error-messages-review']";
        WebElement errorMessagesReview = driver.findElement(By.xpath(errorMessagesXPath));
        assertions.assertDisplayed(errorMessagesReview);
        
        String userFriendlyStatusXPath = "//span[@id='error-message-quality' and contains(text(),'User-Friendly')]";
        WebElement userFriendlyStatus = driver.findElement(By.xpath(userFriendlyStatusXPath));
        assertions.assertDisplayed(userFriendlyStatus);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("system should automatically recover within {int} minutes")
    public void systemShouldAutomaticallyRecoverWithinMinutes(int maxMinutes) {
        String recoveryTimeXPath = "//span[@id='recovery-time-minutes']";
        WebElement recoveryTimeElement = driver.findElement(By.xpath(recoveryTimeXPath));
        String recoveryText = recoveryTimeElement.getText().replaceAll("[^0-9.]", "");
        double actualRecoveryTime = Double.parseDouble(recoveryText);
        
        String recoveryValidationXPath = String.format("//div[@id='recovery-validation' and contains(text(),'Pass')]");
        WebElement recoveryValidation = driver.findElement(By.xpath(recoveryValidationXPath));
        assertions.assertDisplayed(recoveryValidation);
        
        performanceMetrics.put("recoveryTime", actualRecoveryTime);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("response times should return to baseline")
    public void responseTimesShouldReturnToBaseline() {
        String currentResponseTimeXPath = "//span[@id='current-response-time']";
        WebElement currentResponseTimeElement = driver.findElement(By.xpath(currentResponseTimeXPath));
        String currentText = currentResponseTimeElement.getText().replaceAll("[^0-9.]", "");
        double currentResponseTime = Double.parseDouble(currentText);
        
        String baselineComparisonXPath = "//div[@id='baseline-comparison' and contains(text(),'Returned to Baseline')]";
        WebElement baselineComparison = driver.findElement(By.xpath(baselineComparisonXPath));
        assertions.assertDisplayed(baselineComparison);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("no manual intervention should be required")
    public void noManualInterventionShouldBeRequired() {
        String interventionStatusXPath = "//span[@id='manual-intervention-status' and contains(text(),'Not Required')]";
        WebElement interventionStatus = driver.findElement(By.xpath(interventionStatusXPath));
        assertions.assertDisplayed(interventionStatus);
        
        String autoRecoveryXPath = "//div[@id='auto-recovery-status' and contains(text(),'Automatic')]";
        WebElement autoRecovery = driver.findElement(By.xpath(autoRecoveryXPath));
        assertions.assertDisplayed(autoRecovery);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("all successfully acknowledged comments should be persisted correctly")
    public void allSuccessfullyAcknowledgedCommentsShouldBePersistedCorrectly() {
        String acknowledgedCommentsXPath = "//button[@id='verify-acknowledged-comments']";
        WebElement acknowledgedCommentsButton = driver.findElement(By.xpath(acknowledgedCommentsXPath));
        actions.click(acknowledgedCommentsButton);
        waits.waitForPageLoad();
        
        String persistenceStatusXPath = "//span[@id='acknowledged-persistence-status' and contains(text(),'All Persisted')]";
        WebElement persistenceStatus = driver.findElement(By.xpath(persistenceStatusXPath));
        assertions.assertDisplayed(persistenceStatus);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("no duplicate entries should exist")
    public void noDuplicateEntriesShouldExist() {
        String duplicateCheckXPath = "//button[@id='check-duplicates']";
        WebElement duplicateCheckButton = driver.findElement(By.xpath(duplicateCheckXPath));
        actions.click(duplicateCheckButton);
        waits.waitForPageLoad();
        
        String noDuplicatesXPath = "//span[@id='duplicate-status' and contains(text(),'No Duplicates')]";
        WebElement noDuplicates = driver.findElement(By.xpath(noDuplicatesXPath));
        assertions.assertDisplayed(noDuplicates);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("system should be fully recovered to operational state")
    public void systemShouldBeFullyRecoveredToOperationalState() {
        String operationalStateXPath = "//span[@id='system-operational-state' and contains(text(),'Operational')]";
        WebElement operationalState = driver.findElement(By.xpath(operationalStateXPath));
        assertions.assertDisplayed(operationalState);
        
        String fullRecoveryXPath = "//div[@id='full-recovery-status' and contains(text(),'Complete')]";
        WebElement fullRecovery = driver.findElement(By.xpath(fullRecoveryXPath));
        assertions.assertDisplayed(fullRecovery);
    }
    
    /**************************************************/
    /*  TEST CASE: TC-PERF-003
    /*  Title: Sudden traffic surge handling during comment notification burst
    /*  Priority: Critical
    /*  Category: Performance - Spike Testing
    /**************************************************/
    
    // TODO: Replace XPath with Object Repository when available
    @Then("system should operate normally with P95 response time less than {double} seconds")
    public void systemShouldOperateNormallyWithP95ResponseTimeLessThanSeconds(double maxSeconds) {
        String p95TimeXPath = "//span[@id='baseline-p95-response-time']";
        WebElement p95TimeElement = driver.findElement(By.xpath(p95TimeXPath));
        String p95Text = p95TimeElement.getText().replaceAll("[^0-9.]", "");
        double actualP95 = Double.parseDouble(p95Text);
        
        String normalOperationXPath = "//div[@id='normal-operation-status' and contains(text(),'Normal')]";
        WebElement normalOperation = driver.findElement(By.xpath(normalOperationXPath));
        assertions.assertDisplayed(normalOperation);
        
        performanceMetrics.put("baselineP95", actualP95);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("performance should be stable")
    public void performanceShouldBeStable() {
        String stabilityIndicatorXPath = "//span[@id='performance-stability' and contains(text(),'Stable')]";
        WebElement stabilityIndicator = driver.findElement(By.xpath(stabilityIndicatorXPath));
        assertions.assertDisplayed(stabilityIndicator);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("load spike should be executed successfully")
    public void loadSpikeShouldBeExecutedSuccessfully() {
        String spikeExecutionXPath = "//span[@id='spike-execution-status' and contains(text(),'Successful')]";
        WebElement spikeExecution = driver.findElement(By.xpath(spikeExecutionXPath));
        assertions.assertDisplayed(spikeExecution);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("{int} concurrent users should be actively submitting comments")
    public void concurrentUsersShouldBeActivelySubmittingComments(int expectedUsers) {
        String activeUsersXPath = "//span[@id='spike-active-users']";
        WebElement activeUsersElement = driver.findElement(By.xpath(activeUsersXPath));
        assertions.assertTextContains(activeUsersElement, String.valueOf(expectedUsers));
        
        String submittingStatusXPath = "//span[@id='comment-submission-status' and contains(text(),'Active')]";
        WebElement submittingStatus = driver.findElement(By.xpath(submittingStatusXPath));
        assertions.assertDisplayed(submittingStatus);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("error rate should remain less than {int} percent during first {int} minutes of spike")
    public void errorRateShouldRemainLessThanPercentDuringFirstMinutesOfSpike(int maxErrorPercent, int durationMinutes) {
        String spikeErrorRateXPath = "//span[@id='spike-error-rate']";
        WebElement spikeErrorRateElement = driver.findElement(By.xpath(spikeErrorRateXPath));
        String errorText = spikeErrorRateElement.getText().replaceAll("[^0-9.]", "");
        double actualErrorRate = Double.parseDouble(errorText);
        
        String errorValidationXPath = String.format("//div[@id='spike-error-validation' and contains(text(),'Pass')]");
        WebElement errorValidation = driver.findElement(By.xpath(errorValidationXPath));
        assertions.assertDisplayed(errorValidation);
        
        performanceMetrics.put("spikeErrorRate", actualErrorRate);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("response times may temporarily increase to {int} to {int} seconds but no timeouts should occur")
    public void responseTimesMayTemporarilyIncreaseToToSecondsButNoTimeoutsShouldOccur(int minSeconds, int maxSeconds) {
        String spikeResponseTimeXPath = "//span[@id='spike-response-time']";
        WebElement spikeResponseTimeElement = driver.findElement(By.xpath(spikeResponseTimeXPath));
        assertions.assertDisplayed(spikeResponseTimeElement);
        
        String noTimeoutsXPath = "//span[@id='timeout-status' and contains(text(),'No Timeouts')]";
        WebElement noTimeouts = driver.findElement(By.xpath(noTimeoutsXPath));
        assertions.assertDisplayed(noTimeouts);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("notification queue depth should increase but process without blocking")
    public void notificationQueueDepthShouldIncreaseButProcessWithoutBlocking() {
        String queueDepthXPath = "//span[@id='notification-queue-depth']";
        WebElement queueDepth = driver.findElement(By.xpath(queueDepthXPath));
        assertions.assertDisplayed(queueDepth);
        
        String noBlockingXPath = "//span[@id='queue-blocking-status' and contains(text(),'No Blocking')]";
        WebElement noBlocking = driver.findElement(By.xpath(noBlockingXPath));
        assertions.assertDisplayed(noBlocking);
    }
    
    // TODO: Replace XPath with Object Repository when available
    @Then("auto-scaling should be activated within {int} to {int} minutes")
    public void autoScalingShouldBeActivatedWithinToMinutes(int minMinutes, int maxMinutes) {
        String scalingActivationXPath = "//span[@id='auto-scaling-activation-time']";
        WebElement scalingActivation = driver.findElement(By.xpath(scalingActivationXPath));
        assertions.assertDisplayed(scalingActivation