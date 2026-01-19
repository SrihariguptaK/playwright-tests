# Manual Test Cases

## Story: As Employee, I want to view my daily schedule to plan my workday effectively
**Story ID:** story-12

### Test Case: Validate daily schedule display with valid employee login
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee has valid login credentials
- Employee has at least one shift assigned for current day and next day
- Web portal is accessible and operational
- Database contains employee schedule data
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the web portal login page | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials (username and password) | Credentials are accepted without validation errors |
| 3 | Click the Login button | Login successful and employee dashboard is displayed within 3 seconds |
| 4 | Navigate to the daily schedule page from the dashboard menu | Daily schedule page loads and displays the current date as the header |
| 5 | Verify the daily schedule content for current day | Schedule displays correct shift start time, end time, location, and role for the logged-in employee |
| 6 | Verify the current day is highlighted in the calendar | Current day is visually highlighted or marked distinctly from other days |
| 7 | Click the 'Next Day' navigation button or arrow | Schedule updates to show next day's shifts without page reload, transition is smooth |
| 8 | Verify the schedule data for next day | Next day's schedule displays with correct shift details and date header updates accordingly |
| 9 | Verify page load time | Schedule data loads within 3 seconds for each navigation action |

**Postconditions:**
- Employee remains logged in
- Daily schedule page is displayed with next day's data
- No errors are logged in the system
- Session remains active

---

### Test Case: Verify access restriction to schedules of other employees
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee is logged into the web portal with valid credentials
- Employee knows or can construct URL pattern for schedule access
- Another employee's ID exists in the system
- OAuth 2.0 authentication is properly configured
- Role-based access control is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the web portal with valid employee credentials | Login successful and dashboard is displayed |
| 2 | Navigate to own daily schedule page and note the URL structure | Daily schedule page loads with URL containing employee ID parameter |
| 3 | Manually modify the URL to include another employee's ID (e.g., change employeeId parameter) | URL is modified in the browser address bar |
| 4 | Press Enter to attempt accessing the modified URL | Access is denied and an appropriate error message is displayed (e.g., 'Access Denied: You do not have permission to view this schedule' or HTTP 403 Forbidden) |
| 5 | Verify that no schedule data from the other employee is visible | No shift details, times, or locations from another employee's schedule are displayed |
| 6 | Navigate back to own schedule using the navigation menu | Own daily schedule page loads successfully |
| 7 | Verify own schedule displays correctly | Schedule shows correct shift details for the logged-in employee with accurate times and locations |

**Postconditions:**
- Employee can only access their own schedule
- Security logs record the unauthorized access attempt
- Employee session remains active and valid
- No data breach has occurred

---

### Test Case: Test responsive design on mobile devices
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee has valid login credentials
- Mobile device (smartphone or tablet) is available for testing
- Mobile browser (Chrome, Safari, or Firefox) is installed
- Employee has shifts assigned for current and adjacent days
- Network connection is available on mobile device

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open mobile browser on the device | Mobile browser launches successfully |
| 2 | Navigate to the web portal URL | Login page loads and displays correctly on mobile screen |
| 3 | Enter valid employee credentials and log in | Login successful and mobile-optimized dashboard is displayed |
| 4 | Navigate to the daily schedule page from the menu | Daily schedule page loads on mobile device |
| 5 | Verify the schedule layout adapts to mobile screen size | Schedule displays in a mobile-friendly format with readable text, properly sized buttons, and no horizontal scrolling required |
| 6 | Verify shift details are clearly visible (start time, end time, location, role) | All shift information is legible and properly formatted for mobile viewing |
| 7 | Tap the 'Next Day' navigation control | Navigation control responds to touch input and schedule updates to next day |
| 8 | Verify next day's schedule displays correctly on mobile | Next day's schedule loads with proper mobile layout and all details are visible |
| 9 | Tap the 'Previous Day' navigation control | Schedule navigates back to previous day smoothly |
| 10 | Test navigation controls function properly with touch gestures | All navigation buttons are easily tappable, respond correctly, and have appropriate touch target sizes |
| 11 | Rotate device to landscape orientation | Schedule layout adjusts appropriately to landscape mode maintaining readability |

**Postconditions:**
- Employee remains logged in on mobile device
- Schedule page is fully functional on mobile
- No layout or rendering issues are present
- Navigation controls remain accessible

---

## Story: As Employee, I want to view my weekly schedule to plan my workweek efficiently
**Story ID:** story-13

### Test Case: Validate weekly schedule display with valid employee login
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee has valid login credentials
- Employee has multiple shifts assigned across current week and next week
- Web portal is accessible and operational
- Database contains employee weekly schedule data
- Network connection is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the web portal login page | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials (username and password) | Credentials are accepted without validation errors |
| 3 | Click the Login button | Login successful and employee dashboard is displayed within 3 seconds |
| 4 | Navigate to the weekly schedule page from the dashboard menu | Weekly schedule page loads and displays a calendar grid view |
| 5 | Verify the weekly schedule displays the current week | Calendar shows current week with dates clearly labeled and current week is highlighted |
| 6 | Verify all shifts for the week are displayed in the calendar grid | Each assigned shift appears on the correct day with shift start time, end time, location, and role information |
| 7 | Verify the calendar grid layout is clear and organized | Days of the week are clearly labeled, dates are visible, and shifts are positioned correctly within their respective day cells |
| 8 | Verify page load time for weekly schedule | Weekly schedule data loads within 4 seconds |
| 9 | Click the 'Next Week' navigation button or arrow | Calendar updates to display next week's schedule without full page reload, transition is smooth |
| 10 | Verify the schedule data for next week | Next week's schedule displays with all assigned shifts showing correct details, dates update accordingly |
| 11 | Verify navigation occurs without errors | No error messages appear, data loads within 4 seconds, and calendar remains functional |

**Postconditions:**
- Employee remains logged in
- Weekly schedule page displays next week's data
- No errors are logged in the system
- Session remains active
- Calendar grid maintains proper formatting

---

### Test Case: Verify access restriction to other employees' weekly schedules
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee is logged into the web portal with valid credentials
- Employee can access URL structure for weekly schedule
- Another employee's ID exists in the system
- OAuth 2.0 authentication is properly configured
- Role-based access control is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the web portal with valid employee credentials | Login successful and dashboard is displayed |
| 2 | Navigate to own weekly schedule page and observe the URL structure | Weekly schedule page loads with URL containing employee ID or identifier parameter |
| 3 | Note the current employee ID in the URL | Employee ID parameter is visible in the browser address bar |
| 4 | Manually modify the URL to include another employee's ID (e.g., change employeeId parameter to a different valid employee ID) | URL is modified in the browser address bar with different employee ID |
| 5 | Press Enter to attempt accessing the modified URL | Access is denied and an appropriate error message is displayed (e.g., 'Access Denied: You do not have permission to view this schedule' or HTTP 403 Forbidden) |
| 6 | Verify that no weekly schedule data from the other employee is visible | No shift details, calendar data, or any information from another employee's weekly schedule is displayed |
| 7 | Verify the error message is user-friendly and informative | Error message clearly indicates access restriction without exposing sensitive system information |
| 8 | Navigate back to own weekly schedule using the navigation menu | Own weekly schedule page loads successfully |
| 9 | Verify own weekly schedule displays correctly | Weekly schedule shows correct shifts for the logged-in employee with accurate times, locations, and calendar layout |

**Postconditions:**
- Employee can only access their own weekly schedule
- Security logs record the unauthorized access attempt
- Employee session remains active and valid
- No data breach has occurred
- System security controls are functioning properly

---

### Test Case: Test weekly schedule UI responsiveness on mobile
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** Medium
- **Estimated Time:** 12 mins

**Preconditions:**
- Employee has valid login credentials
- Mobile device (smartphone or tablet) is available for testing
- Mobile browser (Chrome, Safari, or Firefox) is installed
- Employee has multiple shifts assigned across current and adjacent weeks
- Network connection is available on mobile device

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open mobile browser on the device | Mobile browser launches successfully |
| 2 | Navigate to the web portal URL | Login page loads and displays correctly on mobile screen |
| 3 | Enter valid employee credentials and log in | Login successful and mobile-optimized dashboard is displayed |
| 4 | Navigate to the weekly schedule page from the menu | Weekly schedule page loads on mobile device |
| 5 | Verify the calendar grid layout adapts to mobile screen size | Calendar displays in a mobile-friendly format, either as a compressed grid or alternative mobile view, with no horizontal scrolling required |
| 6 | Verify all days of the week are visible and labeled | Day labels are readable and properly formatted for mobile viewing |
| 7 | Verify shift details are clearly visible within the calendar | Shift times, locations, and roles are legible on mobile screen, text size is appropriate |
| 8 | Verify the current week is highlighted appropriately | Current week indicator is visible and distinguishable on mobile display |
| 9 | Tap the 'Next Week' navigation control | Navigation control responds to touch input and calendar updates to display next week |
| 10 | Verify next week's schedule displays correctly on mobile | Next week's calendar loads with proper mobile layout, all shifts are visible and formatted correctly |
| 11 | Tap the 'Previous Week' navigation control | Calendar navigates back to previous week smoothly without errors |
| 12 | Test navigation controls function properly with touch gestures | All navigation buttons are easily tappable, respond correctly to touch, and have appropriate touch target sizes (minimum 44x44 pixels) |
| 13 | Scroll through the calendar if necessary | Scrolling is smooth and content remains properly aligned |
| 14 | Rotate device to landscape orientation | Calendar layout adjusts appropriately to landscape mode, maintaining readability and functionality |
| 15 | Rotate device back to portrait orientation | Calendar returns to portrait layout without data loss or rendering issues |

**Postconditions:**
- Employee remains logged in on mobile device
- Weekly schedule page is fully functional on mobile
- No layout or rendering issues are present
- Navigation controls remain accessible and functional
- Calendar data is intact and accurate

---

## Story: As Employee, I want to navigate between different schedule views to choose the most useful format
**Story ID:** story-18

### Test Case: Validate schedule view switching
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee account exists in the system with valid credentials
- Employee has assigned shifts in the schedule
- Application is accessible and running
- Browser supports required features (JavaScript enabled)
- Employee is not currently logged in

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the application login page | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials and click Login button | Employee is successfully authenticated and redirected to the dashboard or schedule page |
| 3 | Navigate to the schedule page if not already there | Schedule page loads with default view (daily, weekly, or monthly) and navigation controls are visible |
| 4 | Note the current schedule view format displayed | Current view format is clearly identifiable (daily, weekly, or monthly) |
| 5 | Click on the weekly view navigation control button | Schedule updates dynamically to weekly format showing 7 days in a grid or list layout without full page reload within 3 seconds |
| 6 | Verify that all shifts for the week are displayed with proper formatting | Weekly schedule shows all assigned shifts across 7 days with clear date headers and shift information |
| 7 | Click on the Logout button or menu option | Employee is logged out successfully and redirected to login page or public landing page |
| 8 | Enter the same employee credentials and click Login button | Employee is successfully authenticated and redirected to the schedule page |
| 9 | Observe the default schedule view displayed upon login | Weekly view is automatically restored as the default view, showing the same format as previously selected |
| 10 | Verify that the weekly view navigation control appears selected or highlighted | Weekly view button/control shows active state indicating it is the current view |

**Postconditions:**
- Employee remains logged in with weekly view active
- View preference is persisted in user session/profile
- Schedule data is displayed correctly in weekly format
- No errors are logged in browser console or application logs

---

### Test Case: Verify UI responsiveness of view navigation controls
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee account exists with valid credentials
- Employee has assigned shifts in the schedule
- Mobile device or mobile emulator is available for testing
- Application supports responsive design
- Employee is not currently logged in

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open the application on a mobile device (smartphone with screen width 375px or similar) or use browser developer tools to emulate mobile device | Application loads in mobile-responsive mode with appropriate viewport settings |
| 2 | Navigate to the login page on the mobile device | Login page is displayed with mobile-optimized layout, fields are properly sized and accessible |
| 3 | Enter valid employee credentials using mobile keyboard and tap Login button | Employee is successfully authenticated and redirected to mobile-optimized schedule page |
| 4 | Locate the schedule view navigation controls on the mobile interface | Navigation controls (daily, weekly, monthly buttons or dropdown) are visible, properly sized for touch interaction (minimum 44x44px touch target), and positioned appropriately |
| 5 | Verify the layout of navigation controls (check if they are horizontal buttons, dropdown menu, or tabs) | Navigation controls layout is optimized for mobile screen size without overlapping or requiring horizontal scroll |
| 6 | Tap on the weekly view navigation control | Control responds to touch input immediately, schedule updates to weekly view within 3 seconds, and layout adjusts correctly to fit mobile screen without horizontal scrolling |
| 7 | Verify that the weekly schedule is readable and properly formatted on mobile screen | Weekly schedule displays with appropriate font sizes, spacing, and column widths optimized for mobile viewing |
| 8 | Tap on the monthly view navigation control | Schedule updates to monthly view within 3 seconds with calendar grid or list properly sized for mobile screen |
| 9 | Tap on the daily view navigation control | Schedule updates to daily view within 3 seconds showing single day schedule optimized for mobile display |
| 10 | Rotate the mobile device to landscape orientation | Layout adjusts responsively to landscape mode, navigation controls remain accessible and usable |
| 11 | Rotate back to portrait orientation | Layout adjusts back to portrait mode smoothly, all controls remain functional |

**Postconditions:**
- Employee remains logged in on mobile device
- Schedule view is displayed correctly in mobile-responsive format
- Navigation controls remain functional and accessible
- No layout issues or horizontal scrolling present

---

## Story: As Employee, I want to view shift details including location and role to understand my assignments fully
**Story ID:** story-19

### Test Case: Validate display of shift details on hover or selection
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 7 mins

**Preconditions:**
- Employee account exists with valid credentials
- Employee has at least one assigned shift with complete details (location, role, start time, end time)
- Employee is logged into the application
- Schedule page is accessible and displays shifts
- Browser supports hover interactions or touch events for mobile

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule page | Schedule page loads successfully displaying employee's assigned shifts in the current view (daily, weekly, or monthly) |
| 2 | Identify a shift displayed in the schedule view | At least one shift is visible with basic information (date and time) |
| 3 | Hover the mouse cursor over the identified shift (on desktop) or tap and hold on mobile | Shift details tooltip or popup appears within 2 seconds displaying complete information including shift start time, end time, location, and role |
| 4 | Verify that all required shift details are present in the displayed information | Tooltip/popup shows: Shift start time, Shift end time, Location name/address, Role/position title, and information is clearly formatted and readable |
| 5 | Move the mouse cursor away from the shift (or release touch on mobile) | Tooltip or popup disappears, returning to normal schedule view |
| 6 | Click or tap directly on the same shift | Detailed shift information is displayed in an expanded view, modal, or side panel showing all shift details clearly |
| 7 | Verify the detailed shift information display includes all required fields | Detailed view shows: Shift start time, Shift end time, Location (full address or name), Role/position, and any additional relevant information formatted in a clear, readable layout |
| 8 | Verify that the shift details loaded within the performance requirement | Shift details appeared within 2 seconds of the hover or selection action |
| 9 | Close the detailed shift information view (click close button, click outside modal, or press ESC key) | Detailed view closes and schedule returns to normal display state |
| 10 | Test the same interaction with a different shift in the schedule | Hover and selection interactions work consistently, displaying correct details for the selected shift within 2 seconds |

**Postconditions:**
- Employee remains logged in
- Schedule view returns to normal state
- No shift details remain displayed
- All shift information was displayed accurately
- No errors are present in browser console

---

### Test Case: Verify access control for shift details
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- API endpoint GET /api/schedules/details?shiftId={id} exists and is protected
- At least one valid shift ID exists in the system
- Testing tool (Postman, curl, or browser developer tools) is available
- No user is currently authenticated in the testing session

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open API testing tool (Postman, curl, or browser developer tools) | Testing tool is ready to make HTTP requests |
| 2 | Obtain a valid shift ID from the system (from database or previous authenticated request) | Valid shift ID is available for testing (e.g., shiftId=12345) |
| 3 | Construct a GET request to /api/schedules/details?shiftId={validShiftId} without including any authentication token or session cookie | Request is properly formatted with the correct endpoint and shift ID parameter |
| 4 | Send the unauthenticated GET request to the shift details API endpoint | API responds with HTTP status code 401 (Unauthorized) or 403 (Forbidden) |
| 5 | Verify the error response body contains appropriate error message | Response body includes error message such as 'Authentication required', 'Unauthorized access', or 'Access denied' in JSON format |
| 6 | Verify that no shift details data is included in the error response | Response does not contain any sensitive shift information (location, role, times, employee data) |
| 7 | Attempt to access the shift details API with an invalid or expired authentication token | API responds with HTTP status code 401 (Unauthorized) or 403 (Forbidden) with appropriate error message |
| 8 | Verify that the API does not expose shift details through error messages or headers | No shift information is leaked through error messages, headers, or response metadata |
| 9 | Log the security test results including response codes and messages | All unauthenticated and unauthorized access attempts were properly rejected with appropriate error codes |

**Postconditions:**
- API endpoint remains secure and protected
- No shift details were exposed to unauthenticated requests
- Appropriate error responses were returned
- Security logs may contain failed access attempts (if logging is implemented)

---

## Story: As Employee, I want to receive confirmation when my schedule is successfully loaded to ensure data accuracy
**Story ID:** story-20

### Test Case: Validate confirmation message on schedule load
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 3 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has an active schedule assigned
- Network connectivity is stable
- Browser is supported and up to date

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule view page by clicking on 'My Schedule' or equivalent menu option | Schedule view page begins loading |
| 2 | Wait for the schedule data to load completely | Schedule data is displayed on the screen and a clear confirmation message appears (e.g., 'Schedule loaded successfully' or success icon with message) |
| 3 | Verify the confirmation message is visible and does not obstruct schedule content or navigation elements | Confirmation message is clearly visible, positioned appropriately (e.g., top of page or corner), and does not block any schedule information or navigation buttons |
| 4 | Wait for 5 seconds without any user interaction | Confirmation message automatically disappears after exactly 5 seconds |
| 5 | Verify schedule content remains fully visible and accessible after message disappears | Schedule view is fully functional and all content is accessible without any visual artifacts from the disappeared message |

**Postconditions:**
- Schedule view is fully loaded and displayed
- Confirmation message has disappeared
- Employee can interact with schedule normally
- No error messages are present

---

## Story: As Employee, I want to report issues with my schedule view to get timely support
**Story ID:** story-21

### Test Case: Validate successful issue report submission
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee is authenticated and logged into the system
- Employee is on the schedule page
- Support ticketing system is operational
- Network connectivity is available
- 'Report Issue' button is visible on the schedule page

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Locate and click the 'Report Issue' button on the schedule page | Issue report form opens and is displayed with all required fields visible (e.g., Issue Description, Category, Priority) and optional fields (e.g., Screenshot upload) |
| 2 | Verify all form fields are present including required field indicators (asterisks or labels) | Form displays clearly marked required fields and optional fields, with appropriate input types (text area, dropdowns, file upload) |
| 3 | Fill in all required fields with valid test data (e.g., Issue Description: 'Schedule not displaying correct shift times') | All required fields accept input without errors, text is visible and properly formatted |
| 4 | Optionally attach a screenshot file (PNG or JPG format, under size limit) | Screenshot uploads successfully, file name is displayed, and no error messages appear |
| 5 | Click the 'Submit' button on the issue report form | Form is submitted, loading indicator appears briefly, and a confirmation message is displayed (e.g., 'Your issue has been reported successfully. Ticket ID: #12345') |
| 6 | Verify the confirmation message includes relevant details such as ticket ID or reference number | Confirmation message contains ticket ID, timestamp, and acknowledgment that support team has been notified |
| 7 | Close the confirmation message or form | User is returned to the schedule page, form is closed, and schedule view remains functional |

**Postconditions:**
- Issue report is successfully submitted to support system
- Employee receives confirmation with ticket ID
- Report is logged with employee ID and timestamp in the system
- Support team receives notification of the new issue
- Employee is returned to schedule page

---

### Test Case: Verify form validation for missing required fields
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Employee is authenticated and logged into the system
- Employee is on the schedule page
- 'Report Issue' button is accessible
- Issue report form can be opened

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Click the 'Report Issue' button on the schedule page | Issue report form opens and displays with all required and optional fields |
| 2 | Leave all required fields empty (do not enter any data in fields marked as required) | Required fields remain empty and show no validation errors yet |
| 3 | Click the 'Submit' button without filling any required fields | Form submission is blocked and validation error messages are displayed next to each empty required field (e.g., 'Issue Description is required', 'Category is required') |
| 4 | Verify that validation error messages are clearly visible and indicate which fields need to be completed | Error messages are displayed in red or highlighted color, positioned near the respective fields, and provide clear guidance on what is required |
| 5 | Verify that the form remains open and no data is submitted to the support system | Form stays open with all fields still editable, no confirmation message appears, and no ticket is created in the support system |
| 6 | Fill in only one required field and attempt to submit again | Submission is still blocked, validation errors are displayed only for the remaining empty required fields, and the filled field shows no error |
| 7 | Fill in all remaining required fields with valid data and submit the form | Form validates successfully, submission proceeds, and confirmation message is displayed |

**Postconditions:**
- Form validation prevents submission of incomplete reports
- Clear error messages guide employee to complete required fields
- No invalid or incomplete reports are sent to support system
- Employee can successfully submit after correcting validation errors

---

