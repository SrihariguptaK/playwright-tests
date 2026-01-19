# Manual Test Cases

## Story: As Employee, I want to view my daily work schedule to plan my workday effectively
**Story ID:** story-12

### Test Case: Validate daily schedule display with valid employee and date
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee account exists in the system with valid credentials
- Employee has at least one shift scheduled for today and previous day
- Scheduling portal is accessible and operational
- Test data includes shift times, locations, and role information
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduling portal login page using a web browser | Login page is displayed with username and password fields |
| 2 | Enter valid employee credentials (username and password) and click 'Login' button | Employee is successfully authenticated and redirected to the dashboard within 2 seconds |
| 3 | Verify that the dashboard is displayed with navigation options | Dashboard is displayed showing menu options including 'Daily View' and 'Weekly View' |
| 4 | Click on 'Daily View' option from the navigation menu | System navigates to the daily schedule view and displays today's date as the default selected date |
| 5 | Review the displayed schedule information for today | Schedule for today is displayed showing shift start time, end time, location, and role assignment. Current day is highlighted for easy recognition |
| 6 | Verify that all shift details are accurate and match the expected schedule data | All shift information is correct, complete, and clearly formatted |
| 7 | Click on the 'Previous Day' navigation button or arrow | System loads and displays the schedule for the previous day within 2 seconds |
| 8 | Verify the previous day's schedule details | Schedule for previous day is displayed correctly with accurate shift times, location, and role information |
| 9 | Click on the 'Next Day' navigation button to return to today | System navigates back to today's schedule and displays it correctly |

**Postconditions:**
- Employee remains logged into the system
- Daily schedule view is displayed
- No errors are logged in the system
- Session remains active

---

### Test Case: Verify access restriction to other employees' schedules
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Two employee accounts exist in the system (Employee A and Employee B)
- Employee A is logged into the scheduling portal
- Employee B has schedule data available in the system
- Role-based access control is configured and active
- OAuth2 authentication is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the scheduling portal as Employee A using valid credentials | Employee A is successfully authenticated and dashboard is displayed |
| 2 | Navigate to the daily schedule view for Employee A | Employee A's daily schedule is displayed correctly |
| 3 | Note the current URL structure in the browser address bar | URL contains Employee A's employee ID parameter (e.g., /api/schedules/daily?employeeId=A&date=today) |
| 4 | Manually modify the URL by changing the employeeId parameter to Employee B's ID | URL is updated in the address bar |
| 5 | Press Enter to attempt to load Employee B's schedule | Access is denied and an appropriate error message is displayed (e.g., 'Access Denied: You do not have permission to view this schedule' or HTTP 403 Forbidden) |
| 6 | Verify that no schedule data for Employee B is visible on the screen | No unauthorized schedule information is displayed to Employee A |
| 7 | Navigate back to Employee A's own daily schedule using the navigation menu | System redirects to Employee A's schedule view |
| 8 | Verify that Employee A's schedule is displayed correctly | Schedule is displayed without errors, showing correct shift details for Employee A |

**Postconditions:**
- Employee A remains logged in with access only to their own schedule
- Security logs record the unauthorized access attempt
- No data breach occurred
- System maintains proper access control

---

### Test Case: Test responsive design on mobile devices
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee account exists with valid credentials
- Employee has schedule data for today and tomorrow
- Mobile device (smartphone or tablet) is available for testing
- Mobile device has internet connectivity
- Scheduling portal supports responsive design
- Mobile browser is up to date

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open a mobile web browser on the mobile device (e.g., Chrome, Safari) | Mobile browser launches successfully |
| 2 | Navigate to the scheduling portal URL | Login page loads and displays correctly on the mobile screen with responsive layout |
| 3 | Enter valid employee credentials and tap 'Login' button | Employee is authenticated and dashboard is displayed in mobile-optimized format |
| 4 | Tap on 'Daily View' option from the mobile navigation menu | Daily schedule view loads and displays correctly on the mobile screen |
| 5 | Verify the layout and readability of the schedule on the mobile device | Schedule displays correctly with no layout issues, text is readable, shift details are clearly visible, and no horizontal scrolling is required |
| 6 | Check that all schedule elements (shift times, location, role) are properly formatted for mobile view | All schedule information is properly sized and positioned for mobile display with appropriate touch targets |
| 7 | Tap on the 'Next Day' navigation button | Navigation works smoothly without lag or errors |
| 8 | Verify that the schedule updates to show the next day's information | Schedule updates accordingly and displays tomorrow's shift details correctly in mobile format |
| 9 | Tap on the 'Previous Day' navigation button | Navigation responds immediately and smoothly |
| 10 | Verify that the schedule returns to today's view | Today's schedule is displayed correctly with all information visible and properly formatted |
| 11 | Rotate the mobile device to landscape orientation | Schedule view adjusts responsively to landscape mode without breaking layout |
| 12 | Rotate back to portrait orientation | Schedule view adjusts back to portrait mode correctly |

**Postconditions:**
- Employee remains logged in on mobile device
- Daily schedule view is functional on mobile
- No layout or rendering errors occurred
- Mobile session remains active

---

## Story: As Employee, I want to view my weekly work schedule to plan my week ahead
**Story ID:** story-13

### Test Case: Validate weekly schedule display with valid employee and week
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee account exists in the system with valid credentials
- Employee has shifts scheduled for current week and next week
- Scheduling portal is accessible and operational
- Test data includes multiple shifts across the week with times, locations, and roles
- Network connectivity is stable

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the scheduling portal login page using a web browser | Login page is displayed with username and password input fields |
| 2 | Enter valid employee credentials (username and password) and click 'Login' button | Employee is successfully authenticated and redirected to the dashboard within 3 seconds |
| 3 | Verify that the dashboard is displayed with available navigation options | Dashboard is displayed showing menu options including 'Daily View' and 'Weekly View' |
| 4 | Click on 'Weekly View' option from the navigation menu | System navigates to the weekly schedule view and displays the current week by default |
| 5 | Verify that the weekly schedule is displayed in calendar format | Schedule for the current week is displayed in a calendar layout showing all seven days (or work days) of the week |
| 6 | Review all shifts displayed for the current week | All shifts for the week are shown with correct shift start times, end times, locations, and role assignments. Current week is highlighted for easy recognition |
| 7 | Verify that each day's shifts are clearly organized and readable | Shifts are properly organized by day with clear visual separation and all details are accurate |
| 8 | Click on the 'Next Week' navigation button or arrow | System loads and displays the schedule for the next week within 3 seconds |
| 9 | Verify the next week's schedule details | Schedule for next week is displayed correctly with accurate shift information for all scheduled days |
| 10 | Verify that the week indicator updates to show the correct week range | Week header or indicator shows the correct date range for next week (e.g., 'Week of Jan 15-21, 2024') |
| 11 | Click on the 'Previous Week' navigation button to return to current week | System navigates back to the current week and displays the schedule correctly |

**Postconditions:**
- Employee remains logged into the system
- Weekly schedule view is displayed
- No errors are logged in the system
- Session remains active

---

### Test Case: Verify access restriction to other employees' weekly schedules
- **ID:** tc-005
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 6 mins

**Preconditions:**
- Two employee accounts exist in the system (Employee A and Employee B)
- Employee A is logged into the scheduling portal
- Employee B has weekly schedule data available in the system
- Role-based access control is configured and active
- OAuth2 authentication is enabled

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Log into the scheduling portal as Employee A using valid credentials | Employee A is successfully authenticated and dashboard is displayed |
| 2 | Navigate to the weekly schedule view for Employee A | Employee A's weekly schedule is displayed correctly in calendar format |
| 3 | Note the current URL structure in the browser address bar | URL contains Employee A's employee ID parameter (e.g., /api/schedules/weekly?employeeId=A&weekStart=2024-01-15) |
| 4 | Manually modify the URL by changing the employeeId parameter to Employee B's ID while keeping the same week | URL is updated in the address bar with Employee B's ID |
| 5 | Press Enter to attempt to load Employee B's weekly schedule | Access is denied and an appropriate error message is displayed (e.g., 'Access Denied: You do not have permission to view this schedule' or HTTP 403 Forbidden) |
| 6 | Verify that no schedule data for Employee B is visible on the screen | No unauthorized weekly schedule information is displayed to Employee A |
| 7 | Navigate back to Employee A's own weekly schedule using the navigation menu | System redirects to Employee A's weekly schedule view |
| 8 | Verify that Employee A's weekly schedule is displayed correctly | Schedule is displayed without errors, showing correct shift details for Employee A across the week |

**Postconditions:**
- Employee A remains logged in with access only to their own schedule
- Security logs record the unauthorized access attempt
- No data breach occurred
- System maintains proper access control

---

### Test Case: Test weekly schedule responsiveness on mobile devices
- **ID:** tc-006
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Employee account exists with valid credentials
- Employee has schedule data for current week and next week
- Mobile device (smartphone or tablet) is available for testing
- Mobile device has internet connectivity
- Scheduling portal supports responsive design for weekly view
- Mobile browser is up to date

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open a mobile web browser on the mobile device (e.g., Chrome, Safari) | Mobile browser launches successfully |
| 2 | Navigate to the scheduling portal URL | Login page loads and displays correctly on the mobile screen with responsive layout |
| 3 | Enter valid employee credentials and tap 'Login' button | Employee is authenticated and dashboard is displayed in mobile-optimized format |
| 4 | Tap on 'Weekly View' option from the mobile navigation menu | Weekly schedule view loads and displays correctly on the mobile screen |
| 5 | Verify the layout and readability of the weekly calendar on the mobile device | Weekly schedule displays correctly with no layout issues, calendar format is adapted for mobile view, text is readable, and all days of the week are visible |
| 6 | Check that all schedule elements (days, shift times, locations, roles) are properly formatted for mobile view | All schedule information is properly sized and positioned for mobile display with appropriate touch targets and no overlapping elements |
| 7 | Scroll through the weekly calendar to view all shifts | Scrolling works smoothly and all shifts for the week are accessible and readable |
| 8 | Tap on the 'Next Week' navigation button | Navigation works smoothly without lag or errors |
| 9 | Verify that the schedule updates to show the next week's information | Schedule updates accordingly and displays next week's shifts correctly in mobile-optimized calendar format |
| 10 | Verify that the week indicator updates correctly | Week header shows the correct date range for next week |
| 11 | Tap on the 'Previous Week' navigation button | Navigation responds immediately and smoothly |
| 12 | Verify that the schedule returns to the current week's view | Current week's schedule is displayed correctly with all information visible and properly formatted |
| 13 | Rotate the mobile device to landscape orientation | Weekly schedule view adjusts responsively to landscape mode without breaking layout, calendar remains readable |
| 14 | Rotate back to portrait orientation | Weekly schedule view adjusts back to portrait mode correctly with proper formatting |

**Postconditions:**
- Employee remains logged in on mobile device
- Weekly schedule view is functional on mobile
- No layout or rendering errors occurred
- Mobile session remains active

---

## Story: As Employee, I want to navigate between past and future schedules to review my work history and upcoming shifts
**Story ID:** story-18

### Test Case: Validate schedule navigation between dates
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 8 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has access to the schedule interface
- Schedule data exists for past, current, and future dates
- Employee is viewing the current schedule page
- Navigation controls (Next Day, Previous Day, Next Week, Previous Week buttons) are visible

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Verify the current date is displayed on the schedule interface | Current date is clearly shown in the schedule header |
| 2 | Note the shifts displayed for the current day | Current day's shifts are visible with shift times, locations, and details |
| 3 | Click the 'Next Day' button | Schedule updates to display the next day's shifts within 2 seconds, date header updates to show next day's date, and shifts for the next day are displayed correctly |
| 4 | Verify the schedule content has changed to the next day | Different shifts are displayed corresponding to the next day, and the date indicator reflects the new date |
| 5 | Click the 'Previous Week' button | Schedule updates to display the previous week's shifts within 2 seconds, date range updates to show the previous week, and all shifts for that week are displayed correctly |
| 6 | Verify the schedule content has changed to the previous week | Shifts from the previous week are displayed with correct dates, times, and details |
| 7 | Click the 'Next Week' button twice to navigate forward | Schedule advances two weeks forward, displaying future shifts accurately with updated date range |
| 8 | Click the 'Previous Day' button | Schedule updates to display the previous day's shifts within 2 seconds, date updates accordingly, and correct shifts are shown |

**Postconditions:**
- Employee remains logged in
- Schedule interface is still functional
- Navigation controls remain available for further use
- No errors are displayed on the interface
- System maintains session state

---

### Test Case: Verify filter persistence during navigation
- **ID:** tc-002
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 10 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has access to the schedule interface
- Schedule data exists with multiple shift types (e.g., Morning, Evening, Night)
- Employee is viewing the current schedule page
- Filter controls are visible and functional
- Navigation controls are visible and functional

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Verify the schedule displays all shift types without any filters applied | All shifts are visible including Morning, Evening, Night, and other shift types |
| 2 | Locate and click on the shift type filter dropdown or control | Filter options are displayed showing available shift types (Morning, Evening, Night, etc.) |
| 3 | Select 'Morning' shift type from the filter options | Schedule updates to display only Morning shifts, other shift types are hidden, and filter indicator shows 'Morning' is selected |
| 4 | Verify only Morning shifts are displayed on the current schedule | Only shifts labeled as 'Morning' are visible, and the count of displayed shifts matches the number of Morning shifts |
| 5 | Click the 'Next Day' button to navigate to the next day | Schedule updates to the next day within 2 seconds, Morning filter remains applied (indicated in filter control), and only Morning shifts for the next day are displayed |
| 6 | Verify the filter is still active and only Morning shifts are shown for the new date | Filter indicator still shows 'Morning' selected, only Morning shifts are visible, and Evening/Night shifts are not displayed |
| 7 | Click the 'Next Week' button to navigate to the next week | Schedule updates to the next week within 2 seconds, Morning filter remains applied, and only Morning shifts for the next week are displayed |
| 8 | Verify the filter persistence across week navigation | Filter indicator continues to show 'Morning' selected, only Morning shifts are visible for the entire week, and filter has not been reset |
| 9 | Click the 'Previous Day' button to navigate backward | Schedule updates to the previous day, Morning filter remains applied, and only Morning shifts are displayed |
| 10 | Clear the filter by deselecting 'Morning' or clicking 'Clear Filter' | All shift types are now displayed for the current date, and filter indicator shows no active filters |

**Postconditions:**
- Employee remains logged in
- Schedule interface is functional
- Filter can be reapplied or modified
- Navigation controls remain functional
- No errors are displayed
- System state is consistent

---

## Story: As Employee, I want the schedule interface to be responsive to use on mobile devices for convenience
**Story ID:** story-19

### Test Case: Validate responsive layout on various screen sizes
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 15 mins

**Preconditions:**
- Employee has valid login credentials
- Schedule data is available in the system
- Test devices or browser developer tools are available for testing (desktop, tablet, mobile)
- Internet connection is stable
- Browsers are updated to latest versions (Chrome, Safari, Firefox, Edge)

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Open a desktop browser (Chrome, Firefox, Safari, or Edge) and navigate to the schedule interface login page | Login page loads successfully and displays correctly on desktop screen |
| 2 | Log in with valid employee credentials on desktop browser | Login is successful and schedule interface is displayed |
| 3 | Verify the desktop layout displays all schedule features including navigation controls, filters, search, and full schedule grid | All features are visible and properly arranged, schedule grid shows multiple columns, navigation controls are clearly visible, filters and search are accessible, and layout utilizes full screen width appropriately |
| 4 | Verify all interactive elements (buttons, dropdowns, links) are clickable and properly sized for desktop use | All controls are easily clickable with mouse, hover states work correctly, and elements are appropriately spaced |
| 5 | Open a tablet device (iPad, Android tablet) or resize browser window to tablet dimensions (768px - 1024px width) | Browser window resizes or tablet browser opens successfully |
| 6 | Navigate to the schedule interface and log in on tablet | Login page is responsive and usable on tablet, login is successful, and schedule interface loads |
| 7 | Verify the tablet layout adjusts appropriately with readable text, accessible controls, and optimized schedule grid | Layout adapts to tablet screen size, schedule grid may show fewer columns but remains readable, navigation controls are touch-friendly and properly sized, filters and search remain accessible, and no horizontal scrolling is required for main content |
| 8 | Test scrolling behavior on tablet view | Vertical scrolling works smoothly, content is not cut off, and headers remain visible or accessible during scroll |
| 9 | Open a mobile device (iPhone, Android phone) or resize browser window to mobile dimensions (320px - 480px width) | Browser window resizes or mobile browser opens successfully |
| 10 | Navigate to the schedule interface and log in on mobile device | Login page is fully responsive on mobile, all form fields are accessible, login is successful, and schedule interface loads within 3 seconds |
| 11 | Verify the mobile layout is optimized for small screens with stacked or collapsed elements, large touch targets, and readable text without zooming | Layout is single-column or optimized for narrow screens, schedule displays in mobile-friendly format (list view or simplified grid), navigation controls are large enough for touch (minimum 44x44px), filters may be in a collapsible menu or drawer, text is readable without pinch-to-zoom (minimum 16px font), and no content is cut off or requires horizontal scrolling |
| 12 | Test navigation between different screen orientations on mobile (portrait and landscape) | Layout adjusts smoothly when rotating device, all features remain accessible in both orientations, and no layout breaks occur |
| 13 | Verify page load time on mobile device or simulated mobile network | Schedule interface loads within 3 seconds on mobile network, and performance meets defined SLAs |

**Postconditions:**
- Employee can successfully log out from any device
- No layout breaks or errors are present
- Interface remains functional across all tested screen sizes
- Session is maintained appropriately
- No console errors are logged

---

### Test Case: Test touch interaction on mobile devices
- **ID:** tc-004
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 12 mins

**Preconditions:**
- Employee is logged into the schedule interface on a mobile device (iOS or Android)
- Schedule data is available and displayed
- Mobile device has touch screen capability
- Internet connection is stable
- Mobile browser is updated to latest version

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Verify the schedule interface is loaded and displayed on the mobile device | Schedule interface is fully loaded and visible on mobile screen |
| 2 | Tap on the 'Next Day' navigation button using finger touch | Button responds immediately to touch, visual feedback is provided (button press animation or color change), schedule updates to next day within 2 seconds, and no delay or unresponsiveness occurs |
| 3 | Tap on the 'Previous Day' navigation button | Button responds to touch with visual feedback, schedule updates to previous day smoothly, and navigation works without errors |
| 4 | Tap on the 'Next Week' navigation button | Touch is registered correctly, schedule advances to next week, and transition is smooth without lag |
| 5 | Tap on the 'Previous Week' navigation button | Touch interaction works correctly, schedule updates to previous week, and no errors occur |
| 6 | Tap on a specific shift entry in the schedule | Shift is selected or details are displayed, touch target is large enough to tap accurately, and appropriate action occurs (details popup, highlight, or navigation) |
| 7 | If filters are available, tap on the filter button or icon | Filter menu or drawer opens smoothly, touch is registered accurately, and filter options are displayed |
| 8 | Tap to select a filter option (e.g., shift type) | Filter option is selected with visual confirmation, schedule updates to show filtered results, and touch interaction is smooth |
| 9 | Perform a swipe gesture left or right on the schedule (if swipe navigation is supported) | Swipe gesture is recognized, schedule navigates to previous or next period based on swipe direction, and gesture is smooth without accidental selections |
| 10 | Perform a vertical scroll gesture to view more schedule entries | Scrolling is smooth and responsive, content scrolls without lag, and no accidental taps occur during scrolling |
| 11 | Tap on any dropdown menus or selection controls | Dropdowns open correctly, options are touch-friendly and easy to select, and selections register accurately |
| 12 | Rapidly tap on navigation buttons multiple times | System handles rapid taps gracefully without errors, no duplicate actions occur, and interface remains responsive |
| 13 | Test touch interactions with different finger sizes or using thumb | All touch targets are accessible and usable regardless of finger size, minimum touch target size of 44x44px is maintained, and no accidental adjacent element selections occur |

**Postconditions:**
- Employee remains logged in
- Schedule interface remains functional
- No touch interaction errors are present
- All navigation and selection states are correctly maintained
- Mobile device performance is not degraded
- No JavaScript errors are logged in console

---

## Story: As Employee, I want to view detailed shift information to understand my work assignments fully
**Story ID:** story-20

### Test Case: Validate detailed shift information display
- **ID:** tc-001
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Employee has at least one shift assigned in the schedule
- Schedule view is accessible and loaded
- Test shift data includes role, location, notes, and status information

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule view page | Schedule view page loads successfully displaying the employee's shifts |
| 2 | Identify a shift in the schedule view | Shift is visible with basic information (date, time) |
| 3 | Click or select the shift to view detailed information | Detailed shift information panel or modal opens displaying comprehensive shift details |
| 4 | Verify that the role field is displayed in the detailed information | Role field is visible and shows the assigned role (e.g., 'Cashier', 'Manager') |
| 5 | Verify that the location field is displayed in the detailed information | Location field is visible and shows the work location (e.g., 'Store #123', 'Downtown Branch') |
| 6 | Verify that special instructions or notes are displayed | Notes section is visible showing any special instructions or additional information for the shift |
| 7 | Locate and observe the shift status indicator in the schedule view | Shift status indicator is clearly visible (e.g., badge, icon, or color coding) |
| 8 | Verify the status is displayed as either 'confirmed' or 'tentative' | Status is clearly labeled and distinguishable as 'confirmed' or 'tentative' with appropriate visual styling |

**Postconditions:**
- Detailed shift information remains accessible for review
- Employee can close the detailed view and return to schedule
- No data is modified during the viewing process

---

### Test Case: Verify access control for detailed shift data
- **ID:** tc-002
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Multiple employees exist in the system with assigned shifts
- Another employee's shift is visible or accessible in the system
- Access control rules are configured to restrict shift details to shift owners only

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule view page | Schedule view page loads successfully |
| 2 | Attempt to access another employee's shift details by directly selecting their shift (if visible) or by manipulating URL parameters with another employee's shift ID | System detects unauthorized access attempt |
| 3 | Observe the system response to the unauthorized access attempt | Access is denied and an appropriate error message is displayed (e.g., 'You do not have permission to view this shift', 'Access Denied') |
| 4 | Verify that no detailed shift information is displayed for the other employee's shift | No role, location, notes, or other sensitive shift details are visible to the unauthorized employee |
| 5 | Confirm that the employee can still access their own shift details | Employee's own shifts remain accessible with full detailed information |

**Postconditions:**
- Security logs record the unauthorized access attempt
- Employee remains logged in with access to their own data
- No unauthorized data was exposed or accessed

---

## Story: As Employee, I want to refresh my schedule view to see the latest updates and changes
**Story ID:** story-21

### Test Case: Validate manual schedule refresh
- **ID:** tc-003
- **Type:** happy-path
- **Priority:** High
- **Estimated Time:** 4 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Schedule view is loaded and displaying current schedule data
- Refresh button is visible and enabled on the schedule view
- API endpoint GET /api/schedules is functional and accessible
- Test data includes schedule changes that can be detected after refresh

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule view page | Schedule view page loads successfully displaying the employee's current schedule |
| 2 | Note the current schedule data displayed (shifts, times, dates) | Current schedule information is visible and documented for comparison |
| 3 | Locate the refresh button on the schedule view interface | Refresh button is visible and clearly identifiable (e.g., refresh icon or 'Refresh' label) |
| 4 | Click the refresh button | Loading indicator appears immediately (e.g., spinner, progress bar, or loading message) |
| 5 | Observe the loading indicator during the refresh operation | Loading indicator is visible and provides clear feedback that refresh is in progress |
| 6 | Wait for the refresh operation to complete | Loading indicator disappears and schedule view updates with the latest data within 2 seconds |
| 7 | Compare the updated schedule with the previously noted schedule data | Schedule reflects any recent changes made to shifts (new shifts, modified times, cancellations, etc.) |
| 8 | Verify that all schedule elements are properly rendered after refresh | All shifts, dates, times, and details are displayed correctly without visual glitches or missing data |

**Postconditions:**
- Schedule view displays the most current data from the database
- Loading indicator is no longer visible
- Refresh button remains enabled for subsequent refreshes
- Employee can continue interacting with the updated schedule

---

### Test Case: Test refresh error handling
- **ID:** tc-004
- **Type:** error-case
- **Priority:** High
- **Estimated Time:** 5 mins

**Preconditions:**
- Employee is logged into the system with valid credentials
- Schedule view is loaded and displaying current schedule data
- Ability to simulate API failure or network error exists (test environment or mock setup)
- Previous schedule data is visible before refresh attempt

**Steps:**
| Step | Action | Expected Result |
|------|--------|------------------|
| 1 | Navigate to the schedule view page | Schedule view page loads successfully displaying the employee's current schedule |
| 2 | Note the current schedule data displayed on the screen | Current schedule information is visible and documented |
| 3 | Simulate an API failure condition (e.g., disconnect network, configure mock API to return error, or use test tools to block the request) | API failure condition is successfully simulated and ready to trigger on next request |
| 4 | Click the refresh button on the schedule view | System attempts to fetch latest schedule data and encounters the simulated API failure |
| 5 | Observe the system response to the API failure | Error message is displayed to the user indicating that the refresh failed (e.g., 'Unable to refresh schedule', 'Connection error', 'Please try again later') |
| 6 | Verify that the error message is clear and user-friendly | Error message provides meaningful information without exposing technical details or stack traces |
| 7 | Check that the previous schedule data is still visible on the screen | Previous schedule remains displayed and accessible; no data loss or blank screen occurs |
| 8 | Verify that the schedule view remains functional after the error | Employee can still interact with the existing schedule data and attempt another refresh if desired |

**Postconditions:**
- Previous schedule data remains intact and visible
- Error message is displayed appropriately
- System remains stable and responsive
- Employee can retry the refresh operation when ready

---

