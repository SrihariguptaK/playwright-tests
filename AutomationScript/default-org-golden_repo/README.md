# Automation Test Scripts

This directory contains Playwright test automation scripts generated from DevX user stories.

## Directory Structure

```
AutomationScript/
├── [projectId]/
│   ├── [epicId]/
│   │   ├── [featureId]/
│   │   │   ├── [storyId].spec.ts    # Playwright test for specific user story
│   │   │   └── fixtures.ts           # Test data and fixtures
│   │   └── feature.spec.ts          # Feature-level tests
│   └── epic.spec.ts                 # Epic-level tests
├── playwright.config.ts
├── package.json
└── .env.example
```

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```

2. Copy `.env.example` to `.env` and configure:
   ```bash
   cp .env.example .env
   ```

3. Update `BASE_URL` in `.env` to your application URL

## Running Tests

### Run all tests
```bash
npm test
```

### Run tests in headed mode (see browser)
```bash
npm run test:headed
```

### Run tests in debug mode
```bash
npm run test:debug
```

### Run tests in UI mode
```bash
npm run test:ui
```

### Run specific test file
```bash
npx playwright test tests/story-001.spec.ts
```

### Run tests matching pattern
```bash
npx playwright test -g "login"
```

## Test Reports

After running tests, view reports:

### HTML Report
```bash
npx playwright show-report
```

### JSON Report
Test results are also available in `test-results.json`

## CI/CD Integration

Set the `CI` environment variable to enable:
- Headless mode
- Single worker
- Retry on failure
- Full trace/video recording

Example GitHub Actions:
```yaml
- name: Run Playwright tests
  env:
    CI: true
  run: npm test
```

## Troubleshooting

### Tests timing out
- Increase `TIMEOUT` in `.env`
- Check if application server is running on `BASE_URL`
- Verify network connectivity

### Browser not found
```bash
npx playwright install
```

### Permission denied errors
```bash
chmod +x node_modules/.bin/playwright
```

## Documentation

- [Playwright Documentation](https://playwright.dev)
- [Assertion Reference](https://playwright.dev/docs/api/class-locatorassertions)
- [Configuration Reference](https://playwright.dev/docs/test-configuration)

## Contributing

When adding new test cases:
1. Follow the existing file structure
2. Add meaningful test descriptions
3. Use descriptive variable names
4. Include comments for complex logic
5. Update this README with new test categories
