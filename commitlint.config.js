/**
 * Commitlint configuration for Attestful
 * Per Step 2.2.4 of instructions.txt
 *
 * Enforces conventional commits format:
 * <type>(<scope>): <subject>
 *
 * Examples:
 *   feat(collectors): add PagerDuty collector
 *   fix(oscal): handle missing metadata in profiles
 *   docs(readme): update installation instructions
 *   test(cli): add scan command tests
 */

module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    // Type must be one of these values
    'type-enum': [
      2,
      'always',
      [
        'feat',     // New feature
        'fix',      // Bug fix
        'docs',     // Documentation only
        'style',    // Code style (formatting, whitespace)
        'refactor', // Code refactoring (no feature/fix)
        'perf',     // Performance improvement
        'test',     // Adding or fixing tests
        'build',    // Build system or dependencies
        'ci',       // CI/CD configuration
        'chore',    // Other changes (maintenance)
        'revert',   // Revert a previous commit
      ],
    ],

    // Scope should be one of these values (optional)
    'scope-enum': [
      1, // Warning level (not required)
      'always',
      [
        // Core modules
        'core',
        'oscal',
        'cli',
        'api',
        'storage',
        'config',
        'security',

        // Collectors
        'collectors',
        'aws',
        'azure',
        'gcp',
        'kubernetes',
        'okta',
        'jamf',
        'github',
        'gitlab',
        'jira',
        'slack',
        'datadog',
        'snowflake',
        'google-workspace',
        'microsoft365',
        'pagerduty',
        'terraform',
        'zendesk',
        'zoom',
        'notion',
        'slab',
        'spotdraft',
        'confluence',
        'onepassword',

        // Frameworks
        'frameworks',
        'nist-csf',
        'nist-800-53',
        'fedramp',
        'soc2',
        'iso27001',
        'hitrust',

        // Analysis and reports
        'analysis',
        'reports',
        'maturity',
        'gaps',
        'crosswalk',

        // Remediation
        'remediation',

        // Infrastructure
        'dashboard',
        'docker',
        'helm',
        'ci',

        // Documentation and testing
        'docs',
        'tests',
        'deps',
      ],
    ],

    // Type must be lowercase
    'type-case': [2, 'always', 'lower-case'],

    // Subject must not be empty
    'subject-empty': [2, 'never'],

    // Subject must not end with period
    'subject-full-stop': [2, 'never', '.'],

    // Subject should be sentence case (warning)
    'subject-case': [1, 'always', 'sentence-case'],

    // Header max length
    'header-max-length': [2, 'always', 100],

    // Body max line length
    'body-max-line-length': [2, 'always', 200],
  },
};
