# Contributing to Attestful

Thank you for your interest in contributing to Attestful! This guide will help you get started with development and understand our contribution process.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Development Environment Setup](#development-environment-setup)
- [Code Style Guidelines](#code-style-guidelines)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Release Process](#release-process)

## Code of Conduct

We are committed to providing a welcoming and inclusive environment. Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.

## Development Environment Setup

### Prerequisites

- Python 3.11 or higher
- Poetry 1.5 or higher
- Git
- Docker (optional, for integration tests)

### Clone the Repository

```bash
git clone https://github.com/clay-good/attestful.git
cd attestful
```

### Install Dependencies

```bash
# Install all dependencies including development tools
poetry install --with dev

# Activate the virtual environment
poetry shell
```

### Verify Installation

```bash
# Run the CLI
attestful --version

# Run tests
pytest tests/unit -v

# Run linter
ruff check src/

# Run type checker
mypy src/attestful
```

### IDE Setup

#### VS Code

Recommended extensions:
- Python
- Pylance
- Ruff
- GitLens

Settings (`.vscode/settings.json`):

```json
{
  "python.defaultInterpreterPath": "${workspaceFolder}/.venv/bin/python",
  "python.analysis.typeCheckingMode": "basic",
  "editor.formatOnSave": true,
  "[python]": {
    "editor.defaultFormatter": "charliermarsh.ruff"
  },
  "ruff.lint.args": ["--config=pyproject.toml"]
}
```

#### PyCharm

1. Open the project directory
2. Configure the Poetry interpreter: Settings > Project > Python Interpreter > Add > Poetry Environment
3. Enable Ruff: Settings > Tools > Ruff

### Pre-commit Hooks

Install pre-commit hooks to automatically check code before commits:

```bash
# Install pre-commit
pip install pre-commit

# Install hooks
pre-commit install

# Run manually on all files
pre-commit run --all-files
```

## Code Style Guidelines

### Python Style

We follow PEP 8 with some modifications enforced by Ruff:

```python
# Good: Use type hints
def calculate_maturity(evidence: list[Evidence], framework: str = "nist-csf-2") -> MaturityScore:
    """Calculate maturity score from evidence."""
    ...

# Good: Use dataclasses or Pydantic for data structures
@dataclass
class ScanResult:
    check_id: str
    resource_id: str
    passed: bool
    details: dict[str, Any] = field(default_factory=dict)

# Good: Use explicit imports
from attestful.core.models import Resource, Evidence
from attestful.collectors.base import BaseCollector

# Bad: Avoid star imports
from attestful.core.models import *
```

### Naming Conventions

| Type | Convention | Example |
|------|------------|---------|
| Modules | snake_case | `evidence_store.py` |
| Classes | PascalCase | `EvidenceStore` |
| Functions | snake_case | `calculate_maturity` |
| Variables | snake_case | `scan_results` |
| Constants | UPPER_SNAKE_CASE | `MAX_RETRIES` |
| Private | Leading underscore | `_internal_method` |

### Documentation

All public functions and classes must have docstrings:

```python
def collect_evidence(
    self,
    evidence_types: list[str] | None = None,
    since: datetime | None = None,
) -> CollectionResult:
    """
    Collect evidence from the platform.

    Args:
        evidence_types: List of evidence types to collect.
            If None, collects all supported types.
        since: Only collect data after this datetime.

    Returns:
        CollectionResult containing collected evidence items and any errors.

    Raises:
        CollectionError: If collection fails completely.
        ConfigurationError: If required credentials are missing.

    Example:
        >>> collector = OktaCollector(config)
        >>> result = collector.collect_evidence(["users", "mfa_factors"])
        >>> print(f"Collected {len(result.evidence)} items")
    """
```

### Error Handling

Use custom exceptions and handle errors gracefully:

```python
from attestful.core.exceptions import (
    CollectionError,
    ConfigurationError,
    EvaluationError,
)

def collect_evidence(self) -> CollectionResult:
    if not self.config.api_token:
        raise ConfigurationError("API token is required")

    try:
        data = self._fetch_data()
    except requests.RequestException as e:
        raise CollectionError(f"API request failed: {e}") from e

    return CollectionResult(evidence=data)
```

### Logging

Use the structured logger:

```python
from attestful.core.logging import get_logger

logger = get_logger(__name__)

def process_data(self):
    logger.debug("Starting data processing")
    logger.info(f"Processing {len(self.items)} items")
    logger.warning("Rate limit approaching")
    logger.error(f"Failed to process item: {error}")
```

## Testing Requirements

### Test Structure

```
tests/
├── unit/              # Unit tests
│   ├── test_evaluator.py
│   ├── test_maturity.py
│   └── ...
├── integration/       # Integration tests
│   ├── test_cli.py
│   ├── test_workflows.py
│   └── ...
├── security/          # Security tests
│   └── test_security.py
├── performance/       # Performance tests
│   └── test_performance.py
├── mocks/             # Mock implementations
│   └── collectors.py
└── conftest.py        # Shared fixtures
```

### Writing Tests

```python
import pytest
from attestful.core.models import Resource

class TestEvaluator:
    """Tests for the Evaluator class."""

    @pytest.fixture
    def evaluator(self):
        """Create an evaluator instance."""
        return Evaluator()

    @pytest.fixture
    def sample_resource(self):
        """Create a sample resource."""
        return Resource(
            id="test-123",
            type="s3_bucket",
            provider="aws",
            raw_data={"Name": "test"},
        )

    def test_evaluate_passing_check(self, evaluator, sample_resource):
        """Test that a passing check returns passed=True."""
        # Arrange
        evaluator.register_check(self.create_passing_check())

        # Act
        results = evaluator.evaluate([sample_resource])

        # Assert
        assert len(results) == 1
        assert results[0].passed is True

    def test_evaluate_failing_check(self, evaluator, sample_resource):
        """Test that a failing check returns passed=False."""
        ...
```

### Test Markers

Use markers to categorize tests:

```python
@pytest.mark.unit
def test_basic_functionality():
    ...

@pytest.mark.integration
def test_full_workflow():
    ...

@pytest.mark.slow
def test_large_dataset():
    ...

@pytest.mark.security
def test_encryption():
    ...
```

### Coverage Requirements

- Minimum 80% code coverage overall
- 100% coverage for security-critical code
- All new features must include tests

```bash
# Run tests with coverage
pytest --cov=src/attestful --cov-report=html

# View coverage report
open coverage_html/index.html
```

## Pull Request Process

### Before Creating a PR

1. **Create an issue** describing the change (unless trivial)
2. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes** with clear, atomic commits
4. **Run all checks locally**:
   ```bash
   # Format code
   ruff format src/ tests/

   # Lint
   ruff check src/ tests/

   # Type check
   mypy src/attestful

   # Tests
   pytest tests/ -v

   # Security scan
   bandit -r src/
   ```

### Creating a PR

1. **Push your branch**:
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Create the PR** on GitHub with:
   - Clear title describing the change
   - Description of what and why
   - Link to related issue(s)
   - Screenshots if UI changes
   - Test plan

### PR Template

```markdown
## Summary
Brief description of the changes.

## Related Issues
Fixes #123

## Changes
- Added X feature
- Fixed Y bug
- Refactored Z module

## Test Plan
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Manual testing completed

## Screenshots
(if applicable)

## Checklist
- [ ] Code follows style guidelines
- [ ] Tests pass locally
- [ ] Documentation updated
- [ ] Changelog updated
```

### Review Process

1. **Automated checks** must pass:
   - Tests
   - Linting
   - Type checking
   - Security scanning

2. **Code review** by at least one maintainer
3. **Address feedback** and push updates
4. **Squash and merge** when approved

### Commit Message Format

```
type(scope): short description

Longer description if needed.

Refs: #123
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting
- `refactor`: Code restructuring
- `test`: Tests
- `chore`: Maintenance

Examples:
```
feat(collectors): add Slack collector

Implements evidence collection from Slack workspaces including
users, channels, and workspace settings.

Refs: #456
```

```
fix(evaluator): handle None values in path traversal

Previously, evaluating a path with None intermediate values
would raise an exception. Now returns None gracefully.

Fixes: #789
```

## Release Process

### Version Numbers

We use [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Creating a Release

1. **Update version** in `pyproject.toml`
2. **Update CHANGELOG.md** with release notes
3. **Create PR** for release:
   ```bash
   git checkout -b release/v1.2.0
   # Update version and changelog
   git commit -m "chore: release v1.2.0"
   ```
4. **Merge PR** after review
5. **Create tag**:
   ```bash
   git tag -a v1.2.0 -m "Release v1.2.0"
   git push origin v1.2.0
   ```
6. **GitHub Actions** will automatically:
   - Run tests
   - Build packages
   - Publish to PyPI
   - Create GitHub Release
   - Build Docker images

### Changelog Format

```markdown
# Changelog

## [1.2.0] - 2024-01-15

### Added
- Slack collector for workspace evidence (#123)
- Cross-framework mapping analysis (#124)

### Changed
- Improved scan performance by 30% (#125)

### Fixed
- Okta pagination handling for large tenants (#126)

### Security
- Updated cryptography library to fix CVE-2024-XXXX
```

## Getting Help

- **Questions & Bugs**: Open an [Issue](https://github.com/clay-good/attestful/issues)

Thank you for contributing to Attestful!
