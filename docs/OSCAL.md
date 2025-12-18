# OSCAL Implementation Guide

This document explains how Attestful implements OSCAL (Open Security Controls Assessment Language) and how to work with OSCAL documents in the platform.

## What is OSCAL?

OSCAL is a standardized, machine-readable format for security control information developed by NIST. It provides a common language for:

- Defining security controls (Catalogs)
- Selecting and customizing controls (Profiles)
- Documenting control implementations (Components, SSPs)
- Recording assessment results (Assessment Results, POA&M)

## OSCAL Document Hierarchy

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                               CATALOG LAYER                                  │
│                         (Control Definitions)                                │
│                                                                             │
│  Examples: NIST 800-53, SOC 2 TSC, ISO 27001 Annex A                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                               PROFILE LAYER                                  │
│                     (Control Selection & Customization)                      │
│                                                                             │
│  Examples: FedRAMP Moderate, Organization Baseline                          │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                             COMPONENT LAYER                                  │
│                      (Reusable Implementations)                              │
│                                                                             │
│  Examples: AWS EC2 Component, Kubernetes Component                          │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           IMPLEMENTATION LAYER                               │
│                     (System Security Plans)                                  │
│                                                                             │
│  Examples: Production System SSP, Development Environment SSP               │
└─────────────────────────────────────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            ASSESSMENT LAYER                                  │
│                (Assessment Plans, Results, POA&M)                            │
│                                                                             │
│  Examples: Annual Assessment Results, Continuous Monitoring Results         │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Attestful's OSCAL Implementation

### Supported Document Types

| Document Type | Support Level | Description |
|---------------|---------------|-------------|
| Catalog | Full | Import, export, index, validate |
| Profile | Full | Import, resolve, generate, customize |
| Component Definition | Full | Import, export, map checks |
| SSP | Full | Generate, validate, diff, export |
| Assessment Plan | Partial | Generate from SSP |
| Assessment Results | Full | Generate from scans, export |
| POA&M | Full | Generate from failures, track |

### OSCAL Models

Attestful uses Pydantic models to represent OSCAL documents:

```
src/attestful/oscal/
├── models.py        # Pydantic data models for all OSCAL types
├── catalog.py       # Catalog loading and indexing
├── profile.py       # Profile resolution
├── component.py     # Component management
├── ssp.py           # SSP generation
└── assessment.py    # Assessment results
```

## Working with Catalogs

### Loading a Catalog

```python
from attestful.oscal.catalog import CatalogLoader

loader = CatalogLoader()

# Load from file
catalog = loader.load("data/oscal/catalogs/nist-800-53-rev5.json")

# Load from URL
catalog = loader.load_from_url(
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/..."
)
```

### Indexing Controls

```python
# Create an index for fast lookups
index = catalog.create_index()

# Look up a control
control = index.get_control("AC-2")

# Get control enhancements
enhancements = index.get_enhancements("AC-2")  # AC-2(1), AC-2(2), etc.

# Get all controls in a group
controls = index.get_controls_by_group("access-control")
```

### Control Structure

```python
# Control properties
control.id          # "AC-2"
control.title       # "Account Management"
control.prose       # Control description text
control.parts       # Statement, guidance, etc.
control.parameters  # Parameter definitions
control.properties  # Additional metadata
```

## Working with Profiles

### Loading a Profile

```python
from attestful.oscal.profile import ProfileLoader

loader = ProfileLoader()
profile = loader.load("data/oscal/profiles/fedramp-moderate.json")
```

### Resolving a Profile

Profile resolution flattens a profile's imports and modifications into a resolved catalog:

```python
from attestful.oscal.profile import ProfileResolver

resolver = ProfileResolver()
resolved = resolver.resolve(profile)

# resolved is a Catalog containing only the selected controls
# with all modifications applied
```

### Creating Custom Profiles

```python
from attestful.oscal.profile import ProfileBuilder

builder = ProfileBuilder()

# Start from a baseline
builder.import_profile("data/oscal/profiles/fedramp-moderate.json")

# Add additional controls
builder.add_controls(["AU-14", "SI-4(5)"])

# Remove controls not applicable
builder.remove_controls(["PE-1", "PE-2"])

# Set parameter values
builder.set_parameter("ac-2_prm_1", "30 days")

# Build the profile
profile = builder.build()

# Save
profile.to_json("my-organization-profile.json")
```

## Working with Components

### Component Definitions

Components describe reusable control implementations for specific technologies:

```python
from attestful.oscal.component import ComponentLoader

loader = ComponentLoader()
aws_component = loader.load("data/oscal/components/aws-ec2.json")

# List implemented controls
for impl in aws_component.control_implementations:
    for req in impl.implemented_requirements:
        print(f"{req.control_id}: {req.description}")
```

### Mapping Checks to Components

Attestful automatically maps automated checks to OSCAL component statements:

```python
from attestful.oscal.component import CheckMapper

mapper = CheckMapper()

# Load checks from YAML
checks = load_checks("data/standards/soc2-security.yaml")

# Generate component definition
component = mapper.generate_component(
    title="Attestful SOC 2 Automated Checks",
    checks=checks,
    catalog_id="soc2-trust-services-criteria"
)
```

## Working with SSPs

### Generating an SSP

```python
from attestful.oscal.ssp import SSPGenerator

generator = SSPGenerator()

# Configure the SSP
ssp = generator.generate(
    profile_path="data/oscal/profiles/fedramp-moderate.json",
    components=[
        "data/oscal/components/aws.json",
        "data/oscal/components/kubernetes.json",
    ],
    system_name="Production Application",
    system_description="Customer-facing SaaS application",
    authorization_boundary={
        "description": "AWS us-east-1 region VPC",
    }
)

# Save
ssp.to_json("production-ssp.json")
```

### SSP Validation

```python
from attestful.oscal.ssp import SSPValidator

validator = SSPValidator()

# Validate against profile
results = validator.validate(ssp, profile)

for issue in results.issues:
    print(f"{issue.severity}: {issue.message}")
    print(f"  Control: {issue.control_id}")
```

### SSP Diff

Compare two SSP versions to track changes:

```python
from attestful.oscal.ssp import SSPDiff

diff = SSPDiff()
changes = diff.compare(old_ssp, new_ssp)

for change in changes:
    print(f"{change.type}: {change.control_id}")
    print(f"  Before: {change.old_value}")
    print(f"  After: {change.new_value}")
```

## Working with Assessment Results

### Converting Scan Results

```python
from attestful.oscal.assessment import AssessmentResultsGenerator

generator = AssessmentResultsGenerator()

# Convert scan results to OSCAL
assessment = generator.from_scan_results(
    scan_results=scan.results,
    ssp_id="production-ssp-uuid",
    assessor="Attestful Automated Scan"
)

# Save
assessment.to_json("assessment-results-2024-01.json")
```

### Converting Maturity Scores

```python
# Convert maturity scores to OSCAL observations
assessment = generator.from_maturity_scores(
    maturity_data=maturity_calculator.results,
    ssp_id="production-ssp-uuid"
)
```

### Generating POA&M

```python
from attestful.oscal.assessment import POAMGenerator

generator = POAMGenerator()

# Generate from failed controls
poam = generator.from_failures(
    failures=assessment.findings,
    ssp_id="production-ssp-uuid"
)

# Add remediation details
for item in poam.poam_items:
    if item.control_id == "AC-2":
        item.remediation = {
            "description": "Implement automated account review process",
            "milestone": [
                {"title": "Design review process", "due_date": "2024-02-01"},
                {"title": "Implement automation", "due_date": "2024-03-01"},
            ]
        }

# Save
poam.to_json("poam-2024-q1.json")
```

## OSCAL Formats

Attestful supports all three OSCAL serialization formats:

### JSON (Default)

```python
catalog.to_json("catalog.json")
catalog = CatalogLoader().load("catalog.json")
```

### YAML

```python
catalog.to_yaml("catalog.yaml")
catalog = CatalogLoader().load("catalog.yaml")
```

### XML (FedRAMP Compatibility)

```python
catalog.to_xml("catalog.xml")
catalog = CatalogLoader().load("catalog.xml")
```

## CLI Commands

### Catalog Operations

```bash
# List available catalogs
attestful oscal catalog list

# Import a catalog
attestful oscal catalog import https://example.com/catalog.json

# Validate a catalog
attestful oscal catalog validate data/oscal/catalogs/custom.json

# Export catalog to different format
attestful oscal catalog export nist-800-53 --format yaml --output catalog.yaml
```

### Profile Operations

```bash
# List available profiles
attestful oscal profile list

# Resolve a profile to see selected controls
attestful oscal profile resolve fedramp-moderate

# Create a custom profile interactively
attestful oscal profile create --base fedramp-moderate --output my-profile.json
```

### SSP Operations

```bash
# Generate an SSP
attestful oscal ssp generate \
    --profile fedramp-moderate \
    --components aws,kubernetes \
    --output production-ssp.json

# Validate an SSP
attestful oscal ssp validate production-ssp.json

# Compare SSP versions
attestful oscal ssp diff old-ssp.json new-ssp.json
```

### Assessment Operations

```bash
# Export latest scan as OSCAL assessment results
attestful oscal assessment export --scan-id abc123 --output assessment.json

# Generate POA&M from failures
attestful oscal poam generate --assessment assessment.json --output poam.json
```

## Official OSCAL Resources

Attestful includes these official OSCAL catalogs and profiles:

### Catalogs (in `data/oscal/catalogs/`)
- `nist-800-53-rev5.json` - NIST SP 800-53 Rev 5 (1000+ controls)

### Profiles (in `data/oscal/profiles/`)
- `fedramp-low.json` - FedRAMP Low baseline
- `fedramp-moderate.json` - FedRAMP Moderate baseline
- `fedramp-high.json` - FedRAMP High baseline

### Downloading Updates

```bash
# Download latest OSCAL content from NIST
make oscal-download
```

## Best Practices

### 1. Use UUIDs Consistently

All OSCAL documents use UUIDs for identification. Attestful generates deterministic UUIDs based on content to ensure consistency:

```python
from attestful.oscal.utils import generate_uuid

# Generate UUID from content
uuid = generate_uuid(control.id, control.title)
```

### 2. Track Document Lineage

Always include `import` references to show document relationships:

```python
ssp.import_profile = {
    "href": "profiles/fedramp-moderate.json",
    "remarks": "FedRAMP Moderate baseline as of 2024-01"
}
```

### 3. Use Metadata Effectively

Include comprehensive metadata for traceability:

```python
catalog.metadata = {
    "title": "Organization Custom Catalog",
    "version": "1.0.0",
    "last_modified": "2024-01-15T10:30:00Z",
    "parties": [...],
    "responsible_parties": {...}
}
```

### 4. Validate Before Export

Always validate documents before sharing:

```bash
attestful oscal validate document.json
```

## Troubleshooting

### Common Issues

**Profile Resolution Failures**
- Ensure all imported catalogs/profiles are accessible
- Check for circular imports
- Verify control IDs match the source catalog

**Invalid Control References**
- Control IDs are case-sensitive
- Enhancement IDs include parentheses: `AC-2(1)` not `AC-2-1`
- Verify control exists in the source catalog

**XML Namespace Issues**
- Use the correct OSCAL namespace for the document type
- Ensure proper namespace prefixes in XPath expressions
