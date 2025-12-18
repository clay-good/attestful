"""
Jamf collector for endpoint management evidence.

Collects device management data including computers, mobile devices,
policies, and configuration profiles for compliance evidence.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import requests

from attestful.collectors.base import BaseCollector, CollectorMetadata, CollectorMode
from attestful.core.exceptions import CollectionError, ConfigurationError
from attestful.core.models import CollectionResult, Evidence, Resource

logger = logging.getLogger(__name__)


@dataclass
class JamfCollectorConfig:
    """Configuration for Jamf collector."""

    url: str = ""  # Jamf Pro URL (e.g., https://company.jamfcloud.com)
    username: str = ""
    password: str = ""
    client_id: str = ""  # For API client authentication
    client_secret: str = ""
    timeout: int = 30
    page_size: int = 100


class JamfCollector(BaseCollector):
    """
    Collector for Jamf Pro endpoint management platform.

    Collects:
    - Computers: macOS device inventory and compliance status
    - Mobile Devices: iOS/iPadOS device inventory
    - Policies: Configuration policies and enforcement
    - Configuration Profiles: MDM profiles and settings
    - Users: User accounts and group memberships
    - Extension Attributes: Custom device attributes

    Evidence types map to compliance controls for:
    - SOC 2: CC6.1 (Access Controls), CC6.6 (System Boundaries), CC6.7 (Data Transmission)
    - NIST 800-53: CM-2 (Baseline Config), CM-6 (Config Settings), CM-8 (System Inventory)
    - ISO 27001: A.8.1.1 (Asset Inventory), A.9.1.2 (Network Access), A.12.5.1 (Software Install)
    - HITRUST: 07.a (Asset Inventory), 09.j (Mobile Computing), 10.h (Control of Software)
    """

    PLATFORM = "jamf"
    SUPPORTED_RESOURCE_TYPES = [
        "jamf_computer",
        "jamf_mobile_device",
        "jamf_policy",
        "jamf_configuration_profile",
        "jamf_user",
    ]
    SUPPORTED_EVIDENCE_TYPES = [
        "computers",
        "mobile_devices",
        "policies",
        "configuration_profiles",
        "users",
        "extension_attributes",
        "computer_groups",
    ]

    # Map evidence types to compliance framework controls
    EVIDENCE_CONTROL_MAPPINGS = {
        "computers": {
            "soc2": ["CC6.1", "CC6.6", "CC6.7", "CC6.8"],
            "nist_800_53": ["CM-2", "CM-6", "CM-8", "SI-2"],
            "iso_27001": ["A.8.1.1", "A.8.1.2", "A.12.5.1", "A.12.6.1"],
            "hitrust": ["07.a", "07.b", "10.h", "10.m"],
        },
        "mobile_devices": {
            "soc2": ["CC6.1", "CC6.6", "CC6.7"],
            "nist_800_53": ["CM-2", "CM-8", "AC-19"],
            "iso_27001": ["A.6.2.1", "A.8.1.1", "A.11.2.6"],
            "hitrust": ["07.a", "09.j", "09.m"],
        },
        "policies": {
            "soc2": ["CC5.2", "CC6.1", "CC6.8"],
            "nist_800_53": ["CM-2", "CM-6", "CM-7", "SI-3"],
            "iso_27001": ["A.12.1.1", "A.12.5.1", "A.12.6.2"],
            "hitrust": ["10.h", "10.k", "10.m"],
        },
        "configuration_profiles": {
            "soc2": ["CC5.2", "CC6.1", "CC6.6"],
            "nist_800_53": ["CM-2", "CM-6", "CM-7"],
            "iso_27001": ["A.12.1.1", "A.12.5.1", "A.14.2.2"],
            "hitrust": ["10.h", "10.k", "01.v"],
        },
        "users": {
            "soc2": ["CC6.1", "CC6.2", "CC6.3"],
            "nist_800_53": ["AC-2", "IA-2", "IA-4"],
            "iso_27001": ["A.9.2.1", "A.9.2.2", "A.9.2.3"],
            "hitrust": ["01.b", "01.c", "01.q"],
        },
        "extension_attributes": {
            "soc2": ["CC6.1", "CC7.1"],
            "nist_800_53": ["CM-8", "SI-4"],
            "iso_27001": ["A.8.1.1", "A.12.4.1"],
            "hitrust": ["07.a", "09.ab"],
        },
        "computer_groups": {
            "soc2": ["CC6.1", "CC6.3"],
            "nist_800_53": ["AC-2", "CM-8"],
            "iso_27001": ["A.8.1.1", "A.9.2.1"],
            "hitrust": ["01.b", "07.a"],
        },
    }

    def __init__(self, config: JamfCollectorConfig | None = None):
        """Initialize Jamf collector."""
        self.config = config or JamfCollectorConfig()
        self._session: requests.Session | None = None
        self._token: str | None = None
        self._token_expires: datetime | None = None

    @property
    def metadata(self) -> CollectorMetadata:
        """Return collector metadata."""
        return CollectorMetadata(
            name="Jamf Collector",
            platform=self.PLATFORM,
            description="Collects endpoint management evidence from Jamf Pro",
            mode=CollectorMode.BOTH,
            resource_types=self.SUPPORTED_RESOURCE_TYPES,
            evidence_types=self.SUPPORTED_EVIDENCE_TYPES,
            version="1.0.0",
        )

    @property
    def session(self) -> requests.Session:
        """Get or create HTTP session."""
        if self._session is None:
            self._session = requests.Session()
            self._session.headers.update({
                "Accept": "application/json",
                "Content-Type": "application/json",
            })
        return self._session

    @property
    def api_url(self) -> str:
        """Return the API base URL."""
        return self.config.url.rstrip("/")

    def _get_token(self) -> str:
        """Get or refresh OAuth token."""
        # Check if we have a valid token
        if self._token and self._token_expires:
            if datetime.now(timezone.utc) < self._token_expires - timedelta(minutes=5):
                return self._token

        # Get new token
        if self.config.client_id and self.config.client_secret:
            # OAuth client credentials flow
            token_url = f"{self.api_url}/api/oauth/token"
            response = requests.post(
                token_url,
                data={
                    "client_id": self.config.client_id,
                    "client_secret": self.config.client_secret,
                    "grant_type": "client_credentials",
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            data = response.json()
            self._token = data["access_token"]
            expires_in = data.get("expires_in", 3600)
            self._token_expires = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        else:
            # Basic auth token
            token_url = f"{self.api_url}/api/v1/auth/token"
            response = requests.post(
                token_url,
                auth=(self.config.username, self.config.password),
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            data = response.json()
            self._token = data["token"]
            # Basic auth tokens typically expire in 30 minutes
            self._token_expires = datetime.now(timezone.utc) + timedelta(minutes=30)

        return self._token

    def _make_request(
        self,
        method: str,
        endpoint: str,
        params: dict | None = None,
        json_data: dict | None = None,
        use_classic_api: bool = False,
    ) -> dict:
        """Make an API request to Jamf."""
        token = self._get_token()

        if use_classic_api:
            url = f"{self.api_url}/JSSResource{endpoint}"
        else:
            url = f"{self.api_url}/api/v1{endpoint}"

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

        try:
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                json=json_data,
                headers=headers,
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.warning(f"Jamf API request failed: {e}")
            raise

    def _paginate(
        self,
        endpoint: str,
        data_key: str = "results",
        use_classic_api: bool = False,
    ) -> list[dict]:
        """Paginate through API results."""
        results = []
        page = 0

        while True:
            try:
                params = {
                    "page": page,
                    "page-size": self.config.page_size,
                }
                response = self._make_request(
                    "GET",
                    endpoint,
                    params=params,
                    use_classic_api=use_classic_api,
                )

                data = response.get(data_key, [])
                if not data:
                    break

                results.extend(data)

                # Check for more pages
                total_count = response.get("totalCount", 0)
                if len(results) >= total_count or len(data) < self.config.page_size:
                    break

                page += 1

            except requests.RequestException:
                if not results:
                    raise
                break

        return results

    def validate_credentials(self) -> bool:
        """Validate Jamf credentials."""
        if not self.config.url:
            raise ConfigurationError("Jamf url is required")

        has_basic_auth = self.config.username and self.config.password
        has_oauth = self.config.client_id and self.config.client_secret

        if not has_basic_auth and not has_oauth:
            raise ConfigurationError(
                "Jamf credentials required: either username/password or client_id/client_secret"
            )

        try:
            # Test authentication by getting auth token
            self._get_token()
            logger.info(f"Authenticated to Jamf Pro at: {self.api_url}")
            return True
        except requests.RequestException as e:
            if "401" in str(e) or "Unauthorized" in str(e):
                raise ConfigurationError("Invalid Jamf credentials")
            raise ConfigurationError(f"Failed to validate Jamf credentials: {e}")

    def collect_evidence(
        self,
        evidence_types: list[str] | None = None,
    ) -> CollectionResult:
        """Collect evidence from Jamf."""
        evidence_types = evidence_types or self.SUPPORTED_EVIDENCE_TYPES
        invalid_types = set(evidence_types) - set(self.SUPPORTED_EVIDENCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported evidence types: {invalid_types}")

        logger.info(f"Collecting Jamf evidence: {evidence_types}")
        evidence_items: list[Evidence] = []
        errors: list[str] = []

        collection_methods = {
            "computers": self._collect_computers_evidence,
            "mobile_devices": self._collect_mobile_devices_evidence,
            "policies": self._collect_policies_evidence,
            "configuration_profiles": self._collect_configuration_profiles_evidence,
            "users": self._collect_users_evidence,
            "extension_attributes": self._collect_extension_attributes_evidence,
            "computer_groups": self._collect_computer_groups_evidence,
        }

        for evidence_type in evidence_types:
            try:
                method = collection_methods.get(evidence_type)
                if method:
                    evidence = method()
                    if evidence:
                        evidence_items.append(evidence)
            except Exception as e:
                error_msg = f"Error collecting {evidence_type}: {e}"
                logger.error(error_msg)
                errors.append(error_msg)

        result = CollectionResult(
            platform=self.PLATFORM,
            evidence_items=evidence_items,
            errors=errors,
        )
        result.complete()
        return result

    def _collect_computers_evidence(self) -> Evidence:
        """Collect computers evidence."""
        logger.info("Collecting Jamf computers...")

        computers = self._paginate("/computers-inventory")

        # Analyze computer inventory
        os_versions = {}
        managed_count = 0
        unmanaged_count = 0
        encrypted_count = 0
        unencrypted_count = 0
        compliant_count = 0
        non_compliant_count = 0

        for computer in computers:
            # Count OS versions
            general = computer.get("general", {})
            os_version = general.get("operatingSystemVersion", "unknown")
            os_versions[os_version] = os_versions.get(os_version, 0) + 1

            # Management status
            if general.get("managed", False):
                managed_count += 1
            else:
                unmanaged_count += 1

            # Encryption status (FileVault)
            disk_encryption = computer.get("diskEncryption", {})
            if disk_encryption.get("fileVault2Status", "").lower() == "enabled":
                encrypted_count += 1
            else:
                unencrypted_count += 1

            # Simple compliance check (managed + encrypted)
            if general.get("managed", False) and disk_encryption.get("fileVault2Status", "").lower() == "enabled":
                compliant_count += 1
            else:
                non_compliant_count += 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="computers",
            raw_data={
                "computers": [
                    {
                        "id": c.get("id"),
                        "name": c.get("general", {}).get("name"),
                        "serial_number": c.get("hardware", {}).get("serialNumber"),
                        "model": c.get("hardware", {}).get("model"),
                        "os_version": c.get("general", {}).get("operatingSystemVersion"),
                        "os_build": c.get("general", {}).get("operatingSystemBuild"),
                        "managed": c.get("general", {}).get("managed", False),
                        "supervised": c.get("general", {}).get("supervised", False),
                        "last_contact": c.get("general", {}).get("lastContactTime"),
                        "last_enrolled": c.get("general", {}).get("lastEnrolledDate"),
                        "filevault_enabled": c.get("diskEncryption", {}).get("fileVault2Status", "").lower() == "enabled",
                        "sip_enabled": c.get("security", {}).get("sipStatus", "").lower() == "enabled",
                        "gatekeeper_enabled": c.get("security", {}).get("gatekeeperStatus", "").lower() in ("app store and identified developers", "app store"),
                        "firewall_enabled": c.get("security", {}).get("firewallStatus", "").lower() == "enabled",
                        "user": c.get("userAndLocation", {}).get("username"),
                        "department": c.get("userAndLocation", {}).get("department"),
                    }
                    for c in computers
                ],
                "total_count": len(computers),
                "os_versions": os_versions,
                "managed_count": managed_count,
                "unmanaged_count": unmanaged_count,
                "encrypted_count": encrypted_count,
                "unencrypted_count": unencrypted_count,
                "compliant_count": compliant_count,
                "non_compliant_count": non_compliant_count,
                "compliance_rate": round(compliant_count / len(computers) * 100, 1) if computers else 0,
            },
            metadata={
                "source": "collector:jamf",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["computers"],
            },
        )

    def _collect_mobile_devices_evidence(self) -> Evidence:
        """Collect mobile devices evidence."""
        logger.info("Collecting Jamf mobile devices...")

        devices = self._paginate("/mobile-devices")

        # Analyze device inventory
        os_versions = {}
        managed_count = 0
        supervised_count = 0
        model_counts = {}

        for device in devices:
            # Count OS versions
            os_version = device.get("osVersion", "unknown")
            os_versions[os_version] = os_versions.get(os_version, 0) + 1

            # Management status
            if device.get("managed", False):
                managed_count += 1

            if device.get("supervised", False):
                supervised_count += 1

            # Model distribution
            model = device.get("model", "unknown")
            model_counts[model] = model_counts.get(model, 0) + 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="mobile_devices",
            raw_data={
                "mobile_devices": [
                    {
                        "id": d.get("id"),
                        "name": d.get("name"),
                        "serial_number": d.get("serialNumber"),
                        "model": d.get("model"),
                        "os_version": d.get("osVersion"),
                        "managed": d.get("managed", False),
                        "supervised": d.get("supervised", False),
                        "last_inventory_update": d.get("lastInventoryUpdateDate"),
                        "username": d.get("username"),
                    }
                    for d in devices
                ],
                "total_count": len(devices),
                "os_versions": os_versions,
                "model_counts": model_counts,
                "managed_count": managed_count,
                "supervised_count": supervised_count,
            },
            metadata={
                "source": "collector:jamf",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["mobile_devices"],
            },
        )

    def _collect_policies_evidence(self) -> Evidence:
        """Collect policies evidence."""
        logger.info("Collecting Jamf policies...")

        policies = self._paginate("/policies")

        # Categorize policies
        enabled_count = 0
        disabled_count = 0
        category_counts = {}

        for policy in policies:
            if policy.get("enabled", False):
                enabled_count += 1
            else:
                disabled_count += 1

            category = policy.get("category", {}).get("name", "uncategorized")
            category_counts[category] = category_counts.get(category, 0) + 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="policies",
            raw_data={
                "policies": [
                    {
                        "id": p.get("id"),
                        "name": p.get("name"),
                        "enabled": p.get("enabled", False),
                        "category": p.get("category", {}).get("name"),
                        "trigger": p.get("trigger"),
                        "frequency": p.get("frequency"),
                    }
                    for p in policies
                ],
                "total_count": len(policies),
                "enabled_count": enabled_count,
                "disabled_count": disabled_count,
                "category_counts": category_counts,
            },
            metadata={
                "source": "collector:jamf",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["policies"],
            },
        )

    def _collect_configuration_profiles_evidence(self) -> Evidence:
        """Collect configuration profiles evidence."""
        logger.info("Collecting Jamf configuration profiles...")

        # Get macOS profiles
        computer_profiles = self._paginate("/os-x-configuration-profiles")
        # Get iOS profiles
        mobile_profiles = self._paginate("/mobile-device-configuration-profiles")

        all_profiles = []

        for profile in computer_profiles:
            all_profiles.append({
                "id": profile.get("id"),
                "name": profile.get("name"),
                "platform": "macOS",
                "scope": profile.get("scope", {}).get("allComputers", False),
                "distribution_method": profile.get("general", {}).get("distributionMethod"),
            })

        for profile in mobile_profiles:
            all_profiles.append({
                "id": profile.get("id"),
                "name": profile.get("name"),
                "platform": "iOS",
                "scope": profile.get("scope", {}).get("allMobileDevices", False),
                "distribution_method": profile.get("general", {}).get("distributionMethod"),
            })

        platform_counts = {"macOS": len(computer_profiles), "iOS": len(mobile_profiles)}

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="configuration_profiles",
            raw_data={
                "configuration_profiles": all_profiles,
                "total_count": len(all_profiles),
                "platform_counts": platform_counts,
                "macos_profiles": len(computer_profiles),
                "ios_profiles": len(mobile_profiles),
            },
            metadata={
                "source": "collector:jamf",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["configuration_profiles"],
            },
        )

    def _collect_users_evidence(self) -> Evidence:
        """Collect users evidence."""
        logger.info("Collecting Jamf users...")

        users = self._paginate("/users")

        # Categorize users
        ldap_users = 0
        local_users = 0

        for user in users:
            if user.get("ldapServer", {}).get("id"):
                ldap_users += 1
            else:
                local_users += 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="users",
            raw_data={
                "users": [
                    {
                        "id": u.get("id"),
                        "name": u.get("name"),
                        "email": u.get("email"),
                        "full_name": u.get("fullName"),
                        "phone_number": u.get("phoneNumber"),
                        "position": u.get("position"),
                        "department": u.get("department"),
                        "building": u.get("building"),
                        "ldap_server": u.get("ldapServer", {}).get("name"),
                    }
                    for u in users
                ],
                "total_count": len(users),
                "ldap_users": ldap_users,
                "local_users": local_users,
            },
            metadata={
                "source": "collector:jamf",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["users"],
            },
        )

    def _collect_extension_attributes_evidence(self) -> Evidence:
        """Collect extension attributes evidence."""
        logger.info("Collecting Jamf extension attributes...")

        # Get computer extension attributes
        computer_attrs = self._paginate("/computer-extension-attributes")
        # Get mobile device extension attributes
        mobile_attrs = self._paginate("/mobile-device-extension-attributes")

        all_attrs = []

        for attr in computer_attrs:
            all_attrs.append({
                "id": attr.get("id"),
                "name": attr.get("name"),
                "platform": "macOS",
                "data_type": attr.get("dataType"),
                "input_type": attr.get("inputType", {}).get("type"),
                "enabled": attr.get("enabled", True),
            })

        for attr in mobile_attrs:
            all_attrs.append({
                "id": attr.get("id"),
                "name": attr.get("name"),
                "platform": "iOS",
                "data_type": attr.get("dataType"),
                "input_type": attr.get("inputType", {}).get("type"),
                "enabled": attr.get("enabled", True),
            })

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="extension_attributes",
            raw_data={
                "extension_attributes": all_attrs,
                "total_count": len(all_attrs),
                "computer_attributes": len(computer_attrs),
                "mobile_attributes": len(mobile_attrs),
            },
            metadata={
                "source": "collector:jamf",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["extension_attributes"],
            },
        )

    def _collect_computer_groups_evidence(self) -> Evidence:
        """Collect computer groups evidence."""
        logger.info("Collecting Jamf computer groups...")

        groups = self._paginate("/computer-groups")

        smart_groups = 0
        static_groups = 0

        for group in groups:
            if group.get("smartGroup", False):
                smart_groups += 1
            else:
                static_groups += 1

        return Evidence(
            platform=self.PLATFORM,
            evidence_type="computer_groups",
            raw_data={
                "computer_groups": [
                    {
                        "id": g.get("id"),
                        "name": g.get("name"),
                        "smart_group": g.get("smartGroup", False),
                        "member_count": g.get("memberCount", 0),
                    }
                    for g in groups
                ],
                "total_count": len(groups),
                "smart_groups": smart_groups,
                "static_groups": static_groups,
            },
            metadata={
                "source": "collector:jamf",
                "compliance_controls": self.EVIDENCE_CONTROL_MAPPINGS["computer_groups"],
            },
        )

    def collect_resources(
        self,
        resource_types: list[str] | None = None,
    ) -> list[Resource]:
        """Collect resources from Jamf."""
        resource_types = resource_types or self.SUPPORTED_RESOURCE_TYPES
        invalid_types = set(resource_types) - set(self.SUPPORTED_RESOURCE_TYPES)
        if invalid_types:
            raise CollectionError(f"Unsupported resource types: {invalid_types}")

        logger.info(f"Collecting Jamf resources: {resource_types}")
        resources: list[Resource] = []

        collection_methods = {
            "jamf_computer": self._collect_computer_resources,
            "jamf_mobile_device": self._collect_mobile_device_resources,
            "jamf_policy": self._collect_policy_resources,
            "jamf_configuration_profile": self._collect_configuration_profile_resources,
            "jamf_user": self._collect_user_resources,
        }

        for resource_type in resource_types:
            try:
                method = collection_methods.get(resource_type)
                if method:
                    resources.extend(method())
            except Exception as e:
                logger.error(f"Error collecting {resource_type}: {e}")

        return resources

    def _collect_computer_resources(self) -> list[Resource]:
        """Collect computer resources."""
        logger.info("Collecting Jamf computer resources...")
        resources = []

        computers = self._paginate("/computers-inventory")

        for computer in computers:
            general = computer.get("general", {})
            hardware = computer.get("hardware", {})
            security = computer.get("security", {})
            disk_encryption = computer.get("diskEncryption", {})

            resources.append(
                Resource(
                    id=str(computer.get("id", "")),
                    type="jamf_computer",
                    provider="jamf",
                    region="global",
                    name=general.get("name", ""),
                    tags=[],
                    metadata={
                        "serial_number": hardware.get("serialNumber"),
                        "model": hardware.get("model"),
                        "os_version": general.get("operatingSystemVersion"),
                        "managed": general.get("managed", False),
                        "supervised": general.get("supervised", False),
                        "filevault_enabled": disk_encryption.get("fileVault2Status", "").lower() == "enabled",
                        "sip_enabled": security.get("sipStatus", "").lower() == "enabled",
                        "last_contact": general.get("lastContactTime"),
                    },
                    raw_data=computer,
                )
            )

        return resources

    def _collect_mobile_device_resources(self) -> list[Resource]:
        """Collect mobile device resources."""
        logger.info("Collecting Jamf mobile device resources...")
        resources = []

        devices = self._paginate("/mobile-devices")

        for device in devices:
            resources.append(
                Resource(
                    id=str(device.get("id", "")),
                    type="jamf_mobile_device",
                    provider="jamf",
                    region="global",
                    name=device.get("name", ""),
                    tags=[],
                    metadata={
                        "serial_number": device.get("serialNumber"),
                        "model": device.get("model"),
                        "os_version": device.get("osVersion"),
                        "managed": device.get("managed", False),
                        "supervised": device.get("supervised", False),
                        "username": device.get("username"),
                    },
                    raw_data=device,
                )
            )

        return resources

    def _collect_policy_resources(self) -> list[Resource]:
        """Collect policy resources."""
        logger.info("Collecting Jamf policy resources...")
        resources = []

        policies = self._paginate("/policies")

        for policy in policies:
            category = policy.get("category", {}) or {}

            resources.append(
                Resource(
                    id=str(policy.get("id", "")),
                    type="jamf_policy",
                    provider="jamf",
                    region="global",
                    name=policy.get("name", ""),
                    tags=[],
                    metadata={
                        "enabled": policy.get("enabled", False),
                        "category": category.get("name"),
                        "trigger": policy.get("trigger"),
                        "frequency": policy.get("frequency"),
                    },
                    raw_data=policy,
                )
            )

        return resources

    def _collect_configuration_profile_resources(self) -> list[Resource]:
        """Collect configuration profile resources."""
        logger.info("Collecting Jamf configuration profile resources...")
        resources = []

        # Get macOS profiles
        computer_profiles = self._paginate("/os-x-configuration-profiles")
        for profile in computer_profiles:
            resources.append(
                Resource(
                    id=str(profile.get("id", "")),
                    type="jamf_configuration_profile",
                    provider="jamf",
                    region="global",
                    name=profile.get("name", ""),
                    tags=["macOS"],
                    metadata={
                        "platform": "macOS",
                        "distribution_method": profile.get("general", {}).get("distributionMethod"),
                    },
                    raw_data=profile,
                )
            )

        # Get iOS profiles
        mobile_profiles = self._paginate("/mobile-device-configuration-profiles")
        for profile in mobile_profiles:
            resources.append(
                Resource(
                    id=str(profile.get("id", "")),
                    type="jamf_configuration_profile",
                    provider="jamf",
                    region="global",
                    name=profile.get("name", ""),
                    tags=["iOS"],
                    metadata={
                        "platform": "iOS",
                        "distribution_method": profile.get("general", {}).get("distributionMethod"),
                    },
                    raw_data=profile,
                )
            )

        return resources

    def _collect_user_resources(self) -> list[Resource]:
        """Collect user resources."""
        logger.info("Collecting Jamf user resources...")
        resources = []

        users = self._paginate("/users")

        for user in users:
            ldap_server = user.get("ldapServer", {}) or {}

            resources.append(
                Resource(
                    id=str(user.get("id", "")),
                    type="jamf_user",
                    provider="jamf",
                    region="global",
                    name=user.get("name", ""),
                    tags=[],
                    metadata={
                        "email": user.get("email"),
                        "full_name": user.get("fullName"),
                        "department": user.get("department"),
                        "ldap_server": ldap_server.get("name"),
                    },
                    raw_data=user,
                )
            )

        return resources
