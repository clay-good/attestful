"""
NIST Cybersecurity Framework 2.0 Control Definitions.

This module contains the complete NIST CSF 2.0 control hierarchy including
all 6 functions, 22 categories, and 106 subcategories with their official
descriptions, evidence type requirements, and maturity criteria.

Reference: NIST Cybersecurity Framework 2.0 (February 2024)
https://www.nist.gov/cyberframework

The CSF 2.0 structure:
    - 6 Functions: Govern (GV), Identify (ID), Protect (PR), Detect (DE),
                   Respond (RS), Recover (RC)
    - 22 Categories: Grouped under functions
    - 106 Subcategories: Specific outcomes within categories

Each subcategory includes:
    - evidence_types: Types of evidence that can satisfy this control
    - api_collectible: Whether evidence can be collected via API
    - maturity_criteria: Criteria for maturity levels 0-4
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class MaturityCriteria:
    """
    Criteria for each maturity level (0-4).

    Maturity levels align with NIST implementation tiers:
        Level 0: No evidence - Control not addressed
        Level 1: Partial - Ad-hoc, informal processes
        Level 2: Risk Informed - Documented processes, some automation
        Level 3: Repeatable - Consistent automation, measured effectiveness
        Level 4: Adaptive - Optimized, continuous improvement
    """

    level_0: str = "No evidence of this control being addressed"
    level_1: str = "Partial or informal implementation"
    level_2: str = "Documented processes with some automation"
    level_3: str = "Consistent, automated, and measured"
    level_4: str = "Optimized with continuous improvement"

    def to_dict(self) -> dict[str, str]:
        """Convert to dictionary."""
        return {
            "0": self.level_0,
            "1": self.level_1,
            "2": self.level_2,
            "3": self.level_3,
            "4": self.level_4,
        }


@dataclass
class NistSubcategory:
    """
    A NIST CSF 2.0 subcategory (specific control outcome).

    Attributes:
        id: Unique identifier (e.g., "GV.OC-01")
        name: Short name
        description: Official NIST description
        category_id: Parent category ID
        evidence_types: List of evidence types that can satisfy this control
        api_collectible: Whether evidence can be collected automatically
        maturity_criteria: Criteria for each maturity level
    """

    id: str
    name: str
    description: str
    category_id: str
    evidence_types: list[str] = field(default_factory=list)
    api_collectible: bool = True
    maturity_criteria: MaturityCriteria = field(default_factory=MaturityCriteria)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "category_id": self.category_id,
            "evidence_types": self.evidence_types,
            "api_collectible": self.api_collectible,
            "maturity_criteria": self.maturity_criteria.to_dict(),
        }


@dataclass
class NistCategory:
    """
    A NIST CSF 2.0 category (group of related subcategories).

    Attributes:
        id: Unique identifier (e.g., "GV.OC")
        name: Category name
        description: Official NIST description
        function_id: Parent function ID
        subcategories: List of subcategories in this category
    """

    id: str
    name: str
    description: str
    function_id: str
    subcategories: list[NistSubcategory] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "function_id": self.function_id,
            "subcategories": [s.to_dict() for s in self.subcategories],
        }


@dataclass
class NistFunction:
    """
    A NIST CSF 2.0 function (top-level grouping).

    The six functions are:
        GV - Govern: Establish and monitor cybersecurity strategy
        ID - Identify: Understand cybersecurity risk
        PR - Protect: Safeguard against threats
        DE - Detect: Find and analyze attacks
        RS - Respond: Take action on incidents
        RC - Recover: Restore capabilities after incidents

    Attributes:
        id: Two-letter identifier (GV, ID, PR, DE, RS, RC)
        name: Function name
        description: Official NIST description
        categories: List of categories in this function
    """

    id: str
    name: str
    description: str
    categories: list[NistCategory] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "categories": [c.to_dict() for c in self.categories],
        }


# =============================================================================
# NIST CSF 2.0 COMPLETE CONTROL HIERARCHY
# =============================================================================

def _build_csf2_controls() -> list[NistFunction]:
    """
    Build the complete NIST CSF 2.0 control hierarchy.

    Returns all 6 functions with their 22 categories and 106 subcategories.
    """
    functions = []

    # =========================================================================
    # GOVERN (GV) - Establish and monitor cybersecurity risk management strategy
    # =========================================================================
    gv = NistFunction(
        id="GV",
        name="Govern",
        description=(
            "The organization's cybersecurity risk management strategy, expectations, "
            "and policy are established, communicated, and monitored."
        ),
        categories=[],
    )

    # GV.OC - Organizational Context
    gv_oc = NistCategory(
        id="GV.OC",
        name="Organizational Context",
        description=(
            "The circumstances - mission, stakeholder expectations, dependencies, "
            "and legal, regulatory, and contractual requirements - surrounding the "
            "organization's cybersecurity risk management decisions are understood."
        ),
        function_id="GV",
        subcategories=[
            NistSubcategory(
                id="GV.OC-01",
                name="Mission Understanding",
                description=(
                    "The organizational mission is understood and informs "
                    "cybersecurity risk management."
                ),
                category_id="GV.OC",
                evidence_types=["policy_document", "mission_statement"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No documented mission or cybersecurity alignment",
                    level_1="Mission exists but not linked to cybersecurity",
                    level_2="Mission documented with cybersecurity considerations",
                    level_3="Mission actively guides cybersecurity decisions",
                    level_4="Mission and cybersecurity continuously aligned",
                ),
            ),
            NistSubcategory(
                id="GV.OC-02",
                name="Stakeholder Expectations",
                description=(
                    "Internal and external stakeholders are understood, and their "
                    "needs and expectations regarding cybersecurity risk management "
                    "are understood and considered."
                ),
                category_id="GV.OC",
                evidence_types=["policy_document", "stakeholder_register"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No stakeholder analysis performed",
                    level_1="Some stakeholders identified informally",
                    level_2="Stakeholder expectations documented",
                    level_3="Regular stakeholder engagement process",
                    level_4="Continuous stakeholder feedback integration",
                ),
            ),
            NistSubcategory(
                id="GV.OC-03",
                name="Legal and Regulatory Requirements",
                description=(
                    "Legal, regulatory, and contractual requirements regarding "
                    "cybersecurity - including privacy and civil liberties "
                    "obligations - are understood and managed."
                ),
                category_id="GV.OC",
                evidence_types=["compliance_register", "policy_document"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No awareness of legal requirements",
                    level_1="Some requirements known informally",
                    level_2="Requirements documented and tracked",
                    level_3="Compliance actively monitored",
                    level_4="Proactive compliance with emerging requirements",
                ),
            ),
            NistSubcategory(
                id="GV.OC-04",
                name="Critical Objectives",
                description=(
                    "Critical objectives, capabilities, and services that "
                    "stakeholders depend on or expect from the organization are "
                    "understood and communicated."
                ),
                category_id="GV.OC",
                evidence_types=["business_impact_analysis", "service_catalog"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="Critical objectives not identified",
                    level_1="Some critical services known informally",
                    level_2="Critical objectives documented",
                    level_3="Dependencies mapped and communicated",
                    level_4="Continuous critical service optimization",
                ),
            ),
            NistSubcategory(
                id="GV.OC-05",
                name="Outcomes and Dependencies",
                description=(
                    "Outcomes, capabilities, and services that the organization "
                    "depends on are understood and communicated."
                ),
                category_id="GV.OC",
                evidence_types=["dependency_mapping", "vendor_inventory"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="Dependencies not identified",
                    level_1="Some dependencies known informally",
                    level_2="Dependencies documented",
                    level_3="Dependencies actively managed",
                    level_4="Proactive dependency risk management",
                ),
            ),
        ],
    )
    gv.categories.append(gv_oc)

    # GV.RM - Risk Management Strategy
    gv_rm = NistCategory(
        id="GV.RM",
        name="Risk Management Strategy",
        description=(
            "The organization's priorities, constraints, risk tolerance and appetite "
            "statements, and assumptions are established, communicated, and used to "
            "support operational risk decisions."
        ),
        function_id="GV",
        subcategories=[
            NistSubcategory(
                id="GV.RM-01",
                name="Risk Management Objectives",
                description=(
                    "Risk management objectives are established and agreed to by "
                    "organizational stakeholders."
                ),
                category_id="GV.RM",
                evidence_types=["risk_policy", "policy_document"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No risk management objectives",
                    level_1="Informal risk objectives",
                    level_2="Documented risk objectives",
                    level_3="Objectives aligned with strategy",
                    level_4="Continuously optimized objectives",
                ),
            ),
            NistSubcategory(
                id="GV.RM-02",
                name="Risk Appetite and Tolerance",
                description=(
                    "Risk appetite and risk tolerance statements are established, "
                    "communicated, and maintained."
                ),
                category_id="GV.RM",
                evidence_types=["risk_appetite_statement", "policy_document"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No risk appetite defined",
                    level_1="Informal risk tolerance",
                    level_2="Risk appetite documented",
                    level_3="Risk appetite actively used in decisions",
                    level_4="Dynamic risk appetite based on conditions",
                ),
            ),
            NistSubcategory(
                id="GV.RM-03",
                name="Risk Management Activities",
                description=(
                    "Cybersecurity risk management activities and outcomes are "
                    "included in enterprise risk management processes."
                ),
                category_id="GV.RM",
                evidence_types=["risk_register", "erm_integration"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No ERM integration",
                    level_1="Ad-hoc risk management",
                    level_2="Cyber risk in ERM framework",
                    level_3="Integrated risk management",
                    level_4="Optimized enterprise risk program",
                ),
            ),
            NistSubcategory(
                id="GV.RM-04",
                name="Strategic Direction",
                description=(
                    "Strategic direction that describes appropriate risk response "
                    "options is established and communicated."
                ),
                category_id="GV.RM",
                evidence_types=["risk_response_strategy", "policy_document"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No strategic direction",
                    level_1="Informal response options",
                    level_2="Documented response strategies",
                    level_3="Strategies actively guide decisions",
                    level_4="Adaptive response strategies",
                ),
            ),
            NistSubcategory(
                id="GV.RM-05",
                name="Communication Lines",
                description=(
                    "Lines of communication across the organization are established "
                    "for cybersecurity risks, including risks from suppliers and "
                    "other third parties."
                ),
                category_id="GV.RM",
                evidence_types=["communication_plan", "org_chart"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No communication lines",
                    level_1="Informal communication",
                    level_2="Communication channels documented",
                    level_3="Regular risk communication",
                    level_4="Real-time risk communication",
                ),
            ),
            NistSubcategory(
                id="GV.RM-06",
                name="Standardized Method",
                description=(
                    "A standardized method for calculating, documenting, categorizing, "
                    "and prioritizing cybersecurity risks is established and "
                    "communicated."
                ),
                category_id="GV.RM",
                evidence_types=["risk_methodology", "risk_register"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No risk methodology",
                    level_1="Ad-hoc risk assessment",
                    level_2="Documented methodology",
                    level_3="Consistent methodology application",
                    level_4="Continuously improved methodology",
                ),
            ),
            NistSubcategory(
                id="GV.RM-07",
                name="Strategic Opportunities",
                description=(
                    "Strategic opportunities (i.e., positive risks) are characterized "
                    "and are included in organizational cybersecurity risk discussions."
                ),
                category_id="GV.RM",
                evidence_types=["opportunity_register", "strategic_plan"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No opportunity consideration",
                    level_1="Informal opportunity awareness",
                    level_2="Opportunities documented",
                    level_3="Opportunities in risk discussions",
                    level_4="Proactive opportunity pursuit",
                ),
            ),
        ],
    )
    gv.categories.append(gv_rm)

    # GV.RR - Roles, Responsibilities, and Authorities
    gv_rr = NistCategory(
        id="GV.RR",
        name="Roles, Responsibilities, and Authorities",
        description=(
            "Cybersecurity roles, responsibilities, and authorities to foster "
            "accountability, performance assessment, and continuous improvement "
            "are established and communicated."
        ),
        function_id="GV",
        subcategories=[
            NistSubcategory(
                id="GV.RR-01",
                name="Leadership Accountability",
                description=(
                    "Organizational leadership is responsible and accountable for "
                    "cybersecurity risk and fosters a culture that is risk-aware, "
                    "ethical, and continually improving."
                ),
                category_id="GV.RR",
                evidence_types=["governance_charter", "board_minutes"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No leadership accountability",
                    level_1="Informal leadership involvement",
                    level_2="Documented leadership responsibilities",
                    level_3="Active leadership engagement",
                    level_4="Leadership drives security culture",
                ),
            ),
            NistSubcategory(
                id="GV.RR-02",
                name="Roles Established",
                description=(
                    "Roles, responsibilities, and authorities related to cybersecurity "
                    "risk management are established, communicated, understood, and "
                    "enforced."
                ),
                category_id="GV.RR",
                evidence_types=["raci_matrix", "job_descriptions", "org_chart"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No defined roles",
                    level_1="Informal role assignments",
                    level_2="Roles documented",
                    level_3="Roles actively enforced",
                    level_4="Roles continuously optimized",
                ),
            ),
            NistSubcategory(
                id="GV.RR-03",
                name="Adequate Resources",
                description=(
                    "Adequate resources are allocated commensurate with the "
                    "cybersecurity risk strategy, roles, responsibilities, and policies."
                ),
                category_id="GV.RR",
                evidence_types=["budget_allocation", "resource_plan"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No dedicated resources",
                    level_1="Ad-hoc resource allocation",
                    level_2="Budget documented",
                    level_3="Resources aligned with risk",
                    level_4="Dynamic resource optimization",
                ),
            ),
            NistSubcategory(
                id="GV.RR-04",
                name="Performance Evaluation",
                description=(
                    "Cybersecurity is included in human resources practices."
                ),
                category_id="GV.RR",
                evidence_types=["hr_policy", "performance_criteria"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No HR integration",
                    level_1="Informal security in HR",
                    level_2="Security in job descriptions",
                    level_3="Security in performance reviews",
                    level_4="Security culture in all HR practices",
                ),
            ),
        ],
    )
    gv.categories.append(gv_rr)

    # GV.PO - Policy
    gv_po = NistCategory(
        id="GV.PO",
        name="Policy",
        description=(
            "Organizational cybersecurity policy is established, communicated, "
            "and enforced."
        ),
        function_id="GV",
        subcategories=[
            NistSubcategory(
                id="GV.PO-01",
                name="Policy Established",
                description=(
                    "Policy for managing cybersecurity risks is established based on "
                    "organizational context, cybersecurity strategy, and priorities "
                    "and is communicated and enforced."
                ),
                category_id="GV.PO",
                evidence_types=["security_policy", "policy_document"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No security policy",
                    level_1="Informal policies",
                    level_2="Policies documented",
                    level_3="Policies enforced and measured",
                    level_4="Policies continuously improved",
                ),
            ),
            NistSubcategory(
                id="GV.PO-02",
                name="Policy Review",
                description=(
                    "Policy for managing cybersecurity risks is reviewed, updated, "
                    "communicated, and enforced to reflect changes in requirements, "
                    "threats, technology, and organizational mission."
                ),
                category_id="GV.PO",
                evidence_types=["policy_review_log", "policy_document"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No policy review process",
                    level_1="Ad-hoc policy updates",
                    level_2="Scheduled policy reviews",
                    level_3="Regular reviews with updates",
                    level_4="Continuous policy refinement",
                ),
            ),
        ],
    )
    gv.categories.append(gv_po)

    # GV.OV - Oversight
    gv_ov = NistCategory(
        id="GV.OV",
        name="Oversight",
        description=(
            "Results of organization-wide cybersecurity risk management activities "
            "and performance are used to inform, improve, and adjust the risk "
            "management strategy."
        ),
        function_id="GV",
        subcategories=[
            NistSubcategory(
                id="GV.OV-01",
                name="Risk Management Review",
                description=(
                    "Cybersecurity risk management strategy outcomes are reviewed to "
                    "inform and adjust strategy and direction."
                ),
                category_id="GV.OV",
                evidence_types=["risk_review_minutes", "kri_dashboard"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No strategy review",
                    level_1="Ad-hoc reviews",
                    level_2="Scheduled reviews",
                    level_3="Reviews drive improvements",
                    level_4="Continuous strategy optimization",
                ),
            ),
            NistSubcategory(
                id="GV.OV-02",
                name="Strategy Adjustment",
                description=(
                    "The cybersecurity risk management strategy is reviewed and "
                    "adjusted to ensure coverage of organizational requirements "
                    "and risks."
                ),
                category_id="GV.OV",
                evidence_types=["strategy_document", "review_minutes"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No strategy adjustment",
                    level_1="Reactive adjustments",
                    level_2="Planned adjustments",
                    level_3="Proactive adjustments",
                    level_4="Predictive adjustments",
                ),
            ),
            NistSubcategory(
                id="GV.OV-03",
                name="Performance Evaluation",
                description=(
                    "Organizational cybersecurity risk management performance is "
                    "evaluated and reviewed for adjustments needed."
                ),
                category_id="GV.OV",
                evidence_types=["kpi_report", "performance_metrics"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No performance evaluation",
                    level_1="Ad-hoc evaluation",
                    level_2="Regular performance reviews",
                    level_3="Metrics-driven evaluation",
                    level_4="Continuous performance optimization",
                ),
            ),
        ],
    )
    gv.categories.append(gv_ov)

    # GV.SC - Cybersecurity Supply Chain Risk Management
    gv_sc = NistCategory(
        id="GV.SC",
        name="Cybersecurity Supply Chain Risk Management",
        description=(
            "Cyber supply chain risk management processes are identified, "
            "established, managed, monitored, and improved by organizational "
            "stakeholders."
        ),
        function_id="GV",
        subcategories=[
            NistSubcategory(
                id="GV.SC-01",
                name="Supply Chain Program",
                description=(
                    "A cybersecurity supply chain risk management program, strategy, "
                    "objectives, policies, and processes are established and agreed "
                    "to by organizational stakeholders."
                ),
                category_id="GV.SC",
                evidence_types=["scrm_policy", "vendor_policy"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No SCRM program",
                    level_1="Ad-hoc vendor management",
                    level_2="SCRM program documented",
                    level_3="SCRM actively managed",
                    level_4="Optimized SCRM program",
                ),
            ),
            NistSubcategory(
                id="GV.SC-02",
                name="Supplier Roles",
                description=(
                    "Cybersecurity roles and responsibilities for suppliers, customers, "
                    "and partners are established, communicated, and coordinated "
                    "internally and externally."
                ),
                category_id="GV.SC",
                evidence_types=["vendor_agreements", "raci_matrix"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No supplier roles defined",
                    level_1="Informal supplier expectations",
                    level_2="Roles documented in contracts",
                    level_3="Roles actively managed",
                    level_4="Collaborative role optimization",
                ),
            ),
            NistSubcategory(
                id="GV.SC-03",
                name="Supply Chain Integration",
                description=(
                    "Cybersecurity supply chain risk management is integrated into "
                    "cybersecurity and enterprise risk management, risk assessment, "
                    "and improvement processes."
                ),
                category_id="GV.SC",
                evidence_types=["risk_register", "erm_integration"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No SCRM integration",
                    level_1="Isolated SCRM activities",
                    level_2="SCRM in risk framework",
                    level_3="Integrated SCRM",
                    level_4="SCRM drives improvements",
                ),
            ),
            NistSubcategory(
                id="GV.SC-04",
                name="Supplier Assessment",
                description=(
                    "Suppliers are known and prioritized by criticality."
                ),
                category_id="GV.SC",
                evidence_types=["vendor_inventory", "criticality_assessment"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No supplier inventory",
                    level_1="Partial supplier list",
                    level_2="Complete inventory with criticality",
                    level_3="Regular supplier assessments",
                    level_4="Continuous supplier monitoring",
                ),
            ),
            NistSubcategory(
                id="GV.SC-05",
                name="Supplier Requirements",
                description=(
                    "Requirements to address cybersecurity risks in supply chains "
                    "are established, prioritized, and integrated into contracts "
                    "and other agreements with suppliers and other relevant third "
                    "parties."
                ),
                category_id="GV.SC",
                evidence_types=["contract_templates", "security_requirements"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No supplier requirements",
                    level_1="Informal requirements",
                    level_2="Requirements in contracts",
                    level_3="Requirements enforced",
                    level_4="Requirements continuously updated",
                ),
            ),
            NistSubcategory(
                id="GV.SC-06",
                name="Due Diligence",
                description=(
                    "Planning and due diligence are performed to reduce risks before "
                    "entering into formal supplier or other third-party relationships."
                ),
                category_id="GV.SC",
                evidence_types=["due_diligence_reports", "vendor_assessments"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No due diligence",
                    level_1="Ad-hoc due diligence",
                    level_2="Standardized due diligence",
                    level_3="Risk-based due diligence",
                    level_4="Continuous due diligence",
                ),
            ),
            NistSubcategory(
                id="GV.SC-07",
                name="Supplier Risk Understanding",
                description=(
                    "The risks posed by a supplier, their products and services, "
                    "and other third parties are understood, recorded, prioritized, "
                    "assessed, responded to, and monitored over the course of the "
                    "relationship."
                ),
                category_id="GV.SC",
                evidence_types=["vendor_risk_assessments", "risk_register"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No supplier risk tracking",
                    level_1="Ad-hoc risk awareness",
                    level_2="Risks documented",
                    level_3="Risks actively managed",
                    level_4="Continuous risk monitoring",
                ),
            ),
            NistSubcategory(
                id="GV.SC-08",
                name="Supplier Inclusion",
                description=(
                    "Relevant suppliers and other third parties are included in "
                    "incident planning, response, and recovery activities."
                ),
                category_id="GV.SC",
                evidence_types=["incident_plan", "vendor_contacts"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No supplier inclusion",
                    level_1="Ad-hoc supplier involvement",
                    level_2="Suppliers in incident plans",
                    level_3="Regular supplier exercises",
                    level_4="Integrated incident response",
                ),
            ),
            NistSubcategory(
                id="GV.SC-09",
                name="Supply Chain Security",
                description=(
                    "Supply chain security practices are integrated into cybersecurity "
                    "and enterprise risk management programs, and their performance "
                    "is monitored throughout the technology product and service life "
                    "cycle."
                ),
                category_id="GV.SC",
                evidence_types=["scrm_metrics", "lifecycle_management"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No lifecycle management",
                    level_1="Ad-hoc lifecycle consideration",
                    level_2="Lifecycle documented",
                    level_3="Lifecycle actively managed",
                    level_4="Continuous lifecycle optimization",
                ),
            ),
            NistSubcategory(
                id="GV.SC-10",
                name="Supply Chain Plan",
                description=(
                    "Cybersecurity supply chain risk management plans include "
                    "provisions for activities that occur after the conclusion of "
                    "a partnership or service agreement."
                ),
                category_id="GV.SC",
                evidence_types=["offboarding_procedures", "data_return_policy"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No exit planning",
                    level_1="Ad-hoc exit procedures",
                    level_2="Exit procedures documented",
                    level_3="Exit procedures tested",
                    level_4="Comprehensive exit management",
                ),
            ),
        ],
    )
    gv.categories.append(gv_sc)

    functions.append(gv)

    # =========================================================================
    # IDENTIFY (ID) - Understand current cybersecurity risk
    # =========================================================================
    id_func = NistFunction(
        id="ID",
        name="Identify",
        description=(
            "The organization's current cybersecurity risks are understood."
        ),
        categories=[],
    )

    # ID.AM - Asset Management
    id_am = NistCategory(
        id="ID.AM",
        name="Asset Management",
        description=(
            "Assets (e.g., data, hardware, software, systems, facilities, services, "
            "people) that enable the organization to achieve business purposes are "
            "identified and managed consistent with their relative importance to "
            "organizational objectives and the organization's risk strategy."
        ),
        function_id="ID",
        subcategories=[
            NistSubcategory(
                id="ID.AM-01",
                name="Hardware Inventory",
                description=(
                    "Inventories of hardware managed by the organization are "
                    "maintained."
                ),
                category_id="ID.AM",
                evidence_types=["device_inventory", "cmdb_export", "jamf_inventory"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No hardware inventory",
                    level_1="Partial or outdated inventory",
                    level_2="Complete manual inventory",
                    level_3="Automated inventory management",
                    level_4="Real-time inventory with analytics",
                ),
            ),
            NistSubcategory(
                id="ID.AM-02",
                name="Software Inventory",
                description=(
                    "Inventories of software, services, and systems managed by the "
                    "organization are maintained."
                ),
                category_id="ID.AM",
                evidence_types=["software_inventory", "application_catalog"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No software inventory",
                    level_1="Partial software list",
                    level_2="Complete software inventory",
                    level_3="Automated software discovery",
                    level_4="Real-time software management",
                ),
            ),
            NistSubcategory(
                id="ID.AM-03",
                name="Data Flow Mapping",
                description=(
                    "Representations of the organization's authorized network "
                    "communication and internal and external network data flows "
                    "are maintained."
                ),
                category_id="ID.AM",
                evidence_types=["network_diagram", "data_flow_diagram"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No data flow documentation",
                    level_1="Informal data flow knowledge",
                    level_2="Documented data flows",
                    level_3="Automated flow monitoring",
                    level_4="Real-time flow analysis",
                ),
            ),
            NistSubcategory(
                id="ID.AM-04",
                name="External Service Inventory",
                description=(
                    "Inventories of services provided by suppliers are maintained."
                ),
                category_id="ID.AM",
                evidence_types=["vendor_inventory", "service_catalog"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No service inventory",
                    level_1="Partial service list",
                    level_2="Complete service inventory",
                    level_3="Services linked to vendors",
                    level_4="Automated service discovery",
                ),
            ),
            NistSubcategory(
                id="ID.AM-05",
                name="Asset Prioritization",
                description=(
                    "Assets are prioritized based on classification, criticality, "
                    "resources, and impact to the mission."
                ),
                category_id="ID.AM",
                evidence_types=["asset_classification", "criticality_assessment"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No asset prioritization",
                    level_1="Informal prioritization",
                    level_2="Documented classification",
                    level_3="Classification drives decisions",
                    level_4="Dynamic prioritization",
                ),
            ),
            NistSubcategory(
                id="ID.AM-07",
                name="Data Inventory",
                description=(
                    "Inventories of data and corresponding metadata for designated "
                    "data types are maintained."
                ),
                category_id="ID.AM",
                evidence_types=["data_inventory", "data_catalog"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No data inventory",
                    level_1="Partial data awareness",
                    level_2="Data inventory documented",
                    level_3="Automated data discovery",
                    level_4="Real-time data governance",
                ),
            ),
            NistSubcategory(
                id="ID.AM-08",
                name="System Use Management",
                description=(
                    "Systems, hardware, software, services, and data are managed "
                    "throughout their life cycles."
                ),
                category_id="ID.AM",
                evidence_types=["lifecycle_policy", "decommission_records"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No lifecycle management",
                    level_1="Ad-hoc lifecycle practices",
                    level_2="Lifecycle procedures documented",
                    level_3="Lifecycle actively managed",
                    level_4="Optimized lifecycle management",
                ),
            ),
        ],
    )
    id_func.categories.append(id_am)

    # ID.RA - Risk Assessment
    id_ra = NistCategory(
        id="ID.RA",
        name="Risk Assessment",
        description=(
            "The cybersecurity risk to the organization, assets, and individuals "
            "is understood."
        ),
        function_id="ID",
        subcategories=[
            NistSubcategory(
                id="ID.RA-01",
                name="Vulnerability Identification",
                description=(
                    "Vulnerabilities in assets are identified, validated, and "
                    "recorded."
                ),
                category_id="ID.RA",
                evidence_types=["vulnerability_scan", "security_findings"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No vulnerability identification",
                    level_1="Ad-hoc vulnerability awareness",
                    level_2="Regular vulnerability scanning",
                    level_3="Continuous vulnerability management",
                    level_4="Predictive vulnerability intelligence",
                ),
            ),
            NistSubcategory(
                id="ID.RA-02",
                name="Threat Intelligence",
                description=(
                    "Cyber threat intelligence is received from information sharing "
                    "forums and sources."
                ),
                category_id="ID.RA",
                evidence_types=["threat_feeds", "isac_membership"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No threat intelligence",
                    level_1="Ad-hoc threat awareness",
                    level_2="Subscribed threat feeds",
                    level_3="Integrated threat intelligence",
                    level_4="Proactive threat hunting",
                ),
            ),
            NistSubcategory(
                id="ID.RA-03",
                name="Threat Identification",
                description=(
                    "Internal and external threats to the organization are "
                    "identified and recorded."
                ),
                category_id="ID.RA",
                evidence_types=["threat_register", "threat_assessment"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No threat identification",
                    level_1="Informal threat awareness",
                    level_2="Threats documented",
                    level_3="Threats regularly updated",
                    level_4="Continuous threat modeling",
                ),
            ),
            NistSubcategory(
                id="ID.RA-04",
                name="Impact Analysis",
                description=(
                    "Potential impacts and likelihoods of threats exploiting "
                    "vulnerabilities are identified and recorded."
                ),
                category_id="ID.RA",
                evidence_types=["risk_assessment", "impact_analysis"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No impact analysis",
                    level_1="Informal impact awareness",
                    level_2="Impact analysis documented",
                    level_3="Quantitative impact analysis",
                    level_4="Continuous impact modeling",
                ),
            ),
            NistSubcategory(
                id="ID.RA-05",
                name="Risk Determination",
                description=(
                    "Threats, vulnerabilities, likelihoods, and impacts are used to "
                    "understand inherent risk and inform risk response prioritization."
                ),
                category_id="ID.RA",
                evidence_types=["risk_register", "risk_matrix"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No risk determination",
                    level_1="Ad-hoc risk awareness",
                    level_2="Risk register maintained",
                    level_3="Risk-based prioritization",
                    level_4="Dynamic risk assessment",
                ),
            ),
            NistSubcategory(
                id="ID.RA-06",
                name="Risk Response",
                description=(
                    "Risk responses are chosen, prioritized, planned, tracked, and "
                    "communicated."
                ),
                category_id="ID.RA",
                evidence_types=["risk_treatment_plan", "risk_register"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No risk response",
                    level_1="Ad-hoc responses",
                    level_2="Documented response plans",
                    level_3="Tracked risk treatments",
                    level_4="Optimized response strategies",
                ),
            ),
            NistSubcategory(
                id="ID.RA-07",
                name="Risk Management Changes",
                description=(
                    "Changes and exceptions are managed, assessed for risk impact, "
                    "recorded, and tracked."
                ),
                category_id="ID.RA",
                evidence_types=["change_management", "exception_log"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No change tracking",
                    level_1="Ad-hoc change awareness",
                    level_2="Change management process",
                    level_3="Risk-assessed changes",
                    level_4="Automated change risk analysis",
                ),
            ),
            NistSubcategory(
                id="ID.RA-08",
                name="Risk Prioritization",
                description=(
                    "Processes for receiving, analyzing, and responding to "
                    "vulnerability disclosures are established."
                ),
                category_id="ID.RA",
                evidence_types=["vulnerability_disclosure_policy", "vdp"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No disclosure process",
                    level_1="Ad-hoc disclosure handling",
                    level_2="Disclosure process documented",
                    level_3="Active disclosure program",
                    level_4="Bug bounty program",
                ),
            ),
            NistSubcategory(
                id="ID.RA-09",
                name="Asset Authenticity",
                description=(
                    "The authenticity and integrity of hardware and software are "
                    "assessed prior to acquisition and use."
                ),
                category_id="ID.RA",
                evidence_types=["procurement_policy", "integrity_verification"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No integrity verification",
                    level_1="Ad-hoc verification",
                    level_2="Verification procedures",
                    level_3="Automated integrity checks",
                    level_4="Supply chain integrity program",
                ),
            ),
            NistSubcategory(
                id="ID.RA-10",
                name="Critical Supplier Assessment",
                description=(
                    "Critical suppliers are assessed prior to acquisition."
                ),
                category_id="ID.RA",
                evidence_types=["vendor_assessment", "due_diligence_reports"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No supplier assessment",
                    level_1="Ad-hoc assessments",
                    level_2="Standardized assessments",
                    level_3="Risk-based assessments",
                    level_4="Continuous supplier monitoring",
                ),
            ),
        ],
    )
    id_func.categories.append(id_ra)

    # ID.IM - Improvement
    id_im = NistCategory(
        id="ID.IM",
        name="Improvement",
        description=(
            "Improvements to organizational cybersecurity risk management processes, "
            "procedures, and activities are identified across all CSF Functions."
        ),
        function_id="ID",
        subcategories=[
            NistSubcategory(
                id="ID.IM-01",
                name="Improvement Identification",
                description=(
                    "Improvements are identified from evaluations."
                ),
                category_id="ID.IM",
                evidence_types=["audit_findings", "assessment_results"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No improvement tracking",
                    level_1="Ad-hoc improvements",
                    level_2="Improvements documented",
                    level_3="Systematic improvement process",
                    level_4="Continuous improvement culture",
                ),
            ),
            NistSubcategory(
                id="ID.IM-02",
                name="Improvement Implementation",
                description=(
                    "Improvements are prioritized and implemented."
                ),
                category_id="ID.IM",
                evidence_types=["improvement_plan", "remediation_tracking"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No improvement implementation",
                    level_1="Ad-hoc implementation",
                    level_2="Prioritized implementation",
                    level_3="Tracked implementation",
                    level_4="Optimized improvement cycles",
                ),
            ),
            NistSubcategory(
                id="ID.IM-03",
                name="Evaluation Sharing",
                description=(
                    "Improvements are evaluated through exercises and real-world "
                    "execution."
                ),
                category_id="ID.IM",
                evidence_types=["exercise_results", "lessons_learned"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No evaluation",
                    level_1="Ad-hoc evaluation",
                    level_2="Scheduled evaluations",
                    level_3="Regular exercises",
                    level_4="Continuous evaluation",
                ),
            ),
            NistSubcategory(
                id="ID.IM-04",
                name="Process Effectiveness",
                description=(
                    "Incident response plans and other cybersecurity plans that "
                    "affect operations are established, communicated, maintained, "
                    "and improved."
                ),
                category_id="ID.IM",
                evidence_types=["incident_response_plan", "plan_review_log"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No plans",
                    level_1="Basic plans exist",
                    level_2="Plans documented and communicated",
                    level_3="Plans regularly tested",
                    level_4="Plans continuously improved",
                ),
            ),
        ],
    )
    id_func.categories.append(id_im)

    functions.append(id_func)

    # =========================================================================
    # PROTECT (PR) - Implement safeguards
    # =========================================================================
    pr = NistFunction(
        id="PR",
        name="Protect",
        description=(
            "Safeguards to manage the organization's cybersecurity risks are used."
        ),
        categories=[],
    )

    # PR.AA - Identity Management, Authentication, and Access Control
    pr_aa = NistCategory(
        id="PR.AA",
        name="Identity Management, Authentication, and Access Control",
        description=(
            "Access to physical and logical assets is limited to authorized users, "
            "services, and hardware and managed commensurate with the assessed risk "
            "of unauthorized access."
        ),
        function_id="PR",
        subcategories=[
            NistSubcategory(
                id="PR.AA-01",
                name="Identity Management",
                description=(
                    "Identities and credentials for authorized users, services, and "
                    "hardware are managed by the organization."
                ),
                category_id="PR.AA",
                evidence_types=["user_inventory", "identity_provider_config"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No identity management",
                    level_1="Basic user accounts",
                    level_2="Centralized identity management",
                    level_3="Automated provisioning",
                    level_4="Advanced identity governance",
                ),
            ),
            NistSubcategory(
                id="PR.AA-02",
                name="Identity Proofing",
                description=(
                    "Identities are proofed and bound to credentials based on the "
                    "context of interactions."
                ),
                category_id="PR.AA",
                evidence_types=["identity_verification_policy", "onboarding_process"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No identity proofing",
                    level_1="Basic verification",
                    level_2="Documented proofing process",
                    level_3="Risk-based proofing",
                    level_4="Continuous identity assurance",
                ),
            ),
            NistSubcategory(
                id="PR.AA-03",
                name="Authentication",
                description=(
                    "Users, services, and hardware are authenticated."
                ),
                category_id="PR.AA",
                evidence_types=["mfa_status", "authentication_logs", "sso_config"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No authentication controls",
                    level_1="Password-only authentication",
                    level_2="MFA for privileged access",
                    level_3="MFA for all users",
                    level_4="Passwordless/adaptive authentication",
                ),
            ),
            NistSubcategory(
                id="PR.AA-04",
                name="Identity Assertions",
                description=(
                    "Identity assertions are protected, conveyed, and verified."
                ),
                category_id="PR.AA",
                evidence_types=["sso_config", "saml_config", "federation_config"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No assertion protection",
                    level_1="Basic SSO",
                    level_2="Secure federation",
                    level_3="Protected assertions",
                    level_4="Zero trust assertions",
                ),
            ),
            NistSubcategory(
                id="PR.AA-05",
                name="Access Permissions",
                description=(
                    "Access permissions, entitlements, and authorizations are defined "
                    "in a policy, managed, enforced, and reviewed, and incorporate "
                    "the principles of least privilege and separation of duties."
                ),
                category_id="PR.AA",
                evidence_types=["access_policies", "rbac_config", "access_reviews"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No access management",
                    level_1="Ad-hoc permissions",
                    level_2="Role-based access",
                    level_3="Regular access reviews",
                    level_4="Just-in-time access",
                ),
            ),
            NistSubcategory(
                id="PR.AA-06",
                name="Physical Access",
                description=(
                    "Physical access to assets is managed, monitored, and enforced "
                    "commensurate with risk."
                ),
                category_id="PR.AA",
                evidence_types=["physical_access_logs", "badge_system"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No physical access control",
                    level_1="Basic locks and keys",
                    level_2="Badge access system",
                    level_3="Monitored physical access",
                    level_4="Integrated physical/logical access",
                ),
            ),
        ],
    )
    pr.categories.append(pr_aa)

    # PR.AT - Awareness and Training
    pr_at = NistCategory(
        id="PR.AT",
        name="Awareness and Training",
        description=(
            "The organization's personnel are provided with cybersecurity awareness "
            "and training so that they can perform their cybersecurity-related tasks."
        ),
        function_id="PR",
        subcategories=[
            NistSubcategory(
                id="PR.AT-01",
                name="Security Awareness",
                description=(
                    "Personnel are provided with awareness and training so that they "
                    "possess the knowledge and skills to perform general tasks with "
                    "cybersecurity risks in mind."
                ),
                category_id="PR.AT",
                evidence_types=["training_records", "awareness_program"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No security awareness",
                    level_1="Ad-hoc awareness",
                    level_2="Annual awareness training",
                    level_3="Continuous awareness program",
                    level_4="Behavior-based training",
                ),
            ),
            NistSubcategory(
                id="PR.AT-02",
                name="Specialized Training",
                description=(
                    "Individuals in specialized roles are provided with awareness "
                    "and training so that they possess the knowledge and skills to "
                    "perform relevant tasks with cybersecurity risks in mind."
                ),
                category_id="PR.AT",
                evidence_types=["role_training", "certification_records"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No specialized training",
                    level_1="Ad-hoc training",
                    level_2="Role-based training",
                    level_3="Certification requirements",
                    level_4="Continuous skill development",
                ),
            ),
        ],
    )
    pr.categories.append(pr_at)

    # PR.DS - Data Security
    pr_ds = NistCategory(
        id="PR.DS",
        name="Data Security",
        description=(
            "Data are managed consistent with the organization's risk strategy to "
            "protect the confidentiality, integrity, and availability of information."
        ),
        function_id="PR",
        subcategories=[
            NistSubcategory(
                id="PR.DS-01",
                name="Data-at-Rest Protection",
                description=(
                    "The confidentiality, integrity, and availability of data-at-rest "
                    "are protected."
                ),
                category_id="PR.DS",
                evidence_types=["encryption_status", "data_protection_config"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No data-at-rest protection",
                    level_1="Partial encryption",
                    level_2="Full disk encryption",
                    level_3="Application-level encryption",
                    level_4="Key management with HSM",
                ),
            ),
            NistSubcategory(
                id="PR.DS-02",
                name="Data-in-Transit Protection",
                description=(
                    "The confidentiality, integrity, and availability of "
                    "data-in-transit are protected."
                ),
                category_id="PR.DS",
                evidence_types=["tls_config", "network_encryption"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No transit protection",
                    level_1="Partial TLS",
                    level_2="TLS everywhere",
                    level_3="Modern TLS with HSTS",
                    level_4="Zero trust networking",
                ),
            ),
            NistSubcategory(
                id="PR.DS-10",
                name="Data-in-Use Protection",
                description=(
                    "The confidentiality, integrity, and availability of data-in-use "
                    "are protected."
                ),
                category_id="PR.DS",
                evidence_types=["dlp_config", "data_masking"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No in-use protection",
                    level_1="Basic access controls",
                    level_2="DLP deployed",
                    level_3="Advanced DLP",
                    level_4="Confidential computing",
                ),
            ),
            NistSubcategory(
                id="PR.DS-11",
                name="Data Backup",
                description=(
                    "Backups of data are created, protected, maintained, and tested."
                ),
                category_id="PR.DS",
                evidence_types=["backup_config", "backup_test_results"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No backups",
                    level_1="Ad-hoc backups",
                    level_2="Scheduled backups",
                    level_3="Tested backups",
                    level_4="Immutable backups with DR",
                ),
            ),
        ],
    )
    pr.categories.append(pr_ds)

    # PR.PS - Platform Security
    pr_ps = NistCategory(
        id="PR.PS",
        name="Platform Security",
        description=(
            "The hardware, software (e.g., firmware, operating systems, applications), "
            "and services of physical and virtual platforms are managed consistent "
            "with the organization's risk strategy to protect their confidentiality, "
            "integrity, and availability."
        ),
        function_id="PR",
        subcategories=[
            NistSubcategory(
                id="PR.PS-01",
                name="Configuration Management",
                description=(
                    "Configuration management practices are established and applied."
                ),
                category_id="PR.PS",
                evidence_types=["config_standards", "baseline_config"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No configuration management",
                    level_1="Ad-hoc configurations",
                    level_2="Documented standards",
                    level_3="Automated configuration",
                    level_4="Continuous compliance",
                ),
            ),
            NistSubcategory(
                id="PR.PS-02",
                name="Software Maintenance",
                description=(
                    "Software is maintained, replaced, and removed commensurate with "
                    "risk."
                ),
                category_id="PR.PS",
                evidence_types=["patch_status", "software_lifecycle"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No software maintenance",
                    level_1="Reactive patching",
                    level_2="Scheduled patching",
                    level_3="Risk-based patching",
                    level_4="Automated patching",
                ),
            ),
            NistSubcategory(
                id="PR.PS-03",
                name="Hardware Maintenance",
                description=(
                    "Hardware is maintained, replaced, and removed commensurate with "
                    "risk."
                ),
                category_id="PR.PS",
                evidence_types=["hardware_lifecycle", "maintenance_records"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No hardware maintenance",
                    level_1="Reactive maintenance",
                    level_2="Scheduled maintenance",
                    level_3="Proactive replacement",
                    level_4="Predictive maintenance",
                ),
            ),
            NistSubcategory(
                id="PR.PS-04",
                name="Log Records",
                description=(
                    "Log records are generated and made available for continuous "
                    "monitoring."
                ),
                category_id="PR.PS",
                evidence_types=["logging_config", "audit_logs"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No logging",
                    level_1="Basic logging",
                    level_2="Centralized logging",
                    level_3="Log analysis",
                    level_4="Real-time log intelligence",
                ),
            ),
            NistSubcategory(
                id="PR.PS-05",
                name="Software Installation",
                description=(
                    "Installation and execution of unauthorized software are "
                    "prevented."
                ),
                category_id="PR.PS",
                evidence_types=["application_control", "allowlist_config"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No software control",
                    level_1="Basic antivirus",
                    level_2="Application allowlisting",
                    level_3="Enforced allowlisting",
                    level_4="Zero trust application control",
                ),
            ),
            NistSubcategory(
                id="PR.PS-06",
                name="Secure Development",
                description=(
                    "Secure software development practices are integrated, and their "
                    "performance is monitored throughout the software development life "
                    "cycle."
                ),
                category_id="PR.PS",
                evidence_types=["sdlc_policy", "code_review_records"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No secure development",
                    level_1="Ad-hoc security review",
                    level_2="SDLC with security gates",
                    level_3="DevSecOps practices",
                    level_4="Mature DevSecOps",
                ),
            ),
        ],
    )
    pr.categories.append(pr_ps)

    # PR.IR - Technology Infrastructure Resilience
    pr_ir = NistCategory(
        id="PR.IR",
        name="Technology Infrastructure Resilience",
        description=(
            "Security architectures are managed with the organization's risk strategy "
            "to protect asset confidentiality, integrity, and availability, and "
            "organizational resilience."
        ),
        function_id="PR",
        subcategories=[
            NistSubcategory(
                id="PR.IR-01",
                name="Network Protection",
                description=(
                    "Networks and environments are protected from unauthorized "
                    "logical access and usage."
                ),
                category_id="PR.IR",
                evidence_types=["firewall_config", "network_segmentation"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No network protection",
                    level_1="Basic firewall",
                    level_2="Network segmentation",
                    level_3="Micro-segmentation",
                    level_4="Zero trust network",
                ),
            ),
            NistSubcategory(
                id="PR.IR-02",
                name="Security Architecture",
                description=(
                    "The organization's technology assets are protected from "
                    "environmental threats."
                ),
                category_id="PR.IR",
                evidence_types=["environmental_controls", "datacenter_assessment"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No environmental protection",
                    level_1="Basic protection",
                    level_2="Documented controls",
                    level_3="Monitored controls",
                    level_4="Redundant protection",
                ),
            ),
            NistSubcategory(
                id="PR.IR-03",
                name="Resilience Mechanisms",
                description=(
                    "Mechanisms are implemented to achieve resilience requirements "
                    "in normal and adverse situations."
                ),
                category_id="PR.IR",
                evidence_types=["ha_config", "dr_plan"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No resilience mechanisms",
                    level_1="Basic redundancy",
                    level_2="High availability",
                    level_3="Active-active",
                    level_4="Self-healing infrastructure",
                ),
            ),
            NistSubcategory(
                id="PR.IR-04",
                name="Capacity Resources",
                description=(
                    "Adequate resource capacity to ensure availability is maintained."
                ),
                category_id="PR.IR",
                evidence_types=["capacity_monitoring", "resource_planning"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No capacity planning",
                    level_1="Reactive capacity",
                    level_2="Capacity monitoring",
                    level_3="Proactive scaling",
                    level_4="Auto-scaling",
                ),
            ),
        ],
    )
    pr.categories.append(pr_ir)

    functions.append(pr)

    # =========================================================================
    # DETECT (DE) - Find and analyze potential cybersecurity attacks
    # =========================================================================
    de = NistFunction(
        id="DE",
        name="Detect",
        description=(
            "Possible cybersecurity attacks and compromises are found and analyzed."
        ),
        categories=[],
    )

    # DE.CM - Continuous Monitoring
    de_cm = NistCategory(
        id="DE.CM",
        name="Continuous Monitoring",
        description=(
            "Assets are monitored to find anomalies, indicators of compromise, and "
            "other potentially adverse events."
        ),
        function_id="DE",
        subcategories=[
            NistSubcategory(
                id="DE.CM-01",
                name="Network Monitoring",
                description=(
                    "Networks and network services are monitored to find potentially "
                    "adverse events."
                ),
                category_id="DE.CM",
                evidence_types=["network_monitoring", "ids_alerts"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No network monitoring",
                    level_1="Basic monitoring",
                    level_2="IDS/IPS deployed",
                    level_3="NDR capabilities",
                    level_4="AI-driven network analysis",
                ),
            ),
            NistSubcategory(
                id="DE.CM-02",
                name="Physical Environment Monitoring",
                description=(
                    "The physical environment is monitored to find potentially "
                    "adverse events."
                ),
                category_id="DE.CM",
                evidence_types=["physical_monitoring", "cctv_records"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No physical monitoring",
                    level_1="Basic alarms",
                    level_2="CCTV and sensors",
                    level_3="Monitored 24/7",
                    level_4="Integrated physical security",
                ),
            ),
            NistSubcategory(
                id="DE.CM-03",
                name="Personnel Activity Monitoring",
                description=(
                    "Personnel activity and technology usage are monitored to find "
                    "potentially adverse events."
                ),
                category_id="DE.CM",
                evidence_types=["ueba_alerts", "access_logs"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No activity monitoring",
                    level_1="Basic logging",
                    level_2="Activity monitoring",
                    level_3="UEBA deployed",
                    level_4="AI-driven behavior analysis",
                ),
            ),
            NistSubcategory(
                id="DE.CM-06",
                name="External Service Monitoring",
                description=(
                    "External service provider activities and services are monitored "
                    "to find potentially adverse events."
                ),
                category_id="DE.CM",
                evidence_types=["vendor_monitoring", "third_party_logs"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No external monitoring",
                    level_1="Ad-hoc monitoring",
                    level_2="Contractual monitoring",
                    level_3="Integrated monitoring",
                    level_4="Real-time vendor monitoring",
                ),
            ),
            NistSubcategory(
                id="DE.CM-09",
                name="Computing Hardware Monitoring",
                description=(
                    "Computing hardware and software, runtime environments, and their "
                    "data are monitored to find potentially adverse events."
                ),
                category_id="DE.CM",
                evidence_types=["endpoint_monitoring", "edr_alerts"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No endpoint monitoring",
                    level_1="Antivirus only",
                    level_2="EDR deployed",
                    level_3="XDR capabilities",
                    level_4="AI-driven endpoint security",
                ),
            ),
        ],
    )
    de.categories.append(de_cm)

    # DE.AE - Adverse Event Analysis
    de_ae = NistCategory(
        id="DE.AE",
        name="Adverse Event Analysis",
        description=(
            "Anomalies, indicators of compromise, and other potentially adverse "
            "events are analyzed to characterize the events and detect cybersecurity "
            "incidents."
        ),
        function_id="DE",
        subcategories=[
            NistSubcategory(
                id="DE.AE-02",
                name="Event Analysis",
                description=(
                    "Potentially adverse events are analyzed to better understand "
                    "associated activities."
                ),
                category_id="DE.AE",
                evidence_types=["siem_config", "security_findings"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No event analysis",
                    level_1="Ad-hoc analysis",
                    level_2="SIEM deployed",
                    level_3="Correlation rules",
                    level_4="ML-driven analysis",
                ),
            ),
            NistSubcategory(
                id="DE.AE-03",
                name="Event Correlation",
                description=(
                    "Information is correlated from multiple sources."
                ),
                category_id="DE.AE",
                evidence_types=["siem_correlation", "threat_intel_integration"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No correlation",
                    level_1="Manual correlation",
                    level_2="Basic SIEM correlation",
                    level_3="Advanced correlation",
                    level_4="Real-time threat correlation",
                ),
            ),
            NistSubcategory(
                id="DE.AE-04",
                name="Impact Estimation",
                description=(
                    "The estimated impact and scope of adverse events are understood."
                ),
                category_id="DE.AE",
                evidence_types=["incident_triage", "impact_assessment"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No impact estimation",
                    level_1="Ad-hoc estimation",
                    level_2="Documented estimation process",
                    level_3="Risk-based estimation",
                    level_4="Automated impact analysis",
                ),
            ),
            NistSubcategory(
                id="DE.AE-06",
                name="Incident Declaration",
                description=(
                    "Information on adverse events is provided to authorized staff "
                    "and tools."
                ),
                category_id="DE.AE",
                evidence_types=["alerting_config", "notification_logs"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No incident notification",
                    level_1="Ad-hoc notification",
                    level_2="Documented notification",
                    level_3="Automated alerting",
                    level_4="Intelligent alerting",
                ),
            ),
            NistSubcategory(
                id="DE.AE-07",
                name="Threat Intelligence Integration",
                description=(
                    "Cyber threat intelligence and other contextual information are "
                    "integrated into the analysis."
                ),
                category_id="DE.AE",
                evidence_types=["threat_intel_feeds", "ioc_integration"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No threat intelligence",
                    level_1="Ad-hoc intel",
                    level_2="Subscribed feeds",
                    level_3="Integrated intel",
                    level_4="Actionable intelligence",
                ),
            ),
            NistSubcategory(
                id="DE.AE-08",
                name="Incident Determination",
                description=(
                    "Incidents are declared when adverse events meet the defined "
                    "incident criteria."
                ),
                category_id="DE.AE",
                evidence_types=["incident_criteria", "incident_log"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No incident criteria",
                    level_1="Ad-hoc declaration",
                    level_2="Documented criteria",
                    level_3="Consistent declaration",
                    level_4="Automated declaration",
                ),
            ),
        ],
    )
    de.categories.append(de_ae)

    functions.append(de)

    # =========================================================================
    # RESPOND (RS) - Take action regarding detected incidents
    # =========================================================================
    rs = NistFunction(
        id="RS",
        name="Respond",
        description=(
            "Actions regarding a detected cybersecurity incident are taken."
        ),
        categories=[],
    )

    # RS.MA - Incident Management
    rs_ma = NistCategory(
        id="RS.MA",
        name="Incident Management",
        description=(
            "Responses to detected cybersecurity incidents are managed."
        ),
        function_id="RS",
        subcategories=[
            NistSubcategory(
                id="RS.MA-01",
                name="Incident Response Plan",
                description=(
                    "The incident response plan is executed in coordination with "
                    "relevant third parties once an incident is declared."
                ),
                category_id="RS.MA",
                evidence_types=["incident_response_plan", "ir_execution_logs"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No incident response plan",
                    level_1="Basic plan exists",
                    level_2="Plan documented and tested",
                    level_3="Plan regularly exercised",
                    level_4="Continuously improved plan",
                ),
            ),
            NistSubcategory(
                id="RS.MA-02",
                name="Incident Reporting",
                description=(
                    "Incident reports are triaged and validated."
                ),
                category_id="RS.MA",
                evidence_types=["incident_triage_process", "incident_log"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No triage process",
                    level_1="Ad-hoc triage",
                    level_2="Documented triage",
                    level_3="Automated triage",
                    level_4="AI-assisted triage",
                ),
            ),
            NistSubcategory(
                id="RS.MA-03",
                name="Incident Categorization",
                description=(
                    "Incidents are categorized and prioritized."
                ),
                category_id="RS.MA",
                evidence_types=["incident_classification", "priority_matrix"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No categorization",
                    level_1="Ad-hoc categorization",
                    level_2="Documented categories",
                    level_3="Consistent categorization",
                    level_4="Automated categorization",
                ),
            ),
            NistSubcategory(
                id="RS.MA-04",
                name="Incident Escalation",
                description=(
                    "Incidents are escalated or elevated as needed."
                ),
                category_id="RS.MA",
                evidence_types=["escalation_procedures", "escalation_logs"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No escalation process",
                    level_1="Ad-hoc escalation",
                    level_2="Documented escalation",
                    level_3="Automated escalation",
                    level_4="Intelligent escalation",
                ),
            ),
            NistSubcategory(
                id="RS.MA-05",
                name="Incident Forensics",
                description=(
                    "The criteria for initiating incident recovery are applied."
                ),
                category_id="RS.MA",
                evidence_types=["forensics_capability", "evidence_collection"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No forensics capability",
                    level_1="Basic forensics",
                    level_2="Documented forensics",
                    level_3="Advanced forensics",
                    level_4="Integrated forensics",
                ),
            ),
        ],
    )
    rs.categories.append(rs_ma)

    # RS.AN - Incident Analysis
    rs_an = NistCategory(
        id="RS.AN",
        name="Incident Analysis",
        description=(
            "Investigations are conducted to ensure effective response and support "
            "forensics and recovery activities."
        ),
        function_id="RS",
        subcategories=[
            NistSubcategory(
                id="RS.AN-03",
                name="Root Cause Analysis",
                description=(
                    "Analysis is performed to establish what has taken place during "
                    "an incident and the root cause of the incident."
                ),
                category_id="RS.AN",
                evidence_types=["root_cause_analysis", "incident_reports"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No root cause analysis",
                    level_1="Ad-hoc analysis",
                    level_2="Documented RCA process",
                    level_3="Systematic RCA",
                    level_4="Predictive analysis",
                ),
            ),
            NistSubcategory(
                id="RS.AN-06",
                name="Investigation Actions",
                description=(
                    "Actions performed during an investigation are recorded, and "
                    "the records' integrity and provenance are preserved."
                ),
                category_id="RS.AN",
                evidence_types=["investigation_logs", "chain_of_custody"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No investigation records",
                    level_1="Basic logging",
                    level_2="Documented procedures",
                    level_3="Chain of custody",
                    level_4="Court-admissible records",
                ),
            ),
            NistSubcategory(
                id="RS.AN-07",
                name="Incident Data Collection",
                description=(
                    "Incident data and metadata are collected, and their integrity "
                    "and provenance are preserved."
                ),
                category_id="RS.AN",
                evidence_types=["evidence_collection", "data_preservation"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No data collection",
                    level_1="Ad-hoc collection",
                    level_2="Documented collection",
                    level_3="Automated collection",
                    level_4="Comprehensive collection",
                ),
            ),
            NistSubcategory(
                id="RS.AN-08",
                name="Incident Impact",
                description=(
                    "An incident's magnitude is estimated and validated."
                ),
                category_id="RS.AN",
                evidence_types=["impact_assessment", "damage_report"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No impact estimation",
                    level_1="Ad-hoc estimation",
                    level_2="Documented estimation",
                    level_3="Quantitative estimation",
                    level_4="Real-time impact analysis",
                ),
            ),
        ],
    )
    rs.categories.append(rs_an)

    # RS.CO - Incident Response Reporting and Communication
    rs_co = NistCategory(
        id="RS.CO",
        name="Incident Response Reporting and Communication",
        description=(
            "Response activities are coordinated with internal and external "
            "stakeholders as required by laws, regulations, or policies."
        ),
        function_id="RS",
        subcategories=[
            NistSubcategory(
                id="RS.CO-02",
                name="Internal Reporting",
                description=(
                    "Internal and external stakeholders are notified of incidents."
                ),
                category_id="RS.CO",
                evidence_types=["notification_procedures", "communication_logs"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No notification process",
                    level_1="Ad-hoc notification",
                    level_2="Documented notification",
                    level_3="Automated notification",
                    level_4="Integrated communication",
                ),
            ),
            NistSubcategory(
                id="RS.CO-03",
                name="Information Sharing",
                description=(
                    "Information is shared with designated internal and external "
                    "stakeholders."
                ),
                category_id="RS.CO",
                evidence_types=["information_sharing_policy", "sharing_logs"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No information sharing",
                    level_1="Ad-hoc sharing",
                    level_2="Documented sharing",
                    level_3="Structured sharing",
                    level_4="Real-time sharing",
                ),
            ),
        ],
    )
    rs.categories.append(rs_co)

    # RS.MI - Incident Mitigation
    rs_mi = NistCategory(
        id="RS.MI",
        name="Incident Mitigation",
        description=(
            "Activities are performed to prevent expansion of an event and to "
            "mitigate its effects."
        ),
        function_id="RS",
        subcategories=[
            NistSubcategory(
                id="RS.MI-01",
                name="Containment",
                description=(
                    "Incidents are contained."
                ),
                category_id="RS.MI",
                evidence_types=["containment_procedures", "containment_logs"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No containment capability",
                    level_1="Ad-hoc containment",
                    level_2="Documented containment",
                    level_3="Rapid containment",
                    level_4="Automated containment",
                ),
            ),
            NistSubcategory(
                id="RS.MI-02",
                name="Eradication",
                description=(
                    "Incidents are eradicated."
                ),
                category_id="RS.MI",
                evidence_types=["eradication_procedures", "eradication_logs"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No eradication capability",
                    level_1="Ad-hoc eradication",
                    level_2="Documented eradication",
                    level_3="Systematic eradication",
                    level_4="Verified eradication",
                ),
            ),
        ],
    )
    rs.categories.append(rs_mi)

    functions.append(rs)

    # =========================================================================
    # RECOVER (RC) - Restore capabilities reduced by cybersecurity incidents
    # =========================================================================
    rc = NistFunction(
        id="RC",
        name="Recover",
        description=(
            "Assets and operations affected by a cybersecurity incident are restored."
        ),
        categories=[],
    )

    # RC.RP - Incident Recovery Plan Execution
    rc_rp = NistCategory(
        id="RC.RP",
        name="Incident Recovery Plan Execution",
        description=(
            "Restoration activities are performed to ensure operational availability "
            "of systems and services affected by cybersecurity incidents."
        ),
        function_id="RC",
        subcategories=[
            NistSubcategory(
                id="RC.RP-01",
                name="Recovery Plan Execution",
                description=(
                    "The recovery portion of the incident response plan is executed "
                    "once initiated from the incident response process."
                ),
                category_id="RC.RP",
                evidence_types=["recovery_plan", "recovery_logs"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No recovery plan",
                    level_1="Basic plan exists",
                    level_2="Documented plan",
                    level_3="Tested plan",
                    level_4="Automated recovery",
                ),
            ),
            NistSubcategory(
                id="RC.RP-02",
                name="Recovery Selection",
                description=(
                    "Recovery actions are selected, scoped, prioritized, and "
                    "performed."
                ),
                category_id="RC.RP",
                evidence_types=["recovery_procedures", "prioritization_criteria"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No recovery prioritization",
                    level_1="Ad-hoc recovery",
                    level_2="Documented recovery",
                    level_3="Risk-based recovery",
                    level_4="Optimized recovery",
                ),
            ),
            NistSubcategory(
                id="RC.RP-03",
                name="Backup Integrity",
                description=(
                    "The integrity of backups and other restoration assets is "
                    "verified before using them for restoration."
                ),
                category_id="RC.RP",
                evidence_types=["backup_verification", "integrity_checks"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No backup verification",
                    level_1="Ad-hoc verification",
                    level_2="Regular verification",
                    level_3="Automated verification",
                    level_4="Continuous integrity monitoring",
                ),
            ),
            NistSubcategory(
                id="RC.RP-04",
                name="Critical Function Consideration",
                description=(
                    "Critical mission functions and cybersecurity risk management "
                    "are considered to establish post-incident operational norms."
                ),
                category_id="RC.RP",
                evidence_types=["business_continuity_plan", "operational_norms"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No post-incident planning",
                    level_1="Ad-hoc planning",
                    level_2="Documented planning",
                    level_3="Integrated planning",
                    level_4="Adaptive planning",
                ),
            ),
            NistSubcategory(
                id="RC.RP-05",
                name="Restoration Verification",
                description=(
                    "The integrity of restored assets is verified, systems and "
                    "services are restored, and normal operating status is confirmed."
                ),
                category_id="RC.RP",
                evidence_types=["restoration_verification", "system_validation"],
                api_collectible=True,
                maturity_criteria=MaturityCriteria(
                    level_0="No restoration verification",
                    level_1="Ad-hoc verification",
                    level_2="Documented verification",
                    level_3="Comprehensive verification",
                    level_4="Automated verification",
                ),
            ),
            NistSubcategory(
                id="RC.RP-06",
                name="Recovery End Declaration",
                description=(
                    "The end of incident recovery is declared based on criteria, "
                    "and incident-related documentation is completed."
                ),
                category_id="RC.RP",
                evidence_types=["recovery_completion", "incident_closure"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No closure process",
                    level_1="Ad-hoc closure",
                    level_2="Documented closure",
                    level_3="Systematic closure",
                    level_4="Comprehensive post-incident review",
                ),
            ),
        ],
    )
    rc.categories.append(rc_rp)

    # RC.CO - Incident Recovery Communication
    rc_co = NistCategory(
        id="RC.CO",
        name="Incident Recovery Communication",
        description=(
            "Restoration activities are coordinated with internal and external "
            "parties."
        ),
        function_id="RC",
        subcategories=[
            NistSubcategory(
                id="RC.CO-03",
                name="Recovery Communication",
                description=(
                    "Recovery activities and progress in restoring operational "
                    "capabilities are communicated to designated internal and "
                    "external stakeholders."
                ),
                category_id="RC.CO",
                evidence_types=["recovery_communication", "status_reports"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No recovery communication",
                    level_1="Ad-hoc communication",
                    level_2="Documented communication",
                    level_3="Regular status updates",
                    level_4="Real-time dashboards",
                ),
            ),
            NistSubcategory(
                id="RC.CO-04",
                name="Public Communication",
                description=(
                    "Public updates on incident recovery are shared using approved "
                    "methods and messaging."
                ),
                category_id="RC.CO",
                evidence_types=["public_communication_plan", "press_releases"],
                api_collectible=False,
                maturity_criteria=MaturityCriteria(
                    level_0="No public communication plan",
                    level_1="Ad-hoc public updates",
                    level_2="Approved messaging",
                    level_3="Coordinated PR response",
                    level_4="Crisis communication program",
                ),
            ),
        ],
    )
    rc.categories.append(rc_co)

    functions.append(rc)

    return functions


# Build the control hierarchy
_CSF2_FUNCTIONS = _build_csf2_controls()

# Build lookup indices
_FUNCTION_INDEX: dict[str, NistFunction] = {f.id: f for f in _CSF2_FUNCTIONS}
_CATEGORY_INDEX: dict[str, NistCategory] = {}
_SUBCATEGORY_INDEX: dict[str, NistSubcategory] = {}
_EVIDENCE_TYPE_INDEX: dict[str, list[NistSubcategory]] = {}

for func in _CSF2_FUNCTIONS:
    for cat in func.categories:
        _CATEGORY_INDEX[cat.id] = cat
        for subcat in cat.subcategories:
            _SUBCATEGORY_INDEX[subcat.id] = subcat
            for ev_type in subcat.evidence_types:
                if ev_type not in _EVIDENCE_TYPE_INDEX:
                    _EVIDENCE_TYPE_INDEX[ev_type] = []
                _EVIDENCE_TYPE_INDEX[ev_type].append(subcat)


# =============================================================================
# PUBLIC API
# =============================================================================

def get_function(function_id: str) -> NistFunction | None:
    """
    Get a NIST function by ID.

    Args:
        function_id: Function identifier (GV, ID, PR, DE, RS, RC)

    Returns:
        NistFunction if found, None otherwise.
    """
    return _FUNCTION_INDEX.get(function_id.upper())


def get_category(category_id: str) -> NistCategory | None:
    """
    Get a NIST category by ID.

    Args:
        category_id: Category identifier (e.g., "GV.OC", "PR.AA")

    Returns:
        NistCategory if found, None otherwise.
    """
    return _CATEGORY_INDEX.get(category_id.upper())


def get_subcategory(subcategory_id: str) -> NistSubcategory | None:
    """
    Get a NIST subcategory by ID.

    Args:
        subcategory_id: Subcategory identifier (e.g., "GV.OC-01", "PR.AA-03")

    Returns:
        NistSubcategory if found, None otherwise.
    """
    return _SUBCATEGORY_INDEX.get(subcategory_id.upper())


def get_all_functions() -> list[NistFunction]:
    """
    Get all NIST CSF 2.0 functions.

    Returns:
        List of all 6 functions.
    """
    return list(_CSF2_FUNCTIONS)


def get_all_categories() -> list[NistCategory]:
    """
    Get all NIST CSF 2.0 categories.

    Returns:
        List of all 22 categories.
    """
    return list(_CATEGORY_INDEX.values())


def get_all_subcategories() -> list[NistSubcategory]:
    """
    Get all NIST CSF 2.0 subcategories.

    Returns:
        List of all 106 subcategories.
    """
    return list(_SUBCATEGORY_INDEX.values())


def get_subcategories_by_evidence_type(evidence_type: str) -> list[NistSubcategory]:
    """
    Get all subcategories that can be satisfied by a specific evidence type.

    Args:
        evidence_type: Evidence type (e.g., "mfa_status", "access_logs")

    Returns:
        List of subcategories that accept this evidence type.
    """
    return _EVIDENCE_TYPE_INDEX.get(evidence_type.lower(), [])


def get_api_collectible_subcategories() -> list[NistSubcategory]:
    """
    Get all subcategories where evidence can be collected via API.

    Returns:
        List of API-collectible subcategories.
    """
    return [s for s in _SUBCATEGORY_INDEX.values() if s.api_collectible]


def get_manual_evidence_subcategories() -> list[NistSubcategory]:
    """
    Get all subcategories that require manual evidence upload.

    Returns:
        List of subcategories requiring manual evidence.
    """
    return [s for s in _SUBCATEGORY_INDEX.values() if not s.api_collectible]


def get_evidence_types() -> list[str]:
    """
    Get all unique evidence types referenced in the control definitions.

    Returns:
        Sorted list of evidence type identifiers.
    """
    return sorted(_EVIDENCE_TYPE_INDEX.keys())


def get_statistics() -> dict[str, int]:
    """
    Get statistics about the NIST CSF 2.0 control definitions.

    Returns:
        Dictionary with counts of functions, categories, subcategories,
        API-collectible controls, and unique evidence types.
    """
    api_collectible = sum(1 for s in _SUBCATEGORY_INDEX.values() if s.api_collectible)
    return {
        "functions": len(_FUNCTION_INDEX),
        "categories": len(_CATEGORY_INDEX),
        "subcategories": len(_SUBCATEGORY_INDEX),
        "api_collectible": api_collectible,
        "manual_evidence": len(_SUBCATEGORY_INDEX) - api_collectible,
        "evidence_types": len(_EVIDENCE_TYPE_INDEX),
    }


def export_controls_json(path: Path | str) -> None:
    """
    Export the complete control hierarchy to a JSON file.

    Args:
        path: Output file path.
    """
    path = Path(path)

    data = {
        "version": "2.0",
        "source": "NIST Cybersecurity Framework 2.0",
        "last_updated": "2024-02-26",
        "functions": [f.to_dict() for f in _CSF2_FUNCTIONS],
        "statistics": get_statistics(),
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
