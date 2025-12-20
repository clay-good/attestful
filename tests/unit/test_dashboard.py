"""Tests for the dashboard module (Section 14)."""

import pytest
from pathlib import Path
import tempfile


class TestDashboardExport:
    """Test static dashboard export functionality."""

    def test_export_static_dashboard(self):
        """Test exporting dashboard as static HTML."""
        from attestful.dashboard.app import export_static_dashboard

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "test_dashboard.html"
            result = export_static_dashboard(output_path)

            assert result.exists()
            assert result.suffix == ".html"

            content = result.read_text()

            # Check for key elements per Section 14
            assert "<!DOCTYPE html>" in content
            assert "Attestful" in content
            assert "SOC 2 Type II" in content

            # Check for monochrome color palette (Section 14.2.1)
            assert "#FFFFFF" in content  # Light background
            assert "#0A0A0A" in content  # Dark background
            assert "#F5F5F5" in content  # Card background
            assert "#3B82F6" in content  # Accent color

            # Check for status colors
            assert "#10B981" in content  # Pass (green)
            assert "#EF4444" in content  # Fail (red)
            assert "#F59E0B" in content  # Warning (amber)

    def test_export_dashboard_includes_theme_toggle(self):
        """Test that static export includes light/dark mode toggle."""
        from attestful.dashboard.app import export_static_dashboard

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "dashboard.html"
            result = export_static_dashboard(output_path)

            content = result.read_text()

            # Check for theme toggle functionality
            assert "toggleTheme" in content
            assert "data-theme" in content
            assert "localStorage" in content
            assert "attestful-theme" in content

    def test_export_dashboard_includes_frameworks(self):
        """Test that static export includes all frameworks."""
        from attestful.dashboard.app import export_static_dashboard

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "dashboard.html"
            result = export_static_dashboard(output_path)

            content = result.read_text()

            # Check for all 5 frameworks per Section 1.3
            assert "SOC 2" in content
            assert "NIST CSF" in content
            assert "NIST 800-53" in content
            assert "ISO 27001" in content
            assert "HITRUST" in content

    def test_export_dashboard_includes_category_breakdown(self):
        """Test that static export includes category breakdown with progress bars."""
        from attestful.dashboard.app import export_static_dashboard

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "dashboard.html"
            result = export_static_dashboard(output_path)

            content = result.read_text()

            # Check for category breakdown (Section 14.3.3)
            assert "Category Breakdown" in content
            assert "category-bar" in content
            assert "category-item" in content

            # SOC 2 categories
            assert "Security" in content
            assert "Availability" in content
            assert "Confidentiality" in content

    def test_export_dashboard_includes_platform_status(self):
        """Test that static export includes platform status grid."""
        from attestful.dashboard.app import export_static_dashboard

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "dashboard.html"
            result = export_static_dashboard(output_path)

            content = result.read_text()

            # Check for platform grid (Section 14.4.1)
            assert "platform-grid" in content
            assert "platform-status" in content

            # Check for some platforms
            assert "AWS" in content
            assert "Okta" in content
            assert "GitHub" in content

    def test_export_dashboard_includes_evidence_stats(self):
        """Test that static export includes evidence statistics."""
        from attestful.dashboard.app import export_static_dashboard

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "dashboard.html"
            result = export_static_dashboard(output_path)

            content = result.read_text()

            # Check for evidence stats (Section 14.4.3)
            assert "Evidence Summary" in content
            assert "Total Items" in content
            assert "Today" in content
            assert "This Week" in content
            assert "This Month" in content

    def test_export_dashboard_responsive_design(self):
        """Test that static export includes responsive CSS."""
        from attestful.dashboard.app import export_static_dashboard

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "dashboard.html"
            result = export_static_dashboard(output_path)

            content = result.read_text()

            # Check for responsive breakpoints (Section 14.2.4)
            assert "@media" in content
            assert "max-width: 1024px" in content
            assert "max-width: 640px" in content


class TestDashboardData:
    """Test dashboard data generation."""

    def test_sample_compliance_data_structure(self):
        """Test that sample data has correct structure."""
        from attestful.dashboard.app import get_sample_compliance_data

        data = get_sample_compliance_data()

        # Check top-level structure
        assert "frameworks" in data
        assert "platforms" in data
        assert "evidence_stats" in data

        # Check frameworks
        frameworks = data["frameworks"]
        assert "soc2" in frameworks
        assert "nist-csf" in frameworks
        assert "nist-800-53" in frameworks
        assert "iso-27001" in frameworks
        assert "hitrust" in frameworks

        # Check framework data structure
        soc2 = frameworks["soc2"]
        assert "name" in soc2
        assert "compliance_pct" in soc2
        assert "trend" in soc2
        assert "last_assessed" in soc2
        assert "categories" in soc2
        assert "total_controls" in soc2
        assert "controls_with_evidence" in soc2
        assert "controls_missing" in soc2

    def test_sample_platforms_data(self):
        """Test that platforms data has correct structure."""
        from attestful.dashboard.app import get_sample_compliance_data

        data = get_sample_compliance_data()
        platforms = data["platforms"]

        # Check platform structure
        for platform_id, platform_data in platforms.items():
            assert "name" in platform_data
            assert "status" in platform_data
            assert platform_data["status"] in ["connected", "error", "not_configured"]

    def test_sample_evidence_stats(self):
        """Test that evidence stats have correct structure."""
        from attestful.dashboard.app import get_sample_compliance_data

        data = get_sample_compliance_data()
        stats = data["evidence_stats"]

        assert "total" in stats
        assert "today" in stats
        assert "this_week" in stats
        assert "this_month" in stats

        # Values should be reasonable
        assert stats["total"] > stats["this_month"]
        assert stats["this_month"] >= stats["this_week"]
        assert stats["this_week"] >= stats["today"]


class TestDashboardColors:
    """Test dashboard color palette (Section 14.2.1)."""

    def test_color_constants(self):
        """Test that color constants match specification."""
        from attestful.dashboard.app import COLORS

        # Light mode
        assert COLORS["light"]["background"] == "#FFFFFF"
        assert COLORS["light"]["card_bg"] == "#F5F5F5"
        assert COLORS["light"]["border"] == "#E5E5E5"
        assert COLORS["light"]["text_primary"] == "#0A0A0A"
        assert COLORS["light"]["text_secondary"] == "#6B7280"

        # Dark mode
        assert COLORS["dark"]["background"] == "#0A0A0A"
        assert COLORS["dark"]["card_bg"] == "#1A1A1A"
        assert COLORS["dark"]["border"] == "#2A2A2A"
        assert COLORS["dark"]["text_primary"] == "#FAFAFA"
        assert COLORS["dark"]["text_secondary"] == "#6B7280"

        # Accent
        assert COLORS["accent"] == "#3B82F6"

        # Status colors
        assert COLORS["status"]["pass"] == "#10B981"
        assert COLORS["status"]["fail"] == "#EF4444"
        assert COLORS["status"]["warning"] == "#F59E0B"


class TestDashboardTypography:
    """Test dashboard typography (Section 14.2.2)."""

    def test_font_constants(self):
        """Test that font constants match specification."""
        from attestful.dashboard.app import FONTS, FONT_SIZES

        # Fonts
        assert "apple-system" in FONTS["primary"]
        assert "Segoe UI" in FONTS["primary"]
        assert "SF Mono" in FONTS["monospace"]

        # Font sizes
        assert FONT_SIZES["hero"] == "72px"
        assert FONT_SIZES["hero_mobile"] == "48px"
        assert FONT_SIZES["heading"] == "24px"
        assert FONT_SIZES["section"] == "18px"
        assert FONT_SIZES["body"] == "14px"
        assert FONT_SIZES["small"] == "12px"


class TestCLIDashboardCommands:
    """Test CLI dashboard commands."""

    def test_dashboard_help(self):
        """Test dashboard help command."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", "--help"])

        assert result.exit_code == 0
        assert "Launch and manage the compliance dashboard" in result.output
        assert "export" in result.output
        assert "serve" in result.output

    def test_dashboard_export_help(self):
        """Test dashboard export help command."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", "export", "--help"])

        assert result.exit_code == 0
        assert "static HTML" in result.output
        assert "--output" in result.output

    def test_dashboard_export_command(self):
        """Test dashboard export command execution."""
        from click.testing import CliRunner
        from attestful.cli.main import cli
        import tempfile

        runner = CliRunner()

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = f"{tmpdir}/test_output.html"
            result = runner.invoke(cli, ["dashboard", "export", "-o", output_path])

            assert result.exit_code == 0
            assert "Dashboard exported" in result.output
            assert Path(output_path).exists()

    def test_dashboard_serve_help(self):
        """Test dashboard serve help command."""
        from click.testing import CliRunner
        from attestful.cli.main import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["dashboard", "serve", "--help"])

        assert result.exit_code == 0
        assert "interactive dashboard" in result.output
        assert "--host" in result.output
        assert "--port" in result.output
        assert "--debug" in result.output
