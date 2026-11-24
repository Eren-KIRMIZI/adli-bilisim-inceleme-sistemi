"""Unit tests for theme tokens and stylesheet generation."""

from src.ui.styles.tokens import get_theme, build_qss, LIGHT_THEME, DARK_THEME

def test_theme_tokens_structure():
    light = get_theme("light")
    dark = get_theme("dark")

    # Verify key tokens exist
    for key in ["bg", "surface", "text", "accent", "verified", "warning", "critical", "border"]:
        assert key in light
        assert key in dark

    assert light["bg"] == "#F5F5F7"
    assert light["surface"] == "#FFFFFF"
    assert light["text"] == "#1D2733"
    assert light["accent"] == "#315C85"

def test_build_qss():
    light_qss = build_qss("light")
    assert "background-color: #F5F5F7" in light_qss
    assert "QPushButton" in light_qss
    assert "QTableWidget" in light_qss

    dark_qss = build_qss("dark")
    assert "background-color: #111418" in dark_qss
    assert "color: #E8ECF2" in dark_qss
