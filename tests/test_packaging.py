import ast
import os
import subprocess
from pathlib import Path


def test_build_script_exists_and_is_executable():
    p = Path('build.sh')
    assert p.exists(), "build.sh not found"
    assert os.access(p, os.X_OK), "build.sh not executable"


def test_build_script_syntax():
    result = subprocess.run(['bash', '-n', 'build.sh'], capture_output=True, text=True)
    assert result.returncode == 0, f"bash -n failed:\n{result.stderr}"


def test_tool_versions_defines_all_tools():
    content = Path('packaging/tool_versions.sh').read_text()
    for tool in ['SUBFINDER', 'DNSX', 'NAABU', 'HTTPX', 'KATANA', 'NUCLEI']:
        assert f'{tool}_VERSION=' in content, f"{tool}_VERSION missing"


def test_deb_control_has_required_fields():
    content = Path('packaging/deb/DEBIAN/control').read_text()
    assert 'Package: secureops' in content
    assert 'Architecture: amd64' in content
    assert 'Depends:' in content
    for dep in ['nmap', 'nikto', 'testssl.sh']:
        assert dep in content, f"Depends missing: {dep}"


def test_deb_postinst_is_shell_script():
    content = Path('packaging/deb/DEBIAN/postinst').read_text()
    assert content.startswith('#!/bin/sh')
    assert 'chmod' in content
    assert os.access(Path('packaging/deb/DEBIAN/postinst'), os.X_OK), "postinst must be executable"


def test_apprun_is_shell_script_that_launches_secureops():
    content = Path('packaging/appimage/AppRun').read_text()
    assert content.startswith('#!/bin/sh')
    assert 'secureops' in content


def test_desktop_file_has_required_fields():
    content = Path('packaging/appimage/secureops.desktop').read_text()
    assert '[Desktop Entry]' in content
    assert 'Name=SecureOps' in content
    assert 'Type=Application' in content
    assert 'Categories=' in content


def test_icon_svg_exists_and_is_xml():
    import xml.etree.ElementTree as ET
    content = Path('packaging/appimage/secureops.svg').read_text()
    assert '<svg' in content
    ET.fromstring(content)  # raises ParseError if malformed


def test_pyinstaller_spec_exists_and_is_valid_python():
    content = Path('secureops.spec').read_text()
    ast.parse(content)


def test_gitignore_excludes_dist():
    content = Path('.gitignore').read_text()
    assert 'dist/' in content
