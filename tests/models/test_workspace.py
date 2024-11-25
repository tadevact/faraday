'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from faraday.server.models import db, Workspace
from tests.factories import (
    HostFactory,
    ServiceFactory,
    SourceCodeFactory,
    VulnerabilityFactory,
    VulnerabilityCodeFactory,
    VulnerabilityWebFactory,
)


C_SOURCE_CODE_VULN_COUNT = 3
C_STANDARD_VULN_COUNT = [6, 2]  # With host parent and with service parent
C_WEB_VULN_COUNT = 5

NC_SOURCE_CODE_VULN_COUNT = 1
NC_STANDARD_VULN_COUNT = [1, 2]  # With host parent and with service parent
NC_WEB_VULN_COUNT = 2

SOURCE_CODE_VULN_COUNT = C_SOURCE_CODE_VULN_COUNT + NC_SOURCE_CODE_VULN_COUNT
STANDARD_VULN_COUNT = C_STANDARD_VULN_COUNT + NC_STANDARD_VULN_COUNT
WEB_VULN_COUNT = C_WEB_VULN_COUNT + NC_WEB_VULN_COUNT


def populate_workspace(workspace):
    """Populates a workspace with various entities and vulnerabilities.
    
    This method creates a host, service, and source code for the given workspace,
    then generates both confirmed and non-confirmed vulnerabilities of different types
    (standard, web, and source code) associated with these entities.
    
    Args:
        workspace: The workspace object to populate with entities and vulnerabilities.
    
    Returns:
        None
    
    """
    host = HostFactory.create(workspace=workspace)
    service = ServiceFactory.create(workspace=workspace, host=host)
    code = SourceCodeFactory.create(workspace=workspace)

    # Create non confirmed vulnerabilities

    # Create standard vulns
    VulnerabilityFactory.create_batch(
        NC_STANDARD_VULN_COUNT[0], workspace=workspace, host=host,
        service=None, confirmed=False)
    VulnerabilityFactory.create_batch(
        NC_STANDARD_VULN_COUNT[1], workspace=workspace, service=service,
        host=None, confirmed=False)

    # Create web vulns
    VulnerabilityWebFactory.create_batch(
        NC_WEB_VULN_COUNT, workspace=workspace, service=service,
        confirmed=False)

    # Create source code vulns
    VulnerabilityCodeFactory.create_batch(
        NC_SOURCE_CODE_VULN_COUNT, workspace=workspace, source_code=code,
        confirmed=False)

    # Create confirmed vulnerabilities

    # Create standard vulns
    VulnerabilityFactory.create_batch(
        C_STANDARD_VULN_COUNT[0], workspace=workspace, host=host, service=None,
        confirmed=True)
    VulnerabilityFactory.create_batch(
        C_STANDARD_VULN_COUNT[1], workspace=workspace, service=service,
        host=None, confirmed=True)

    # Create web vulns
    VulnerabilityWebFactory.create_batch(
        C_WEB_VULN_COUNT, workspace=workspace, service=service, confirmed=True)

    # Create source code vulns
    VulnerabilityCodeFactory.create_batch(
        C_SOURCE_CODE_VULN_COUNT, workspace=workspace, source_code=code,
        confirmed=True)

    db.session.commit()


def test_vuln_count(workspace, second_workspace, database):
    """Tests the vulnerability count functionality for a workspace.
    
    Args:
        workspace (Workspace): The primary workspace to test.
        second_workspace (Workspace): A secondary workspace for comparison.
        database (Database): The database connection object.
    
    Returns:
        None
    
    Raises:
        AssertionError: If the vulnerability counts do not match the expected values.
    
    Note:
        This test is skipped for SQLite databases.
    """
    if database.engine.dialect.name == 'sqlite':
        return
    populate_workspace(workspace)
    populate_workspace(second_workspace)
    workspace = Workspace.query_with_count(None, workspace_name=workspace.name).fetchone()
    assert workspace['vulnerability_web_count'] == WEB_VULN_COUNT
    assert workspace['vulnerability_code_count'] == SOURCE_CODE_VULN_COUNT
    assert workspace['vulnerability_standard_count'] == sum(
        STANDARD_VULN_COUNT)
    assert workspace['vulnerability_total_count'] == (
        sum(STANDARD_VULN_COUNT) + WEB_VULN_COUNT + SOURCE_CODE_VULN_COUNT
    )


def test_vuln_count_confirmed(workspace, second_workspace, database):
    """Test vulnerability count confirmation for a workspace
    
    This method tests the vulnerability count functionality for a given workspace.
    It populates the workspace and a second workspace, then queries the database
    to confirm that the vulnerability counts match the expected values.
    
    Args:
        workspace (Workspace): The primary workspace to test
        second_workspace (Workspace): A secondary workspace for comparison
        database (Database): The database connection object
    
    Returns:
        None
    
    Note:
        This test is skipped for SQLite databases.
    """
    if database.engine.dialect.name == 'sqlite':
        return
    populate_workspace(workspace)
    populate_workspace(second_workspace)
    workspace = Workspace.query_with_count(True, workspace_name=workspace.name).fetchone()
    workspace = dict(workspace)
    assert workspace['vulnerability_web_count'] == C_WEB_VULN_COUNT
    assert workspace['vulnerability_code_count'] == C_SOURCE_CODE_VULN_COUNT
    assert workspace['vulnerability_standard_count'] == sum(
        C_STANDARD_VULN_COUNT)
    assert workspace['vulnerability_total_count'] == (
        sum(C_STANDARD_VULN_COUNT) + C_WEB_VULN_COUNT + C_SOURCE_CODE_VULN_COUNT
    )


def test_vuln_no_count(workspace, second_workspace, database):
    """Tests vulnerability counts when they are not set.
    
    This method checks if the vulnerability counts (web, code, standard, and total) are None for a workspace after populating it. It skips the test for SQLite databases.
    
    Args:
        workspace (Workspace): The primary workspace to be tested.
        second_workspace (Workspace): A secondary workspace to be populated.
        database (Database): The database object to check the dialect.
    
    Returns:
        None
    
    Raises:
        AssertionError: If any of the vulnerability counts are not None.
    
    Note:
        This test is skipped for SQLite databases.
    """
    if database.engine.dialect.name == 'sqlite':
        return

    populate_workspace(workspace)
    populate_workspace(second_workspace)
    workspace = Workspace.query.get(workspace.id)
    assert workspace.vulnerability_web_count is None
    assert workspace.vulnerability_code_count is None
    assert workspace.vulnerability_standard_count is None
    assert workspace.vulnerability_total_count is None
