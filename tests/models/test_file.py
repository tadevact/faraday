'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import pytest
from faraday.server.models import File
from depot.manager import DepotManager

from tests.conftest import TEST_DATA_PATH


@pytest.fixture
def depotfile():
    """Creates and stores a PNG file in the default depot.
    
    Args:
        None
    
    Returns:
        str: The file ID of the stored PNG file.
    
    Raises:
        IOError: If there's an error reading the PNG file.
        DepotError: If there's an error creating the file in the depot.
    """
    depot = DepotManager.get('default')
    png_file_path = TEST_DATA_PATH / 'faraday.png'

    with png_file_path.open('rb') as fp:
        fileid = depot.create(fp, 'faraday.png', 'image/png')
    return fileid


@pytest.mark.usefixtures('app')  # To load depot config
def test_get_vulnweb_evidence(vulnerability_web_factory, depotfile, session):
    # Use vuln web to ensure its parent is a service and not a host
    """Test the retrieval of web vulnerability evidence.
    
    This method tests the functionality of getting evidence (files) associated with a specific web vulnerability. It creates multiple vulnerabilities and files, but ensures only the correct file is associated as evidence for the target vulnerability.
    
    Args:
        vulnerability_web_factory (Factory): A factory for creating web vulnerability objects.
        depotfile (File-like object): A file-like object to be used as content for the created files.
        session (Session): The database session for committing changes.
    
    Returns:
        None: This method doesn't return anything. It uses assertions to verify the correct behavior.
    
    Raises:
        AssertionError: If the vulnerability's evidence does not match the expected file.
    """
    all_vulns = vulnerability_web_factory.create_batch(10)
    session.commit()
    vuln = all_vulns[0]

    correct_file = File(filename='faraday.png', object_id=vuln.id,
                        object_type='vulnerability', content=depotfile)
    session.add(File(filename='faraday.png',
                     object_id=vuln.service_id,
                     object_type='service', content=depotfile))
    session.add(correct_file)

    for other_vuln in all_vulns[1:]:
        session.add(File(filename='faraday.png', object_id=other_vuln.id,
                         object_type='vulnerability', content=depotfile))
        session.add(File(filename='faraday.png',
                         object_id=other_vuln.service_id,
                         object_type='service', content=depotfile))

    session.commit()
    assert vuln.evidence == [correct_file]


@pytest.mark.skip(reason='write to instrumentedlist not implemented')
@pytest.mark.usefixtures('app')  # To load depot config
def test_add_vulnweb_evidence(vulnerability_web, depotfile, session):
    """Tests the addition of web vulnerability evidence.
    
    This method tests the functionality of adding evidence to a web vulnerability
    object. It creates a file, appends it to the vulnerability's evidence, and
    then verifies that the evidence was correctly added and associated with the
    vulnerability.
    
    Args:
        vulnerability_web (VulnerabilityWeb): The web vulnerability object to which
            evidence will be added.
        depotfile (DepotFile): The file object containing the evidence data.
        session (Session): The database session used for committing changes.
    
    Returns:
        None
    
    Raises:
        AssertionError: If the evidence is not correctly added or associated
            with the vulnerability.
    """
    session.commit()
    file_ = File(filename='faraday.png', content=depotfile)
    vulnerability_web.evidence.append(file_)
    session.commit()
    assert len(vulnerability_web.evidence) == 1
    assert vulnerability_web.evidence[0].object_type == 'vulnerability'
    assert vulnerability_web.evidence[0].object_id == vulnerability_web.id
