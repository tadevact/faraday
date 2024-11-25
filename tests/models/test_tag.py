'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from faraday.server.models import TagObject


def test_vulnweb_tags(vulnerability_web_factory, tag_factory, session):
    # Use vuln web to ensure its parent is a service and not a host
    """Test vulnerability web tags
    
    This method tests the tagging functionality for web vulnerabilities. It creates multiple vulnerabilities,
    associates tags with them, and verifies that the correct tags are assigned to a specific vulnerability.
    
    Args:
        vulnerability_web_factory (Factory): A factory for creating web vulnerability objects
        tag_factory (Factory): A factory for creating tag objects
        session (Session): The database session object for managing transactions
    
    Returns:
        None: This method doesn't return anything explicitly, but uses assertions to verify the correct behavior
    
    Raises:
        AssertionError: If the tags associated with the test vulnerability don't match the expected set of tags
    """
    all_vulns = vulnerability_web_factory.create_batch(10)
    session.commit()
    vuln = all_vulns[0]

    correct_tags = tag_factory.create_batch(3)
    for tag in correct_tags:
        session.add(TagObject(tag=tag, object_type='vulnerability',
                              object_id=vuln.id))
    session.add(TagObject(tag=tag_factory.create(),
                          object_type='service',
                          object_id=vuln.service_id))
    for other_vuln in all_vulns[5:]:
        session.add(TagObject(tag=correct_tags[1], object_type='vulnerability',
                              object_id=other_vuln.id))
        session.add(TagObject(tag=tag_factory.create(),
                              object_type='vulnerability',
                              object_id=other_vuln.id))

    session.commit()
    assert vuln.tags == set(correct_tags)
