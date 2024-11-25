'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import random

import pytest
from functools import partial
from posixpath import join as urljoin

from faraday.server.models import Hostname, Host
from faraday.server.api.modules.hosts import HostsView
from faraday.server.tasks import update_host_stats

from tests.test_api_workspaced_base import (
    ReadOnlyAPITests)
from tests import factories


@pytest.mark.parametrize(
    "with_host_vulns,with_service_vulns", [[True, False],
                                           [False, True],
                                           [True, True]],
    ids=["with host vulnerabilities",
         "with service vulnerabilities",
         "with host and service vulnerabilities"]
)
def test_vulnerability_count(with_host_vulns, with_service_vulns, host,
                             session, service_factory,
                             vulnerability_factory, vulnerability_web_factory):
    """Test the vulnerability count calculation for a host.
    
    This method creates host and service vulnerabilities based on the input parameters
    and checks if the host's vulnerability count matches the expected count.
    
    Args:
        with_host_vulns (bool): Flag to create host vulnerabilities.
        with_service_vulns (bool): Flag to create service vulnerabilities.
        host (Host): The host object to test.
        session (Session): The database session.
        service_factory (Factory): Factory to create service objects.
        vulnerability_factory (Factory): Factory to create vulnerability objects.
        vulnerability_web_factory (Factory): Factory to create web vulnerability objects.
    
    Returns:
        None
    
    Raises:
        AssertionError: If the host's vulnerability count doesn't match the expected count.
    """
    expected_count = 0

    if with_host_vulns:
        vulnerability_factory.create_batch(8, host=host, service=None,
                                           workspace=host.workspace)
        expected_count += 8

    if with_service_vulns:
        services = service_factory.create_batch(10, workspace=host.workspace,
                                                host=host)
        for service in services:
            for _ in range(5):
                # Randomly pick between a standard or a web vuln
                create = random.choice([
                    vulnerability_web_factory.create,
                    partial(vulnerability_factory.create, host=None)
                ])
                create(
                    service=service,
                    workspace=host.workspace
                )
                expected_count += 1

    session.commit()
    assert host.vulnerability_count == expected_count


class TestUpdateHostnames:
    """This class tests the generic set_children_objects function and
    not only the Host model logic. Think twice if you are going to
    remove this"""
    # set_children = partial(set_children_objects, attr='hostnames', key='name')

    def test_set_from_empty_host(self, host, session):
        session.commit()
        assert len(host.hostnames) == 0
        host.set_hostnames(['test.com', 'other.com'])
        assert len(session.new) == 2
        session.commit()
        assert len(host.hostnames) == 2
        assert {hn.name for hn in host.hostnames} == {'test.com', 'other.com'}

    def test_set_to_empty_host(self, host_with_hostnames, session):
        """Test setting host hostnames to an empty list.
        
        Args:
            self: The test class instance.
            host_with_hostnames (Host): A Host object with existing hostnames.
            session (Session): The database session object.
        
        Returns:
            None
        
        Raises:
            AssertionError: If the number of deleted hostnames doesn't match the original count,
                            or if the hostnames list is not empty after the operation.
        """
        session.commit()
        n_hostnames = len(host_with_hostnames.hostnames)
        host_with_hostnames.set_hostnames([])
        assert len(session.deleted) == n_hostnames
        session.commit()
        assert host_with_hostnames.hostnames == []

    def test_stays_equal(self, host_with_hostnames, session):
        """Tests if the hostnames of a host object remain equal after shuffling and reassignment.
        
        Args:
            self: The test class instance.
            host_with_hostnames (Host): A host object with associated hostnames.
            session (Session): A database session object for managing transactions.
        
        Returns:
            None: This method doesn't return anything explicitly.
        
        Raises:
            AssertionError: If the session is not clean or if the set of hostnames doesn't match after shuffling.
        """
        new_value = [hn.name for hn in host_with_hostnames.hostnames]
        random.shuffle(new_value)
        host_with_hostnames.set_hostnames(new_value)
        session.commit()
        assert len(session.new) == len(session.deleted) == len(
            session.dirty) == 0
        assert set(new_value) == {hn.name for hn in
                                     host_with_hostnames.hostnames}

    def test_all(self, host, session):
        """Test the functionality of setting hostnames for a host object.
        
        Args:
            self: The instance of the test class.
            host (Host): The host object to be tested.
            session (Session): The database session for managing objects.
        
        Returns:
            None: This method doesn't return anything explicitly.
        
        Raises:
            AssertionError: If any of the assertions fail during the test.
        """
        a = Hostname(workspace=host.workspace, host=host, name='a')
        b = Hostname(workspace=host.workspace, host=host, name='b')
        session.add(a)
        session.add(b)
        session.commit()

        host.set_hostnames(['b', 'c'])

        # a should be deleted
        assert len(session.deleted) == 1
        assert session.deleted.pop() is a

        # c should be created
        assert len(session.new) == 1
        c = session.new.pop()
        assert c.name == 'c'

        session.commit()
        assert {hn.name for hn in host.hostnames} == {'b', 'c'}

    def test_change_one(self, host, session):
        """Test changing a single hostname for a host.
        
        Args:
            self: The test class instance.
            host (Host): The host object to modify.
            session (Session): The database session to use for operations.
        
        Returns:
            None: This method doesn't return anything explicitly.
        
        Raises:
            AssertionError: If any of the assertions fail during the test.
        """
        hn = Hostname(workspace=host.workspace,
                      host=host,
                      name='x')
        session.add(hn)
        session.commit()
        host.set_hostnames(['y'])

        assert len(session.deleted) == 1
        assert session.deleted.pop() is hn

        assert len(session.new) == 1
        new = session.new.pop()
        assert new.name == 'y'

        session.commit()
        assert len(host.hostnames) == 1
        assert host.hostnames[0].name == 'y'


HOST_TO_QUERY_AMOUNT = 3
HOST_NOT_TO_QUERY_AMOUNT = 2
SERVICE_BY_HOST = 3
VULN_BY_HOST = 2
VULN_BY_SERVICE = 1


class TestHostAPI(ReadOnlyAPITests):
    model = Host
    factory = factories.HostFactory
    api_endpoint = 'hosts'
    view_class = HostsView

    # This test the api endpoint for some of the host in the ws, with existing other host with vulns in the same and
    # other ws
    @pytest.mark.parametrize('querystring', ['countVulns?hosts={}'])
    def test_vuln_count(self,
                        vulnerability_factory,
                        host_factory,
                        service_factory,
                        workspace_factory,
                        test_client,
                        session,
                        querystring):

        """Tests the vulnerability count functionality for hosts in a workspace.
        
        Args:
            vulnerability_factory (Factory): Factory for creating vulnerability objects.
            host_factory (Factory): Factory for creating host objects.
            service_factory (Factory): Factory for creating service objects.
            workspace_factory (Factory): Factory for creating workspace objects.
            test_client (TestClient): The test client for making HTTP requests.
            session (Session): The database session for committing changes.
            querystring (str): The query string format for the API request.
        
        Returns:
            None: This method doesn't return anything, but uses assertions to validate the response.
        
        Raises:
            AssertionError: If the response status code is not 200 or if the vulnerability counts don't match the expected values.
        """
        workspace1 = workspace_factory.create()
        workspace2 = workspace_factory.create()
        session.add(workspace1)
        session.add(workspace2)
        session.commit()

        hosts_to_query = host_factory.create_batch(HOST_TO_QUERY_AMOUNT, workspace=workspace1)
        hosts_not_to_query = host_factory.create_batch(HOST_NOT_TO_QUERY_AMOUNT, workspace=workspace1)
        hosts_not_to_query_w2 = host_factory.create_batch(HOST_NOT_TO_QUERY_AMOUNT, workspace=workspace2)
        hosts = hosts_to_query + hosts_not_to_query + hosts_not_to_query_w2

        services = []
        vulns = []

        session.add_all(hosts)

        for host in hosts:
            services += service_factory.create_batch(SERVICE_BY_HOST, host=host, workspace=host.workspace)
            vulns += vulnerability_factory.create_batch(VULN_BY_HOST, host=host, service=None, workspace=host.workspace)

        session.add_all(services)

        for service in services:
            vulns += vulnerability_factory.create_batch(VULN_BY_SERVICE, service=service, host=None,
                                                        workspace=service.workspace)

        session.add_all(vulns)
        session.commit()

        update_host_stats(
            [host.id for host in hosts],
            []
        )

        url = urljoin(
            self.url(workspace=workspace1),
            querystring.format(",".join(map(lambda x: str(x.id), hosts_to_query)))
        )
        res = test_client.get(url)

        assert res.status_code == 200

        for host in hosts_to_query:
            assert res.json['hosts'][str(host.id)]['total'] == VULN_BY_HOST + VULN_BY_SERVICE * SERVICE_BY_HOST
            assert str(host.id) in res.json['hosts']

    # This test the api endpoint for some of the host in the ws, with existing other host in other ws and ask for the
    # other hosts and test the api endpoint for all of the host in the ws, retrieving all host when none is required
    @pytest.mark.parametrize('querystring', ['countVulns?hosts={}', 'countVulns',
    ])
    def test_vuln_count_ignore_other_ws(self,
                        vulnerability_factory,
                        host_factory,
                        service_factory,
                        workspace_factory,
                        test_client,
                        session,
                        querystring):

        """Test vulnerability count ignoring other workspaces
        
        This method tests the functionality of counting vulnerabilities for hosts in a specific workspace while ignoring hosts and vulnerabilities in other workspaces.
        
        Args:
            vulnerability_factory (Factory): Factory for creating vulnerability objects
            host_factory (Factory): Factory for creating host objects
            service_factory (Factory): Factory for creating service objects
            workspace_factory (Factory): Factory for creating workspace objects
            test_client (TestClient): Test client for making HTTP requests
            session (Session): Database session object
            querystring (str): Query string format for the API endpoint
        
        Returns:
            None: This method doesn't return anything, but uses assertions to verify the expected behavior
        
        Raises:
            AssertionError: If any of the test conditions are not met
        """
        workspace1 = workspace_factory.create()
        workspace2 = workspace_factory.create()
        session.add(workspace1)
        session.add(workspace2)
        session.commit()

        hosts_to_query = host_factory.create_batch(HOST_TO_QUERY_AMOUNT, workspace=workspace1)
        hosts_not_to_query_w2 = host_factory.create_batch(HOST_NOT_TO_QUERY_AMOUNT, workspace=workspace2)
        hosts = hosts_to_query + hosts_not_to_query_w2

        services = []
        vulns = []

        session.add_all(hosts)

        for host in hosts:
            services += service_factory.create_batch(SERVICE_BY_HOST, host=host, workspace=host.workspace)
            vulns += vulnerability_factory.create_batch(VULN_BY_HOST, host=host, service=None, workspace=host.workspace)

        session.add_all(services)

        for service in services:
            vulns += vulnerability_factory.create_batch(VULN_BY_SERVICE, service=service, host=None, workspace=service.workspace)

        session.add_all(vulns)
        session.commit()

        update_host_stats(
            [host.id for host in hosts],
            []
        )

        url = urljoin(self.url(workspace=workspace1), querystring.format(",".join(map(lambda x: str(x.id), hosts))))
        res = test_client.get(url)

        assert res.status_code == 200
        assert len(res.json['hosts']) == HOST_TO_QUERY_AMOUNT

        for host in hosts_to_query:
            assert res.json['hosts'][str(host.id)]['total'] == VULN_BY_HOST + VULN_BY_SERVICE * SERVICE_BY_HOST
            assert str(host.id) in res.json['hosts']

        for host in hosts_not_to_query_w2:
            assert str(host.id) not in res.json['hosts']
