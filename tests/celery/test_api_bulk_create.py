from datetime import datetime, timedelta
import time

import pytest
from celery import current_app as current_flask_app

from faraday.server.models import (
    db,
    Command,
    Host,
    Service,
    Workspace)

from faraday.server.api.modules import bulk_create as bc


host_data = {
    "ip": "127.0.0.1",
    "description": "test",
    "hostnames": ["test.com", "test2.org"]
}

service_data = {
    "name": "http",
    "port": 80,
    "protocol": "tcp",
    "status": "open"
}

vuln_data = {
    'name': 'sql injection',
    'desc': 'test',
    'severity': 'high',
    'type': 'Vulnerability',  # TODO: Add constant with vulnerability type.
    'impact': {
        'accountability': True,
        'availability': False,
    },
    'refs': [{'name': 'CVE-2021-1234', 'type': 'other'}],
    'cve': ['CVE-2021-1234', 'CVE-2020-0001'],
    'cwe': ['cwe-123', 'CWE-485'],
    'tool': 'some_tool',
    'data': 'test data',
    'custom_fields': {},
}

vuln_web_data = {
    'type': 'VulnerabilityWeb',
    'method': 'POST',
    'website': 'https://faradaysec.com',
    'path': '/search',
    'parameter_name': 'q',
    'status_code': 200,
}

credential_data = {
    'name': 'test credential',
    'description': 'test',
    'username': 'admin',
    'password': '12345',
}

command_data = {
    'tool': 'pytest',
    'command': 'pytest tests/test_api_bulk_create.py',
    'user': 'root',
    'hostname': 'pc',
    'start_date': (datetime.utcnow() - timedelta(days=7)).isoformat(),
}


def count(model, workspace):
    return model.query.filter(model.workspace == workspace).count()


def new_empty_command(workspace: Workspace):
    """Creates and initializes a new empty Command object.
    
    Args:
        workspace (Workspace): The workspace to associate with the new command.
    
    Returns:
        Command: A new Command object with initial values set.
    
    """
    command = Command()
    command.workspace = workspace
    command.start_date = datetime.utcnow()
    command.import_source = 'report'
    command.tool = "In progress"
    command.command = "In progress"
    db.session.commit()
    return command


def check_task_status(task_id):
    """Check the status of an asynchronous task.
    
    This method polls the status of a task identified by the given task_id until it is ready.
    It uses the AsyncResult functionality provided by the current Flask application to
    retrieve the task status.
    
    Args:
        task_id (str): The unique identifier of the task to check.
    
    Returns:
        str: The final status of the task after it has completed.
    
    Raises:
        AttributeError: If current_flask_app is not properly initialized or lacks AsyncResult.
    """
    task = current_flask_app.AsyncResult(task_id)
    while not task.ready():
        time.sleep(1)
    return task.status


@pytest.mark.skip(reason="Need to mock celery_enabled at start server")
@pytest.mark.skip_sql_dialect('sqlite')
async def test_create_host_task(session, celery_app, celery_worker, workspace):
    """Create and verify a host task in a workspace.
    
    This asynchronous function tests the creation of a host task within a given workspace using a Celery worker. It creates a new host, verifies the task's success, and checks the created host's properties.
    
    Args:
        session: The database session object.
        celery_app: The Celery application instance.
        celery_worker: The Celery worker instance.
        workspace: The workspace object where the host will be created.
    
    Returns:
        None: This function doesn't return a value, but performs assertions to verify the task's execution.
    
    Raises:
        AssertionError: If any of the assertions fail during the test.
    """
    assert count(Host, workspace) == 0
    command = new_empty_command(workspace)
    db.session.commit()
    ret = bc.bulk_create(workspace, command, dict(hosts=[host_data], command=command_data.copy())).get(timeout=10)
    status = check_task_status(ret[0][0])
    assert status == 'SUCCESS'

    host = Host.query.filter(Host.workspace == workspace).one()
    assert host.ip == "127.0.0.1"
    assert set({hn.name for hn in host.hostnames}) == {"test.com", "test2.org"}


@pytest.mark.skip(reason="Need to mock celery_enabled at start server")
@pytest.mark.skip_sql_dialect('sqlite')
def test_create_host_with_services_task(session, celery_app, celery_worker, workspace):
    """Tests the creation of a host with services using a bulk create task.
    
    Args:
        session (Session): The database session for the test.
        celery_app (Celery): The Celery application instance.
        celery_worker (CeleryWorker): The Celery worker instance.
        workspace (Workspace): The workspace in which to create the host and service.
    
    Returns:
        None: This method doesn't return anything, but performs assertions.
    
    Raises:
        AssertionError: If any of the assertions fail, indicating that the host or service creation was unsuccessful or incorrect.
    """
    host_data_ = host_data.copy()
    host_data_['services'] = [service_data]
    command = new_empty_command(workspace)
    ret = bc.bulk_create(workspace, command, dict(hosts=[host_data_], command=command_data.copy())).get()
    status = check_task_status(ret[0][0])
    assert status == 'SUCCESS'

    assert count(Host, workspace) == 1
    assert count(Service, workspace) == 1
    service = Service.query.filter(Service.workspace == workspace).one()
    assert service.name == 'http'
    assert service.port == 80
