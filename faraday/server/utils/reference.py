import logging

from faraday.server.models import db, Reference
from faraday.server.utils.database import get_or_create


logger = logging.getLogger(__name__)


def create_reference(reference_list: list = [], workspace_id: int = None) -> set:
    reference_obj_set = set()
    for reference in reference_list:
        reference_obj, _ = get_or_create(db.session, Reference, name=reference['name'],
                                         type=reference['type'], workspace_id=workspace_id)
        reference_obj_set.add(reference_obj)
    return set(reference_obj_set)


def create_reference_multiworkspace(reference_list: list = [], workspaces_ids: list = []) -> set:
    reference_obj_set = set()
    for reference in reference_list:
        for _id in workspaces_ids:
            reference_obj, _ = get_or_create(db.session, Reference, name=reference['name'],
                                             type=reference['type'], workspace_id=_id)
            reference_obj_set.add(reference_obj)
    return set(reference_obj_set)
