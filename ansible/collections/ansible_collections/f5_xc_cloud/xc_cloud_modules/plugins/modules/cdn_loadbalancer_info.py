#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: cdn_loadbalancer_info
short_description: Gather information about F5 Distributed Cloud CDN Load Balancers
description:
    - Retrieve information about F5 Distributed Cloud CDN (Content Delivery Network) Load Balancers / Distributions
    - Read-only module: never changes resources (always returns changed: false)
    - Query a single CDN load balancer or list all in a namespace
    - Supports simple filtering by domains and labels (client-side)
version_added: "0.0.7"
options:
    name:
        description:
            - Name of a specific CDN Load Balancer to retrieve.
            - If omitted, all CDN load balancers in the namespace are returned.
        type: str
    namespace:
        description:
            - Namespace to query.
        type: str
        required: true
    filters:
        description:
            - Optional filters when listing multiple resources (client-side evaluation).
        type: dict
        suboptions:
            domains:
                description:
                    - Return only resources that serve at least one of these domains (substring match allowed unless exact=true).
                type: list
                elements: str
            labels:
                description:
                    - Match metadata.labels; all provided key/value pairs must match.
                type: dict
    exact:
        description:
            - When true, domain filter must match exactly; when false, substring match is allowed.
        type: bool
        default: false
    include_spec:
        description:
            - Include full spec in output (if false, only metadata returned).
        type: bool
        default: true
    include_status:
        description:
            - Include status field if present (future compatibility; currently may be minimal).
        type: bool
        default: true
notes:
    - Always returns changed: false.
    - Supports check mode.
    - Filters are applied client-side because current API does not expose server-side filtering for this view.
author:
    - F5 Networks (@f5networks)
requirements:
    - F5 Distributed Cloud access (API token, tenant)
'''

EXAMPLES = r'''
- name: Get one CDN distribution
  cdn_loadbalancer_info:
    namespace: "prod"
    name: "media-cdn"
  register: cdn_one

- name: List all CDN distributions
  cdn_loadbalancer_info:
    namespace: "prod"
  register: cdn_all

- name: Filter by domain substring
  cdn_loadbalancer_info:
    namespace: "prod"
    filters:
      domains:
        - "cdn.example.com"
  register: cdn_domain

- name: Check existence (no failure on empty)
  cdn_loadbalancer_info:
    namespace: "prod"
    name: "maybe-cdn"
  register: maybe
  failed_when: false

- name: Filter by labels
  cdn_loadbalancer_info:
    namespace: "prod"
    filters:
      labels:
        environment: "prod"
        team: "edge"
  register: cdn_labeled
'''

RETURN = r'''
changed:
  description: Always false
  type: bool
  returned: always
resources:
  description: List of CDN Load Balancer resources
  type: list
  elements: dict
  returned: always
warnings:
  description: Non-fatal warnings
  type: list
  elements: str
  returned: always
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.client import XcRestClient
from ..module_utils.common import AnsibleF5Parameters, f5_argument_spec
from ..module_utils.exceptions import XcValidationError, XcApiError, F5ModuleError
from ..module_utils.utils import normalize_response, safe_get

CDN_LBS_ENDPOINT = "/api/config/namespaces/{namespace}/cdn_loadbalancers"

class InfoParameters(AnsibleF5Parameters):
    returnables = ['resources', 'warnings']

    def to_return(self):
        result = {}
        for r in self.returnables:
            v = getattr(self, r, None)
            if v is not None:
                result[r] = v
        return self._filter_params(result)

    @property
    def name(self):
        return self._values.get('name')

    @property
    def namespace(self):
        return self._values.get('namespace')

    @property
    def filters(self):
        # Ensure we always return a dict for downstream logic even if user passes null
        f = self._values.get('filters')
        if f is None:
            return {}
        return f

    @property
    def exact(self):
        return self._values.get('exact', False)

    @property
    def include_spec(self):
        return self._values.get('include_spec', True)

    @property
    def include_status(self):
        return self._values.get('include_status', True)

    def validate(self):
        if not self.namespace:
            raise XcValidationError("namespace is required")
        # self.filters property guarantees a dict (never None)
        if self.name and self.filters:
            raise XcValidationError("'name' and 'filters' are mutually exclusive")
        f = self.filters or {}
        # Only validate type if key exists
        if 'domains' in f and f['domains'] is not None and not isinstance(f['domains'], list):
            raise XcValidationError("filters.domains must be a list")
        if 'labels' in f and f['labels'] is not None and not isinstance(f['labels'], dict):
            raise XcValidationError("filters.labels must be a dict")
        return True

class InfoManager(object):
    def __init__(self, module):
        self.module = module
        self.client = XcRestClient(**module.params)
        self.params = InfoParameters(params=module.params)
        self.resources = []
        self.warnings = []
        try:
            self.params.validate()
        except XcValidationError as e:
            module.fail_json(msg=str(e))

    def _endpoint(self, name=None):
        base = CDN_LBS_ENDPOINT.format(namespace=self.params.namespace)
        return f"{base}/{name}" if name else base

    @staticmethod
    def _prune(obj):
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if v is None:
                    continue
                pv = InfoManager._prune(v)
                if pv in (None, {}, []):
                    continue
                out[k] = pv
            return out
        if isinstance(obj, list):
            lst = [InfoManager._prune(v) for v in obj]
            return [v for v in lst if v not in (None, {}, [])]
        return obj

    def fetch_one(self):
        uri = self._endpoint(self.params.name)
        response = self.client.api.get(url=uri)
        if response.status_code == 404:
            return []
        if not response.ok:
            self._raise_error(response, 'GET')
        data = normalize_response(response)
        return [self._shape_resource(data)] if data else []

    def fetch_all(self):
        uri = self._endpoint()
        response = self.client.api.get(url=uri)
        if not response.ok:
            if response.status_code == 404:
                return []
            self._raise_error(response, 'LIST')
        data = normalize_response(response)
        if not data:
            return []
        # Handle API variations: list, or wrapper with 'items' or 'results'
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get('items') or data.get('results') or []
        else:
            items = []
        shaped = [self._shape_resource(i) for i in items if isinstance(i, dict)]
        return self._apply_filters(shaped)

    def _shape_resource(self, data):
        md = data.get('metadata', {}) if isinstance(data, dict) else {}
        spec = data.get('spec') if self.params.include_spec else None
        status = data.get('status') if self.params.include_status else None
        shaped = {'metadata': md}
        if spec is not None:
            shaped['spec'] = spec
        if status is not None:
            shaped['status'] = status
        return self._prune(shaped)

    def _apply_filters(self, items):
        f = self.params.filters
        if not f:
            return items
        result = items
        # domain filter
        domains_filter = f.get('domains')
        if domains_filter:
            if self.params.exact:
                result = [r for r in result if any(d in domains_filter for d in r.get('spec', {}).get('domains', []))]
            else:
                result = [r for r in result if any(any(df in d for df in domains_filter) for d in r.get('spec', {}).get('domains', []))]
        # labels filter
        labels_filter = f.get('labels')
        if labels_filter:
            def labels_match(res):
                labels = res.get('metadata', {}).get('labels', {})
                for k, v in labels_filter.items():
                    if labels.get(k) != v:
                        return False
                return True
            result = [r for r in result if labels_match(r)]
        return result

    def _raise_error(self, response, op):
        msg = f"API {op} failed"
        try:
            data = response.json()
            if isinstance(data, dict):
                if 'error' in data:
                    msg = f"{msg}: {data['error']}"
                elif 'message' in data:
                    msg = f"{msg}: {data['message']}"
        except Exception:
            pass
        raise XcApiError(msg, status_code=response.status_code, response=response)

    def exec_module(self):
        if self.params.name:
            self.resources = self.fetch_one()
        else:
            self.resources = self.fetch_all()
        return {
            'changed': False,
            'resources': self.resources,
            'warnings': self.warnings
        }

def main():
    # f5_argument_spec may be provided as a function (expected) or already as a dict in some loader contexts
    base_spec = f5_argument_spec() if callable(f5_argument_spec) else dict(f5_argument_spec)
    argument_spec = base_spec
    argument_spec.update(dict(
        name=dict(type='str'),
        namespace=dict(type='str', required=True),
        filters=dict(type='dict'),
        exact=dict(type='bool', default=False),
        include_spec=dict(type='bool', default=True),
        include_status=dict(type='bool', default=True),
    ))

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[('name', 'filters')]
    )

    try:
        mgr = InfoManager(module)
        result = mgr.exec_module()
        module.exit_json(**result)
    except (XcValidationError, XcApiError, F5ModuleError) as e:
        module.fail_json(msg=str(e))
    except Exception as e:  # noqa
        module.fail_json(msg=f"Unexpected failure: {e}")

if __name__ == '__main__':
    main()
