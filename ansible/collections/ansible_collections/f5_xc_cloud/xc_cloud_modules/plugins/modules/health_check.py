#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: health_check
short_description: Manage Health Check
description:
    - Health check is used to monitor the health of origin servers and determine their availability
    - Can be configured with HTTP or TCP health checking mechanisms
    - Supports advanced configuration options for intervals, thresholds, and custom headers
version_added: "0.0.1"
options:
    metadata:
        annotations:
            description:
                - Annotations is an unstructured key value map stored with a resource
                  that may be set by external tools to store and retrieve arbitrary metadata.
                  They are not queryable and should be preserved when modifying objects.
            type: object
        description:
            description:
                - Human readable description for the object
            type: str
        disable:
            description:
                - A value of true will administratively disable the object
            type: bool
        labels:
            description:
                - Map of string keys and values that can be used to organize and categorize (scope and select)
                  objects as chosen by the user. Values specified here will be used by selector expression
            type: object
        name:
            type: str
            required: True
            description:
                - This is the name of configuration object. It has to be unique within the namespace.
                  It can only be specified during create API and cannot be changed during replace API.
                  The value of name has to follow DNS-1035 format.
        namespace:
            description:
                - This defines the workspace within which each the configuration object is to be created.
                  Must be a DNS_LABEL format
            type: str
    state:
        description:
            - When C(state) is C(present), ensures the object is created or modified.
            - When C(state) is C(absent), ensures the object is removed.
        type: str
        choices:
          - present
          - absent
        default: present
    spec:
        type: object (Health Check)
        description:
            - Shape of the Health Check specification
              https://docs.cloud.f5.com/docs/api/views-health-check
'''

EXAMPLES = r'''
---
- name: Configure Health Check
  hosts: webservers
  collections:
    - f5_xc_cloud.xc_cloud_modules
  connection: local

  environment:
    XC_API_TOKEN: "your_api_token"
    XC_TENANT: "console.ves.volterra.io"

  tasks:
    - name: create HTTP health check
      health_check:
        state: present
        metadata:
          namespace: "default"
          name: "demo-http-healthcheck"
          description: "HTTP health check for demo application"
        spec:
          interval: 30
          timeout: 10
          healthy_threshold: 2
          unhealthy_threshold: 3
          jitter_percent: 10
          http_health_check:
            path: "/health"
            host_header: "demo.example.com"
            expected_status_codes:
              - "200"
              - "204"
            headers:
              "User-Agent": "F5-XC-HealthCheck"
            use_http2: false

    - name: create TCP health check
      health_check:
        state: present
        metadata:
          namespace: "default"
          name: "demo-tcp-healthcheck"
          description: "TCP health check for database"
        spec:
          interval: 15
          timeout: 5
          healthy_threshold: 2
          unhealthy_threshold: 2
          tcp_health_check:
            send_payload: "PING"
            expected_response: "PONG"
'''

RETURN = r'''
---
metadata:
    annotations:
        description:
            - Annotations is an unstructured key value map stored with a resource
              that may be set by external tools to store and retrieve arbitrary metadata.
              They are not queryable and should be preserved when modifying objects.
        type: object
    description:
        description:
            - Human readable description for the object
        type: str
    disable:
        description:
            - A value of true will administratively disable the object
        type: bool
    labels:
        description:
            - Map of string keys and values that can be used to organize and categorize (scope and select)
              objects as chosen by the user. Values specified here will be used by selector expression
        type: object
    name:
        type: str
        required: True
        description:
            - This is the name of configuration object. It has to be unique within the namespace.
              It can only be specified during create API and cannot be changed during replace API.
              The value of name has to follow DNS-1035 format.
    namespace:
        description:
            - This defines the workspace within which each the configuration object is to be created.
              Must be a DNS_LABEL format
        type: str
spec:
    type: object (Health Check)
    description:
        - Shape of the Health Check specification
          https://docs.cloud.f5.com/docs/api/views-health-check
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.client import XcRestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, f5_argument_spec
)
from copy import deepcopy

# Define allowed empty keys that have semantic meaning when explicitly set by user
ALLOWED_EMPTY_KEYS = {
    # Metadata options
    'metadata.annotations',
    'metadata.labels',
    
    # HTTP health check options
    'http_health_check.headers',
    'http_health_check.use_origin_server_name',
    
    # Future expansion for other health check types
}


class Parameters(AnsibleF5Parameters):
    updatables = ['metadata', 'spec']

    returnables = ['metadata', 'spec']

    def to_return(self):
        result = {}
        for returnable in self.returnables:
            result[returnable] = getattr(self, returnable)
        result = self._filter_params(result)
        return result

    def to_update(self):
        result = {}
        for updatebale in self.updatables:
            result[updatebale] = getattr(self, updatebale)
        result = self._filter_params(result)
        return result


class ModuleParameters(Parameters):
    def _extract_user_specified_empty_keys(self, obj, current_path=""):
        """Extract paths to empty dicts that user explicitly specified"""
        user_specified_keys = set()
        
        if isinstance(obj, dict):
            for key, value in obj.items():
                new_path = f"{current_path}.{key}" if current_path else key
                
                if isinstance(value, dict):
                    if len(value) == 0:
                        # This is an empty dict - check if it's in our allowed list
                        if new_path in ALLOWED_EMPTY_KEYS:
                            user_specified_keys.add(new_path)
                    else:
                        # Recursively check nested dictionaries
                        user_specified_keys.update(
                            self._extract_user_specified_empty_keys(value, new_path)
                        )
                elif isinstance(value, list):
                    # Handle lists (though less common for empty key scenarios)
                    for i, item in enumerate(value):
                        if isinstance(item, dict):
                            item_path = f"{new_path}[{i}]"
                            user_specified_keys.update(
                                self._extract_user_specified_empty_keys(item, item_path)
                            )
        
        return user_specified_keys

    @property
    def metadata(self):
        md = self._values.get('metadata')
        if not md:
            return md
        # Shallow prune None values in metadata for idempotency
        cleaned = {k: v for k, v in md.items() if v is not None}
        return cleaned

    @property
    def spec(self):
        spec = self._values.get('spec')
        if spec is None:
            return spec
        # Cache normalized/pruned spec to avoid repeated deep work
        cached = self._values.get('_normalized_spec')
        if cached is not None:
            return cached
            
        # Extract user-specified empty keys before pruning
        user_specified_keys = self._extract_user_specified_empty_keys(spec)
        normalized = self._prune_none(spec, user_specified_keys)
        self._values['_normalized_spec'] = normalized
        return normalized

    def _prune_none(self, obj, user_specified_keys=None, current_path=""):
        if user_specified_keys is None:
            user_specified_keys = set()
            
        if isinstance(obj, dict):
            new_obj = {}
            for k, v in obj.items():
                if v is None:
                    continue
                    
                new_path = f"{current_path}.{k}" if current_path else k
                pruned = self._prune_none(v, user_specified_keys, new_path)
                
                # Keep empty objects {} only if user explicitly specified them
                if isinstance(pruned, dict) and len(pruned) == 0:
                    if new_path in user_specified_keys:
                        new_obj[k] = pruned
                    # Otherwise skip the empty dict
                elif pruned in (None, [], [{}]):
                    continue
                else:
                    new_obj[k] = pruned
            return new_obj
        if isinstance(obj, list):
            new_list = []
            for i, v in enumerate(obj):
                item_path = f"{current_path}[{i}]" if current_path else f"[{i}]"
                pruned = self._prune_none(v, user_specified_keys, item_path)
                if pruned not in (None, {}, [], [{}]):
                    new_list.append(pruned)
            return new_list
        return obj


class ApiParameters(Parameters):
    @property
    def metadata(self):
        md = self._values.get('metadata')
        if not md:
            return md
        # Apply same pruning as ModuleParameters for consistent comparison
        cleaned = {k: v for k, v in md.items() if v is not None}
        return cleaned

    @property
    def spec(self):
        spec = self._values.get('spec')
        if spec is None:
            return spec
        # Apply same pruning as ModuleParameters for consistent comparison
        temp_module = ModuleParameters({'spec': spec})
        user_specified_keys = temp_module._extract_user_specified_empty_keys(spec)
        return temp_module._prune_none(spec, user_specified_keys)


class Changes(Parameters):
    def __init__(self, params=None):
        super(Changes, self).__init__(params or {})
        self._changed_params = set()

    @property
    def metadata(self):
        """Get metadata changes."""
        return self._values.get('metadata')

    @metadata.setter
    def metadata(self, value):
        self._values['metadata'] = value
        self._changed_params.add('metadata')

    @property
    def spec(self):
        """Get spec changes."""
        return self._values.get('spec')

    @spec.setter
    def spec(self, value):
        self._values['spec'] = value
        self._changed_params.add('spec')

    @property
    def changed_params(self):
        return list(self._changed_params) if hasattr(self, '_changed_params') else []

    def has_changes(self):
        return len(self.changed_params) > 0

    def update_changed_params(self, want_params, have_params):
        """Compare want vs have and update changed parameters."""
        if not hasattr(self, '_changed_params'):
            self._changed_params = set()
        
        for param in self.updatables:
            want_value = getattr(want_params, param, None)
            have_value = getattr(have_params, param, None)
            
            # Normalize both values using the same pruning logic
            if want_value is not None:
                temp_module = ModuleParameters({'spec': want_value if param == 'spec' else {'metadata': want_value}})
                user_specified_keys = temp_module._extract_user_specified_empty_keys(want_value)
                want_value = temp_module._prune_none(want_value, user_specified_keys)
            if have_value is not None:
                temp_module = ModuleParameters({'spec': have_value if param == 'spec' else {'metadata': have_value}})
                user_specified_keys = temp_module._extract_user_specified_empty_keys(have_value)
                have_value = temp_module._prune_none(have_value, user_specified_keys)
            
            if self._values_differ(want_value, have_value):
                self._changed_params.add(param)
                setattr(self, param, want_value)
    
    def _values_differ(self, want_value, have_value, _depth=0):
        """Deep comparison of values to detect differences."""
        # Prevent infinite recursion
        if _depth > 50:
            return want_value != have_value
        
        if type(want_value) != type(have_value):
            return True
        
        if isinstance(want_value, dict) and isinstance(have_value, dict):
            # Check for fields that should be removed (exist in have but not in want)
            # Only consider user-controllable fields, ignore system-generated ones
            user_controllable_fields = {
                'healthy_threshold', 'unhealthy_threshold', 'interval', 'timeout', 'jitter_percent',
                'http_health_check', 'tcp_health_check'
            }
            
            # Only compare keys that exist in wanted (like http_loadbalancer)
            for key in want_value.keys():
                if key not in have_value:
                    return True
                if self._values_differ(want_value[key], have_value[key], _depth + 1):
                    return True
            
            # Check for fields that should be removed
            for key in have_value.keys():
                if key in user_controllable_fields and key not in want_value:
                    # Field exists in current config but not in desired config - needs removal
                    # Only treat as change if the current value is not empty/default
                    if have_value[key] not in [None, {}, []]:
                        return True
            
            return False
        elif isinstance(want_value, list):
            if len(want_value) != len(have_value):
                return True
            for i in range(len(want_value)):
                if self._values_differ(want_value[i], have_value[i], _depth + 1):
                    return True
            return False
        else:
            return want_value != have_value


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = XcRestClient(**self.module.params)
        self.want = ModuleParameters(params=self.module.params)
        self.have = ApiParameters()
        self.changes = Changes()

    def exec_module(self):
        changed = False
        result = {}
        state = self.want.state

        if state == 'present':
            changed = self.present()
        elif state == 'absent':
            changed = self.absent()

        # Use changes for result reporting like http_loadbalancer
        if changed and self.changes.has_changes():
            result.update(self.changes.to_return())
            result.update(dict(
                changed=changed,
                changed_params=self.changes.changed_params
            ))
        else:
            changes = self.have.to_return()
            result.update(**changes)
            result['changed'] = changed
        
        return result

    def present(self):
        if self.exists():
            # Set up changes tracking for update comparison
            self.changes.update_changed_params(self.want, self.have)
            return self.update()
        else:
            # For create operations, track all wanted parameters as changes
            self.changes = Changes(params=self.want.to_update())
            for param in self.changes.updatables:
                if hasattr(self.want, param) and getattr(self.want, param) is not None:
                    setattr(self.changes, param, getattr(self.want, param))
                    self.changes._changed_params.add(param)
            return self.create()

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def _endpoint(self, name=None):
        # Use healthchecks endpoint
        base = f'/api/config/namespaces/{self.want.metadata["namespace"]}/healthchecks'
        return f"{base}/{name}" if name else base

    def remove(self):
        uri = self._endpoint(self.want.metadata['name'])
        response = self.client.api.delete(url=uri)
        if response.status == 404:
            return False
        if response.status not in [200, 201, 202]:
            raise F5ModuleError(response.content)
        return True

    def exists(self):
        uri = self._endpoint(self.want.metadata['name'])
        response = self.client.api.get(url=uri)
        if response.status == 404:
            return False
        if response.status not in [200, 201, 202]:
            raise F5ModuleError(response.content)
        data = response.json()
        if data.get('metadata'):
            self.have = ApiParameters(params=self._normalize_existing(data))
            return True
        return False

    def _normalize_existing(self, data):
        # Prune None values similar to desired normalization
        normalized = deepcopy(data)
        # For metadata, use simple none pruning since we don't track user intent on existing data
        normalized['metadata'] = {k: v for k, v in normalized.get('metadata', {}).items() if v is not None}
        if 'spec' in normalized:
            # For spec, use simple none pruning since we don't track user intent on existing data
            temp_module = ModuleParameters({'spec': normalized['spec']})
            user_specified_keys = set()  # Empty set for existing data
            normalized['spec'] = temp_module._prune_none(normalized['spec'], user_specified_keys)
        return normalized

    def create(self):
        uri = self._endpoint()
        payload = self.want.to_update()
        response = self.client.api.post(url=uri, json=payload)
        if response.status not in [200, 201, 202]:
            raise F5ModuleError(response.content)
        resp_json = response.json() if hasattr(response, 'json') else {}
        self.have = ApiParameters(params=self._normalize_existing(resp_json or payload))
        return True

    def update(self):
        # Detect real change using Changes class like http_loadbalancer
        self.changes.update_changed_params(self.want, self.have)
        if not self.changes.has_changes():
            return False

        to_update = self.want.to_update()
        uri = self._endpoint(self.want.metadata['name'])
        response = self.client.api.put(url=uri, json=to_update)
        if response.status not in [200, 201, 202]:
            raise F5ModuleError(response.content)
        
        # Use response data if available, otherwise fallback to desired state
        resp_json = response.json() if hasattr(response, 'json') else {}
        self.have = ApiParameters(params=self._normalize_existing(resp_json or to_update))
        return True


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = False

        argument_spec = dict(
            state=dict(
                default='present',
                choices=['present', 'absent']
            ),
            metadata=dict(
                type='dict',
                name=dict(required=True),
                namespace=dict(required=True),
                labels=dict(type=dict),
                annotations=dict(type=dict),
                description=dict(type="str"),
                disable=dict(type='bool')
            ),
            spec=dict(
                type=dict,
                healthy_threshold=dict(type='int'),
                unhealthy_threshold=dict(type='int'),
                interval=dict(type='int'),
                timeout=dict(type='int'),
                jitter_percent=dict(type='int'),
                http_health_check=dict(
                    type='dict',
                    expected_status_codes=dict(type='list', elements='str'),
                    headers=dict(type='dict'),
                    host_header=dict(type='str'),
                    path=dict(type='str'),
                    request_headers_to_remove=dict(type='list', elements='str'),
                    use_http2=dict(type='bool'),
                    use_origin_server_name=dict(type='dict')
                ),
                tcp_health_check=dict(
                    type='dict',
                    expected_response=dict(type='str'),
                    send_payload=dict(type='str')
                )
            )
        )
        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)
        self.argument_spec.update(argument_spec)


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode
    )
    try:
        mm = ModuleManager(module=module)
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
