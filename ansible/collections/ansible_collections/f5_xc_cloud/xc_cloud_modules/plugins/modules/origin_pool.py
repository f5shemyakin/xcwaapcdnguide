#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: origin_pool
short_description: Manage Origin pool
description:
    - Origin pool is a view to create cluster and endpoi            # Normalize both values using the same pruning logic
            if want_value is not None:
                temp_module = ModuleParameters({'spec': want_value if param == 'spec' else {'metadata': want_value}})
                user_specified_keys = temp_module._extract_user_specified_empty_keys(want_value)
                want_value = ModuleParameters._prune_none(want_value, user_specified_keys=user_specified_keys)
            if have_value is not None:
                temp_module = ModuleParameters({'spec': have_value if param == 'spec' else {'metadata': have_value}})
                user_specified_keys = temp_module._extract_user_specified_empty_keys(have_value)
                have_value = ModuleParameters._prune_none(have_value, user_specified_keys=user_specified_keys)hat can be used in HTTP loadbalancer or TCP loadbalancer
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
        type: object (Origin Pool )
        description:
            - Shape of the Origin Pool specification
              https://docs.cloud.f5.com/docs/api/views-origin-pool
'''

EXAMPLES = r'''
---
- name: Configure Origin pool
  hosts: webservers
  collections:
    - yoctoalex.xc_cloud_modules
  connection: local

  environment:
    XC_API_TOKEN: "your_api_token"
    XC_TENANT: "console.ves.volterra.io"

  tasks:
    - name: create origin pool
      origin_pool:
        state: present
        metadata:
          namespace: "default"
          name: "demo-pool"
        spec:
          origin_servers:
            - k8s_service:
                service_name: "demo-app.default"
                site_locator:
                  virtual_site:
                    tenant: "ves-io"
                    namespace: "shared"
                    name: "ves-io-all-res"
                vk8s_networks:
          port: 8080
          loadbalancer_algorithm: "LB_OVERRIDE"
          endpoint_selection: "LOCAL_PREFERRED"
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
    type: object (Origin Pool )
    description:
        - Shape of the Origin Pool specification
          https://docs.cloud.f5.com/docs/api/views-origin-pool
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.client import XcRestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, f5_argument_spec
)
from ..module_utils.constants import ORIGIN_POOLS_ENDPOINT
from copy import deepcopy


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
    # Keys where an empty dict is a deliberate sentinel meaning "selected/enable with defaults"
    ALLOWED_EMPTY_KEYS = {
        # Basic TLS options (mutually exclusive)
        'no_tls', 'use_tls', 
        
        # TLS sub-options
        'no_mtls', 'skip_server_verification', 'use_server_verification',
        'disable_sni', 'use_host_header_as_sni', 
        'disable_session_key_caching', 'default_session_key_caching',
        'volterra_trusted_ca',
        
        # TLS config options (mutually exclusive)
        'tls_config.default_security', 'tls_config.low_security', 
        'tls_config.medium_security', 'tls_config.custom_security',
        
        # Advanced options
        'auto_http_config', 'default_circuit_breaker', 'disable_circuit_breaker',
        'disable_lb_source_ip_persistance', 'enable_lb_source_ip_persistance',
        'disable_outlier_detection', 'no_panic_threshold',
        'disable_proxy_protocol', 'proxy_protocol_v1', 'proxy_protocol_v2',
        'disable_subsets', 'enable_subsets',
        
        # Port options (mutually exclusive)
        'automatic_port', 'lb_port', 'same_as_endpoint_port',
        
        # Connection pool options (mutually exclusive)
        'upstream_conn_pool_reuse_type.disable_conn_pool_reuse',
        'upstream_conn_pool_reuse_type.enable_conn_pool_reuse',
        
        # Subset options
        'enable_subsets.any_endpoint', 'enable_subsets.fail_request',
        'enable_subsets.default_subset.default_subset',
        
        # Header transformation options (mutually exclusive)
        'http1_config.header_transformation.default_header_transformation',
        'http1_config.header_transformation.legacy_header_transformation',
        'http1_config.header_transformation.preserve_case_header_transformation',
        'http1_config.header_transformation.proper_case_header_transformation',
        
        # Origin server options
        'origin_servers.labels', 'origin_servers.inside_network', 'origin_servers.outside_network',
        'origin_servers.vk8s_networks',
        
        # SNAT pool options (mutually exclusive)
        'snat_pool.no_snat_pool', 'snat_pool.snat_pool',
        
        # Certificate options
        'use_mtls.tls_certificates.disable_ocsp_stapling',
        'use_mtls.tls_certificates.use_system_defaults',
        
        # Metadata options
        'metadata.annotations', 'metadata.labels',
        
        # Legacy compatibility
        'blocking', 'allow_all_response_codes', 'default_anonymization', 
        'enable_path_normalize', 'enable_malicious_user_detection', 'default_security'
    }
    
    def _extract_user_specified_empty_keys(self, obj, current_path=""):
        """Extract paths to empty dicts that user explicitly specified"""
        user_specified_keys = set()
        
        if isinstance(obj, dict):
            for key, value in obj.items():
                new_path = f"{current_path}.{key}" if current_path else key
                
                if isinstance(value, dict):
                    if len(value) == 0:
                        # This is an empty dict - check if it's in our allowed list
                        if new_path in self.ALLOWED_EMPTY_KEYS:
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
        
        # Extract user-specified empty keys from the original spec before pruning
        user_specified_keys = self._extract_user_specified_empty_keys(spec)
        normalized = self._prune_none(spec, user_specified_keys=user_specified_keys)
        self._values['_normalized_spec'] = normalized
        return normalized

    def _extract_user_specified_empty_keys(self, obj, path="", keys=None):
        """Extract keys that user explicitly specified as empty dicts using dot notation."""
        if keys is None:
            keys = set()
        
        if isinstance(obj, dict):
            for k, v in obj.items():
                current_path = f"{path}.{k}" if path else k
                if v == {}:
                    # Store both the simple key name and the full dot-notation path
                    keys.add(k)
                    if path:  # Only add dot notation if there's a parent path
                        keys.add(current_path)
                elif isinstance(v, dict):
                    self._extract_user_specified_empty_keys(v, current_path, keys)
        
        return keys

    @staticmethod
    def _prune_none(obj, parent_key=None, user_specified_keys=None, current_path=""):
        if isinstance(obj, dict):
            new_obj = {}
            for k, v in obj.items():
                if v is None:
                    continue
                
                # Build the current path for this key
                key_path = f"{current_path}.{k}" if current_path else k
                
                pruned = ModuleParameters._prune_none(v, k, user_specified_keys, key_path)
                # Keep empty dicts only for keys that were explicitly specified by the user
                if pruned in (None, {}, []):
                    # Check if this key was specified by the user (either simple name or full path)
                    if (user_specified_keys is not None and 
                        (k in user_specified_keys or key_path in user_specified_keys)):
                        new_obj[k] = pruned
                    continue
                new_obj[k] = pruned
            return new_obj
        if isinstance(obj, list):
            new_list = [ModuleParameters._prune_none(v, parent_key, user_specified_keys, current_path) for v in obj]
            return [v for v in new_list if v not in (None, {}, [])]
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
        return ModuleParameters._prune_none(spec, user_specified_keys=user_specified_keys)


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
                want_value = ModuleParameters._prune_none(want_value, user_specified_keys=ModuleParameters.ALLOWED_EMPTY_KEYS)
            if have_value is not None:
                have_value = ModuleParameters._prune_none(have_value, user_specified_keys=ModuleParameters.ALLOWED_EMPTY_KEYS)
            
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
                'advanced_options', 'endpoint_selection', 'health_check_port', 'healthcheck', 'health_check',
                'loadbalancer_algorithm', 'no_tls', 'origin_servers', 'port', 
                'same_as_endpoint_port', 'use_tls'
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
        # Use non-versioned endpoint for parity with http_loadbalancer
        base = f'/api/config/namespaces/{self.want.metadata["namespace"]}/origin_pools'
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
        # For existing data, use simple none pruning since we don't track user intent
        normalized['metadata'] = {k: v for k, v in normalized.get('metadata', {}).items() if v is not None}
        if 'spec' in normalized:
            # For existing spec, use empty set for user keys since we don't track intent on existing data
            user_specified_keys = set()
            normalized['spec'] = ModuleParameters._prune_none(normalized['spec'], user_specified_keys=user_specified_keys)
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
                advanced_options=dict(),
                endpoint_selection=dict(
                    default="DISTRIBUTED",
                    choices=['DISTRIBUTED', 'LOCAL_ONLY', 'LOCAL_PREFERRED']
                ),
                health_check_port=dict(type='int'),
                healthcheck=dict(),
                loadbalancer_algorithm=dict(
                    default="ROUND_ROBIN",
                    choices=['ROUND_ROBIN', 'LEAST_REQUEST', 'RING_HASH', 'RANDOM', 'LB_OVERRIDE']
                ),
                no_tls=dict(),
                origin_servers=dict(),
                port=dict(type='int'),
                same_as_endpoint_port=dict(),
                use_tls=dict(),
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
