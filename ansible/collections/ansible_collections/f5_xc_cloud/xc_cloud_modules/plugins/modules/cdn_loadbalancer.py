#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: cdn_loadbalancer
short_description: Manage CDN Load Balancer
description:
    - CDN Loadbalancer view defines a required parameters that can be used in CRUD,
      to create and manage CDN loadbalancer. It can be used to create CDN loadbalancer
      and HTTPS loadbalancer.
version_added: "0.0.6"
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
        description:
            - Shape of the CDN load balancer specification
              https://docs.cloud.f5.com/docs/api/views-cdn-loadbalancer
        type: object (CDN Load Balancer)
'''

EXAMPLES = r'''
---
- name: Configure CDN Load Balancer
  hosts: webservers
  collections:
    - yoctoalex.xc_cloud_modules
  connection: local

  environment:
    XC_API_TOKEN: "your_api_token"
    XC_TENANT: "console.ves.volterra.io"

  tasks:
    - name: create cdn load balancer
      cdn_loadbalancer:
        state: present
        metadata:
          namespace: "default"
          name: "demo-cdn-lb"
        spec:
          domains:
            - "cdn.example.com"
          http:
            dns_volterra_managed: False
          add_location: False
          origin_pool:
            public_name:
              dns_name: "example.com"
            follow_origin_redirect: False
            no_tls: { }
            origin_servers:
              - public_name:
                  dns_name: "example.com"
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
    type: object (CDN Load Balancer)
    description:
        - Shape of the CDN load balancer specification
          https://docs.cloud.f5.com/docs/api/views-cdn-loadbalancer
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.client import XcRestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, f5_argument_spec
)
from ..module_utils.exceptions import XcValidationError, XcApiError
from ..module_utils.utils import normalize_response
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
        'no_tls', 'use_tls', 'no_mtls', 'blocking', 'allow_all_response_codes',
        'default_anonymization', 'enable_path_normalize', 'enable_malicious_user_detection'
    }
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
        # Validate and normalize CDN LB specific configurations
        normalized = self._validate_and_normalize_spec(normalized)
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

    def _validate_and_normalize_spec(self, spec):
        """Validate and normalize CDN Load Balancer specific configurations."""
        if not isinstance(spec, dict):
            return spec
        
        # Only validate if this appears to be a complete configuration attempt
        # Skip validation during initial property access or when checking resource existence
        if self._should_validate_spec(spec):
            # Validate origin_pool configuration
            if 'origin_pool' in spec and isinstance(spec['origin_pool'], dict):
                spec = self._validate_origin_pool_config(spec)
        
        return spec

    def _should_validate_spec(self, spec):
        """Determine if we should run full validation on the spec."""
        # Don't validate if spec is empty or minimal
        if not spec or len(spec) < 2:
            return False
        
        # Don't validate if we're missing critical fields (likely incomplete config)
        if 'domains' not in spec and 'origin_pool' not in spec:
            return False
        
        # Validate if we have both domains and origin_pool with substantial config
        origin_pool = spec.get('origin_pool', {})
        if isinstance(origin_pool, dict) and origin_pool:
            # Check if origin_pool has substantial configuration
            substantial_keys = ['origin_servers', 'public_name', 'no_tls', 'use_tls']
            if any(key in origin_pool for key in substantial_keys):
                return True
        
        return False

    def _validate_origin_pool_config(self, spec):
        """Validate complete origin_pool configuration for CDN Load Balancer."""
        origin_pool = spec['origin_pool']
        
        # Validate TLS configuration
        spec = self._validate_origin_pool_tls_config(spec)
        
        # Validate origin servers configuration
        if not any(key in origin_pool for key in ['origin_servers', 'public_name']):
            raise XcValidationError(
                "CDN Load Balancer origin_pool requires either 'origin_servers' or 'public_name' to be configured."
            )
        
        return spec

    def _validate_origin_pool_tls_config(self, spec):
        """Validate TLS configuration in origin_pool for CDN Load Balancer."""
        origin_pool = spec['origin_pool']
        tls_configs = ['no_tls', 'use_tls']
        # Presence of key indicates selection (empty dict is valid sentinel)
        configured_tls = [t for t in tls_configs if t in origin_pool]

        if len(configured_tls) > 1:
            raise XcValidationError(
                f"Cannot configure multiple TLS options simultaneously in origin_pool. "
                f"Found: {', '.join(configured_tls)}. Please specify either 'no_tls' or 'use_tls', not both."
            )

        # Only require TLS configuration if origin_pool has substantial other configuration
        has_origin_config = any(key in origin_pool for key in ['origin_servers', 'public_name'])

        if has_origin_config and len(configured_tls) == 0:
            if not any(key in origin_pool for key in tls_configs):
                raise XcValidationError(
                    "CDN Load Balancer requires TLS configuration in origin_pool. "
                    "Please specify either 'no_tls: {}' or 'use_tls: {...}' in the origin_pool configuration."
                )
        return spec

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
        # For API parameters, we don't have user context, so preserve all ALLOWED_EMPTY_KEYS
        return ModuleParameters._prune_none(spec, user_specified_keys=ModuleParameters.ALLOWED_EMPTY_KEYS)


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
                'active_service_policies', 'api_rate_limit', 'api_specification', 'app_firewall', 
                'blocked_clients', 'bot_defense', 'captcha_challenge', 'client_side_defense', 
                'cors_policy', 'csrf_policy', 'custom_cache_rule', 'data_guard_rules', 
                'ddos_mitigation_rules', 'default_cache_action', 'default_sensitive_data_policy',
                'disable_api_definition', 'disable_api_discovery', 'disable_client_side_defense',
                'disable_ip_reputation', 'disable_malicious_user_detection', 'disable_rate_limit',
                'disable_threat_mesh', 'disable_waf', 'domains', 'enable_api_discovery',
                'enable_challenge', 'enable_ip_reputation', 'enable_malicious_user_detection',
                'enable_threat_mesh', 'graphql_rules', 'http', 'https', 'https_auto_cert',
                'js_challenge', 'jwt_validation', 'l7_ddos_action_block', 'l7_ddos_action_default',
                'l7_ddos_action_js_challenge', 'no_challenge', 'no_service_policies', 'origin_pool',
                'other_settings', 'policy_based_challenge', 'protected_cookies', 'rate_limit',
                'sensitive_data_policy', 'service_policies_from_namespace', 'slow_ddos_mitigation',
                'system_default_timeouts', 'trusted_clients', 'user_id_client_ip', 'user_identification'
            }
            
            # Only compare keys that exist in wanted (like origin_pool)
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

        # Use changes for result reporting like origin_pool
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
        # Use correct CDN Load Balancer endpoint pattern
        base = f'/api/config/namespaces/{self.want.metadata["namespace"]}/cdn_loadbalancers'
        return f"{base}/{name}" if name else base

    def _handle_response(self, response, operation=''):
        """Handle API response with proper error handling."""
        if not response.ok:
            error_msg = f"API {operation} failed"
            error_details = {}
            
            try:
                error_data = response.json()
                
                # Extract detailed error information
                if 'error' in error_data:
                    error_msg = f"{error_msg}: {error_data['error']}"
                    if isinstance(error_data.get('error'), dict):
                        error_details = error_data['error']
                        
                elif 'message' in error_data:
                    error_msg = f"{error_msg}: {error_data['message']}"
                    
                elif 'errors' in error_data and isinstance(error_data['errors'], list):
                    error_messages = []
                    for err in error_data['errors']:
                        if isinstance(err, dict):
                            if 'field' in err and 'message' in err:
                                error_messages.append(f"Field '{err['field']}': {err['message']}")
                            elif 'message' in err:
                                error_messages.append(err['message'])
                        elif isinstance(err, str):
                            error_messages.append(err)
                    
                    if error_messages:
                        error_msg = f"{error_msg}: {'; '.join(error_messages)}"
                
            except (ValueError, KeyError, TypeError):
                # Fallback to basic error message if JSON parsing fails
                error_msg = f"{error_msg}: HTTP {response.status_code}"
                if hasattr(response, 'text') and response.text:
                    error_msg = f"{error_msg} - {response.text[:200]}"
            
            raise XcApiError(error_msg, status_code=response.status_code, response=response)
        
        return normalize_response(response)

    def remove(self):
        """Remove CDN Load Balancer."""
        try:
            uri = self._endpoint(self.want.metadata['name'])
            response = self.client.api.delete(url=uri)
            
            if response.status_code == 404:
                return False
                
            self._handle_response(response, 'DELETE')
            return True
            
        except XcApiError as e:
            if hasattr(e, 'status_code') and e.status_code == 404:
                return False
            raise

    def exists(self):
        """Check if CDN Load Balancer exists."""
        try:
            uri = self._endpoint(self.want.metadata['name'])
            response = self.client.api.get(url=uri)
            
            if response.status_code == 404:
                return False
                
            response_data = self._handle_response(response, 'GET')
            
            if response_data.get('metadata'):
                self.have = ApiParameters(params=self._normalize_existing(response_data))
                return True
                
            return False
            
        except XcApiError as e:
            if hasattr(e, 'status_code') and e.status_code == 404:
                return False
            raise

    def _normalize_existing(self, data):
        # Prune None values similar to desired normalization
        normalized = deepcopy(data)
        normalized['metadata'] = ModuleParameters._prune_none(normalized.get('metadata', {}), user_specified_keys=ModuleParameters.ALLOWED_EMPTY_KEYS)
        if 'spec' in normalized:
            normalized['spec'] = ModuleParameters._prune_none(normalized['spec'], user_specified_keys=ModuleParameters.ALLOWED_EMPTY_KEYS)
        return normalized

    def create(self):
        """Create new CDN Load Balancer."""
        try:
            uri = self._endpoint()
            payload = self.want.to_update()
            response = self.client.api.post(url=uri, json=payload)
            
            response_data = self._handle_response(response, 'CREATE')
            self.have = ApiParameters(params=self._normalize_existing(response_data or payload))
            return True
            
        except XcApiError:
            raise

    def update(self):
        """Update existing CDN Load Balancer."""
        try:
            # Detect real change using Changes class like origin_pool
            self.changes.update_changed_params(self.want, self.have)
            if not self.changes.has_changes():
                return False

            to_update = self.want.to_update()
            uri = self._endpoint(self.want.metadata['name'])
            response = self.client.api.put(url=uri, json=to_update)
            
            response_data = self._handle_response(response, 'UPDATE')
            self.have = ApiParameters(params=self._normalize_existing(response_data or to_update))
            return True
            
        except XcApiError:
            raise


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
                type='dict',
                # Core CDN LB configuration
                domains=dict(type='list', elements='str', required=True),
                origin_pool=dict(type='dict'),
                
                # Protocol configurations
                http=dict(type='dict'),
                https=dict(type='dict'),
                https_auto_cert=dict(type='dict'),
                
                # Security and protection features
                app_firewall=dict(type='dict'),
                bot_defense=dict(type='dict'),
                client_side_defense=dict(type='dict'),
                captcha_challenge=dict(type='dict'),
                js_challenge=dict(type='dict'),
                enable_challenge=dict(type='dict'),
                no_challenge=dict(type='dict'),
                policy_based_challenge=dict(type='dict'),
                
                # Rate limiting and traffic management
                api_rate_limit=dict(type='dict'),
                rate_limit=dict(type='dict'),
                disable_rate_limit=dict(type='dict'),
                
                # WAF and security policies
                disable_waf=dict(type='dict'),
                enable_ip_reputation=dict(type='dict'),
                disable_ip_reputation=dict(type='dict'),
                enable_malicious_user_detection=dict(type='dict'),
                disable_malicious_user_detection=dict(type='dict'),
                enable_threat_mesh=dict(type='dict'),
                disable_threat_mesh=dict(type='dict'),
                
                # API features
                api_specification=dict(type='dict'),
                disable_api_definition=dict(type='dict'),
                enable_api_discovery=dict(type='dict'),
                disable_api_discovery=dict(type='dict'),
                jwt_validation=dict(type='dict'),
                
                # Security policies and rules
                cors_policy=dict(type='dict'),
                csrf_policy=dict(type='dict'),
                graphql_rules=dict(type='list'),
                data_guard_rules=dict(type='list'),
                ddos_mitigation_rules=dict(type='list'),
                
                # Client management
                blocked_clients=dict(type='list'),
                trusted_clients=dict(type='list'),
                
                # Cache configuration
                custom_cache_rule=dict(type='dict'),
                default_cache_action=dict(type='dict'),
                
                # Service policies
                active_service_policies=dict(type='dict'),
                no_service_policies=dict(type='dict'),
                service_policies_from_namespace=dict(type='dict'),
                
                # DDoS protection
                l7_ddos_action_block=dict(type='dict'),
                l7_ddos_action_default=dict(type='dict'),
                l7_ddos_action_js_challenge=dict(type='dict'),
                slow_ddos_mitigation=dict(type='dict'),
                
                # User identification
                user_identification=dict(type='dict'),
                user_id_client_ip=dict(type='dict'),
                
                # Data protection
                sensitive_data_policy=dict(type='dict'),
                default_sensitive_data_policy=dict(type='dict'),
                protected_cookies=dict(type='list'),
                
                # Additional settings
                other_settings=dict(type='dict'),
                system_default_timeouts=dict(type='dict'),
                disable_client_side_defense=dict(type='dict')
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
