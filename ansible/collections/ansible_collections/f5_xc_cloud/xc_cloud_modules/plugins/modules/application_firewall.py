#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: application_firewall
short_description: Manage xC Application Firewall
description:
    - WAF Configuration
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
        ai_risk_based_blocking:
            type: object (AI Risk Based Blocking)
            description:
                - Configuration for AI risk-based blocking settings
        allow_all_response_codes:
            type: object (Empty)
            description:
                - This can be used for messages where no values are needed
        allowed_response_codes:
            type: object (Allowed Response Codes)
            description:
                - List of HTTP response status codes that are allowed
        blocking:
            type: object (Empty)
            description:
                - This can be used for messages where no values are needed
        blocking_page:
            type: object (Custom Blocking Page)
            description:
                - Custom blocking response page body
        bot_protection_setting:
            type: object (BotProtectionSetting)
            description:
                - Configuration of WAF Bot Protection
        custom_anonymization:
            type: object (AnonymizationSetting)
            description:
                - Anonymization settings which is a list of HTTP headers, parameters and cookies
        default_anonymization:
            type: object (Empty)
            description:
                - This can be used for messages where no values are needed
        default_bot_setting:
            type: object (Empty)
            description:
                - This can be used for messages where no values are needed
        default_detection_settings:
            type: object (Empty)
            description:
                - This can be used for messages where no values are needed
        detection_settings:
            type: object (Detection Settings)
            description:
                - Specifies detection settings to be used by WAF
        disable_anonymization:
            type: object (Empty)
            description:
                - This can be used for messages where no values are needed
        monitoring:
            type: object (Empty)
            description:
                - This can be used for messages where no values are needed
        use_default_blocking_page:
            type: object (Empty)
            description:
                - This can be used for messages where no values are needed
    patch:
        type: bool
        description: Merge changes with existing on cloud when True
        default: False
'''

EXAMPLES = r'''
---
- name: Configure Application Firewall on XC Cloud
  hosts: webservers
  collections:
    - yoctoalex.xc_cloud_modules
  connection: local

  environment:
    XC_API_TOKEN: "your_api_token"
    XC_TENANT: "console.ves.volterra.io"

  tasks:
    - name: create app firewall
      application_firewall:
        state: present
        metadata:
          namespace: "default"
          name: "demo-fw"
        spec:
          ai_risk_based_blocking:
            high_risk_action: "AI_BLOCK"
            medium_risk_action: "AI_BLOCK"
            low_risk_action: "AI_BLOCK"
          blocking: {}
          detection_settings:
            signature_selection_setting:
              attack_type_settings:
                disabled_attack_types:
                  - "ATTACK_TYPE_COMMAND_EXECUTION"
              high_medium_low_accuracy_signatures: {}
            enable_suppression: { }
            enable_threat_campaigns: { }
            violation_settings:
              disabled_violation_types:
                - "VIOL_HTTP_PROTOCOL_BAD_HTTP_VERSION"
          bot_protection_setting:
            malicious_bot_action: "BLOCK"
            suspicious_bot_action: "REPORT"
            good_bot_action: "REPORT"
          allow_all_response_codes: {}
          default_anonymization: {}
          blocking_page:
            response_code: "Forbidden"
            blocking_page: "string:///yeS5iYWNrKCki....WNrXTwvYT48L2JvZHk+PC9odG1sPg=="
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
    ai_risk_based_blocking:
        type: object (AI Risk Based Blocking)
        description:
            - Configuration for AI risk-based blocking settings
    allow_all_response_codes:
        type: object (Empty)
        description:
            - This can be used for messages where no values are needed
    allowed_response_codes:
        type: object (Allowed Response Codes)
        description:
            - List of HTTP response status codes that are allowed
    blocking:
        type: object (Empty)
        description:
            - This can be used for messages where no values are needed
    blocking_page:
        type: object (Custom Blocking Page)
        description:
            - Custom blocking response page body
    bot_protection_setting:
        type: object (BotProtectionSetting)
        description:
            - Configuration of WAF Bot Protection
    custom_anonymization:
        type: object (AnonymizationSetting)
        description:
            - Anonymization settings which is a list of HTTP headers, parameters and cookies
    default_anonymization:
        type: object (Empty)
        description:
            - This can be used for messages where no values are needed
    default_bot_setting:
        type: object (Empty)
        description:
            - This can be used for messages where no values are needed
    default_detection_settings:
        type: object (Empty)
        description:
            - This can be used for messages where no values are needed
    detection_settings:
        type: object (Detection Settings)
        description:
            - Specifies detection settings to be used by WAF
    disable_anonymization:
        type: object (Empty)
        description:
            - This can be used for messages where no values are needed
    monitoring:
        type: object (Empty)
        description:
            - This can be used for messages where no values are needed
    use_default_blocking_page:
        type: object (Empty)
        description:
            - This can be used for messages where no values are needed
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.client import XcRestClient
from ..module_utils.common import (
    F5ModuleError, AnsibleF5Parameters, f5_argument_spec
)
from copy import deepcopy

# Define allowed empty keys that have semantic meaning when explicitly set by user
ALLOWED_EMPTY_KEYS = {
    # Basic WAF modes (mutually exclusive)
    'blocking',
    'monitoring',
    
    # Response handling options (mutually exclusive)
    'allow_all_response_codes',
    'use_default_blocking_page',
    
    # Anonymization options (mutually exclusive)
    'default_anonymization',
    'disable_anonymization',
    
    # Bot protection options
    'default_bot_setting',
    
    # Detection settings options
    'default_detection_settings',
    
    # Metadata options
    'metadata.annotations',
    'metadata.labels',
    
    # Detection settings nested options
    'detection_settings.default_bot_setting',
    'detection_settings.default_violation_settings',
    'detection_settings.disable_staging',
    'detection_settings.disable_suppression',
    'detection_settings.disable_threat_campaigns',
    'detection_settings.enable_suppression',
    'detection_settings.enable_threat_campaigns',
    
    # Signature selection settings (mutually exclusive)
    'detection_settings.signature_selection_setting.default_attack_type_settings',
    'detection_settings.signature_selection_setting.high_medium_accuracy_signatures',
    'detection_settings.signature_selection_setting.high_medium_low_accuracy_signatures',
    'detection_settings.signature_selection_setting.only_high_accuracy_signatures'
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
        
        # Additional validation for critical fields
        if 'namespace' in cleaned:
            namespace = cleaned['namespace']
            if not isinstance(namespace, str):
                # Convert to string if it's not already (handles Jinja2 namespace objects)
                # This fixes the error: URL can't contain control characters "/api/config/namespaces/<class 'jinja2.utils.Namespace'>/app_firewalls/..."
                cleaned['namespace'] = str(namespace)
        
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
                elif pruned is None:
                    continue
                else:
                    new_obj[k] = pruned
            return new_obj
        if isinstance(obj, list):
            new_list = []
            for i, v in enumerate(obj):
                item_path = f"{current_path}[{i}]" if current_path else f"[{i}]"
                pruned = self._prune_none(v, user_specified_keys, item_path)
                if pruned is not None:
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
        
        # Additional validation for critical fields (same as ModuleParameters)
        if 'namespace' in cleaned:
            namespace = cleaned['namespace']
            if not isinstance(namespace, str):
                # Convert to string if it's not already (handles Jinja2 namespace objects)
                # This fixes the error: URL can't contain control characters "/api/config/namespaces/<class 'jinja2.utils.Namespace'>/app_firewalls/..."
                cleaned['namespace'] = str(namespace)
        
        return cleaned

    @property
    def spec(self):
        spec = self._values.get('spec')
        if spec is None:
            return spec
        # Apply same pruning as ModuleParameters for consistent comparison
        # For API parameters, we'll preserve all empty dicts since we don't have user context
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
            
            if self._values_differ(want_value, have_value):
                self._changed_params.add(param)
                setattr(self, param, want_value)
    
    def _values_differ(self, want_value, have_value, _depth=0):
        """Deep comparison with empty-object semantics and order-insensitive lists."""
        # Prevent infinite recursion
        if _depth > 50:
            return want_value != have_value

        def normalize_for_comparison(value):
            # Only collapse None; keep {} and [] as they can be meaningful
            return None if value is None else value

        want_normalized = normalize_for_comparison(want_value)
        have_normalized = normalize_for_comparison(have_value)

        # If both are None, they're the same
        if want_normalized is None and have_normalized is None:
            return False

        # If one is None and the other isn't, they differ
        if (want_normalized is None) != (have_normalized is None):
            return True

        # Now we know both are non-None, check types
        if type(want_normalized) != type(have_normalized):
            return True

        # Dicts: compare only keys present in want; allow have to omit empty dict keys
        if isinstance(want_normalized, dict):
            for key in want_normalized.keys():
                if key not in have_normalized:
                    # Treat missing have key as equal only if desired is empty dict
                    if want_normalized[key] == {}:
                        continue
                    return True
                if self._values_differ(want_normalized[key], have_normalized[key], _depth + 1):
                    return True
            # Ignore have's extra keys (system-added) unless they carry non-empty, meaningful values
            for key in have_normalized.keys():
                if key not in want_normalized and have_normalized[key] not in [None, {}]:
                    # Consider non-empty extra keys as acceptable (do not force diff)
                    pass
            return False

        # Lists: compare as order-insensitive multisets using canonical representation
        if isinstance(want_normalized, list):
            from collections import Counter
            import json

            def canon(x):
                if isinstance(x, (dict, list)):
                    try:
                        return json.dumps(x, sort_keys=True)
                    except Exception:
                        return str(x)
                return x

            want_canon = Counter([canon(x) for x in want_normalized])
            have_canon = Counter([canon(x) for x in have_normalized])
            if want_canon != have_canon:
                return True
            return False

        # Scalars
        if want_normalized != have_normalized:
            return True
        return False


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = XcRestClient(**self.module.params)
        self.want = ModuleParameters(params=self.module.params)
        self.have = ApiParameters()
        self.changes = Changes()

    def _merge_dicts(self, dict1, dict2):
        for k in set(dict1.keys()).union(dict2.keys()):
            if k in dict1 and k in dict2:
                if isinstance(dict1[k], dict) and isinstance(dict2[k], dict):
                    yield k, dict(self._merge_dicts(dict1[k], dict2[k]))
                elif dict2[k] is None:
                    pass
                else:
                    yield k, dict2[k]
            elif k in dict1:
                if dict1[k] is None:
                    pass
                else:
                    yield k, dict1[k]
            else:
                if dict2[k] is None:
                    pass
                else:
                    yield k, dict2[k]

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
            # This performs deep comparison between desired and current state
            # to ensure idempotency - only updating when actual changes exist
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
        # Use non-versioned endpoint for parity with origin_pool
        base = f'/api/config/namespaces/{self.want.metadata["namespace"]}/app_firewalls'
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
        # Prune None values and filter out system-generated fields for proper comparison
        normalized = deepcopy(data)
        
        # Filter metadata to only include user-controllable fields
        if 'metadata' in normalized:
            metadata = normalized['metadata']
            user_metadata = {}
            # Only keep user-controllable metadata fields
            user_fields = ['name', 'namespace', 'labels', 'annotations', 'description', 'disable']
            for field in user_fields:
                if field in metadata and metadata[field] is not None:
                    user_metadata[field] = metadata[field]
            normalized['metadata'] = {k: v for k, v in user_metadata.items() if v is not None}
        
        # Keep spec as-is from API response, only remove system_metadata
        # Don't prune None values from spec as empty objects {} have semantic meaning
        if 'system_metadata' in normalized:
            del normalized['system_metadata']
            
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
        if self.want.patch:
            to_update = dict(self._merge_dicts(self.have.to_update(), self.want.to_update()))
        else:
            to_update = self.want.to_update()

        # Changes were already computed in present() method, just check if we have any
        if not self.changes.has_changes():
            return False

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
            patch=dict(type='bool', default=False),
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
                ai_risk_based_blocking=dict(type=dict),
                allow_all_response_codes=dict(type=dict),
                allowed_response_codes=dict(type=dict),
                blocking=dict(type=dict),
                blocking_page=dict(type=dict),
                bot_protection_setting=dict(type=dict),
                custom_anonymization=dict(type=dict),
                default_anonymization=dict(type=dict),
                default_bot_setting=dict(type=dict),
                default_detection_settings=dict(type=dict),
                detection_settings=dict(type=dict),
                disable_anonymization=dict(type=dict),
                monitoring=dict(type=dict),
                use_default_blocking_page=dict(type=dict),
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
