#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: namespace
short_description: Manage F5 Distributed Cloud Namespaces
description:
    - Create, update, delete F5 Distributed Cloud namespaces
    - Namespaces create logical independent workspaces within a tenant
    - Within a namespace, contained objects must have unique names
    - Namespaces are immediately available after creation/update operations
    - This module manages the lifecycle of namespaces (create, update, delete)
version_added: "0.0.1"
options:
    state:
        description:
            - Desired state of the namespace
            - C(present) ensures the namespace is created or updated
            - C(absent) ensures the namespace is removed
        type: str
        choices: [present, absent]
        default: present
    wait_for_completion:
        description:
            - This parameter is kept for compatibility but has no effect for namespaces
            - Namespaces are immediately available after creation/update operations
        type: bool
        default: true
    timeout:
        description:
            - This parameter is kept for compatibility but is not used for namespaces
            - Namespaces do not require waiting for completion
        type: int
        default: 120
    metadata:
        description:
            - Metadata for the namespace resource
        type: dict
        required: true
        suboptions:
            name:
                description:
                    - Name of the namespace. Must be unique within the tenant
                    - Must follow DNS-1035 format
                    - Cannot be changed after creation
                type: str
                required: true
            namespace:
                description:
                    - Parent namespace for the new namespace
                    - This field is automatically set to empty string for namespace resources
                    - Any value provided will be ignored as per F5 XC API requirements
                type: str
                default: system
            labels:
                description:
                    - Map of string keys and values for organizing and categorizing objects
                    - Used by selector expressions
                type: dict
                default: {}
            annotations:
                description:
                    - Unstructured key-value map for storing arbitrary metadata
                    - Not queryable and preserved when modifying objects
                type: dict
                default: {}
            description:
                description:
                    - Human readable description for the namespace
                type: str
            disable:
                description:
                    - Administratively disable the namespace
                type: bool
                default: false
    spec:
        description:
            - Specification for the namespace
        type: dict
        default: {}
'''

EXAMPLES = r'''
---
# Create a basic namespace
- name: Create namespace
  namespace:
    state: present
    metadata:
      name: "my-namespace"
      description: "Development namespace"

# Create namespace with labels and wait for completion
- name: Create labeled namespace
  namespace:
    state: present
    wait_for_completion: true
    timeout: 180
    metadata:
      name: "production-namespace"
      description: "Production environment namespace"
      labels:
        environment: "production"
        team: "platform"
        cost-center: "engineering"

# Create namespace with complete metadata
- name: Create annotated namespace
  namespace:
    state: present
    metadata:
      name: "dev-namespace"
      namespace: "system"
      annotations:
        created-by: "ansible"
        purpose: "development"
        contact: "dev-team@example.com"
      labels:
        environment: "development"

# Remove a namespace
- name: Remove namespace
  namespace:
    state: absent
    metadata:
      name: "old-namespace"
'''

RETURN = r'''
metadata:
    description: Namespace metadata including name, labels, and system information
    returned: always
    type: dict
    contains:
        name:
            description: Name of the namespace
            type: str
            sample: "my-namespace"
        namespace:
            description: Parent namespace (usually "system" for namespaces)
            type: str
            sample: "system"
        labels:
            description: User-defined labels
            type: dict
            sample: {"environment": "production", "team": "platform"}
        annotations:
            description: User-defined annotations
            type: dict
            sample: {"created-by": "ansible"}
        description:
            description: Human readable description
            type: str
            sample: "Development namespace"
        disable:
            description: Administrative disable flag
            type: bool
            sample: false
        creation_timestamp:
            description: When the namespace was created
            type: str
            sample: "2023-01-01T00:00:00.000Z"
        modification_timestamp:
            description: When the namespace was last modified
            type: str
            sample: "2023-01-15T10:30:00.000Z"
spec:
    description: Namespace specification
    returned: always
    type: dict
    sample: {}
system_metadata:
    description: System-managed metadata
    returned: when available
    type: dict
    contains:
        initializers:
            description: Initialization status
            type: dict
        finalizers:
            description: Cleanup handlers
            type: list
changed:
    description: Whether the namespace was changed
    returned: always
    type: bool
    sample: true
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.client import XcRestClient
from ..module_utils.common import (
    AnsibleF5Parameters, f5_argument_spec
)
from ..module_utils.exceptions import F5ModuleError, XcApiError
from ..module_utils.constants import (
    NAMESPACES_WEB_ENDPOINT, NAMESPACE_CASCADE_DELETE_ENDPOINT
)

# Define allowed empty keys that have semantic meaning when explicitly set by user
ALLOWED_EMPTY_KEYS = {
    'metadata.labels',
    'metadata.annotations',
    'spec'
}


class Parameters(AnsibleF5Parameters):
    updatables = ['metadata', 'spec']

    returnables = ['metadata', 'spec', 'system_metadata']

    def to_return(self):
        result = {}
        for returnable in self.returnables:
            result[returnable] = getattr(self, returnable)
        result = self._filter_params(result)
        return result

    def to_update(self):
        result = {}
        for updatable in self.updatables:
            value = getattr(self, updatable)
            result[updatable] = value
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
    def state(self):
        return self._values.get('state', 'present')

    @property
    def wait_for_completion(self):
        return self._values.get('wait_for_completion', True)

    @property
    def timeout(self):
        return self._values.get('timeout', 120)

    @property
    def metadata(self):
        """Construct metadata according to API specification."""
        metadata = self._values['metadata'].copy()
        
        # For namespace resources, the metadata.namespace field should be empty
        # This is different from other resources that live within a namespace
        metadata['namespace'] = ''
        
        # Ensure required fields have defaults
        if 'labels' not in metadata:
            metadata['labels'] = {}
        if 'annotations' not in metadata:
            metadata['annotations'] = {}
        if 'disable' not in metadata:
            metadata['disable'] = False
            
        # Remove None values that might cause comparison issues
        metadata = {k: v for k, v in metadata.items() if v is not None}
            
        return metadata

    @property
    def spec(self):
        return self._values.get('spec', {})


class ApiParameters(Parameters):
    @property
    def metadata(self):
        """Normalize API response metadata for comparison."""
        metadata = self._values.get('metadata', {})
        if not metadata:
            return metadata
            
        # Create a normalized copy
        normalized = metadata.copy()
        
        # Ensure consistent field presence for comparison
        # For namespace resources, the namespace field should be empty
        if 'labels' not in normalized:
            normalized['labels'] = {}
        if 'annotations' not in normalized:
            normalized['annotations'] = {}
        if 'disable' not in normalized:
            normalized['disable'] = False
        if 'namespace' not in normalized:
            normalized['namespace'] = ''
            
        # Remove None values that might cause comparison issues  
        normalized = {k: v for k, v in normalized.items() if v is not None}
        
        return normalized

    @property
    def spec(self):
        return self._values.get('spec', {})

    @property
    def system_metadata(self):
        return self._values.get('system_metadata')


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
        """Return list of parameters that have been changed."""
        return list(self._changed_params) if hasattr(self, '_changed_params') else []

    def has_changes(self):
        """Check if any changes have been made."""
        return len(self.changed_params) > 0

    def update_changed_params(self, want_params, have_params):
        """Compare want vs have and update changed parameters."""
        if not hasattr(self, '_changed_params'):
            self._changed_params = set()
            
        for param in self.updatables:
            want_value = getattr(want_params, param, None)
            have_value = getattr(have_params, param, None)
            
            # Special handling for metadata comparison
            if param == 'metadata':
                if self._metadata_differs(want_value, have_value):
                    self._changed_params.add(param)
                    setattr(self, param, want_value)
            else:
                if self._values_differ(want_value, have_value):
                    self._changed_params.add(param)
                    setattr(self, param, want_value)

    def _metadata_differs(self, want_metadata, have_metadata):
        """Specialized comparison for namespace metadata."""
        if want_metadata is None and have_metadata is None:
            return False
        if want_metadata is None or have_metadata is None:
            return True
            
        # Compare only the fields that matter for namespace updates
        important_fields = ['name', 'namespace', 'labels', 'annotations', 'description', 'disable']
        
        for field in important_fields:
            want_val = want_metadata.get(field)
            have_val = have_metadata.get(field)
            
            # Normalize empty values
            if want_val == {} and have_val is None:
                continue
            if want_val is None and have_val == {}:
                continue
            if want_val != have_val:
                return True
                
        return False

    def _values_differ(self, want_value, have_value, _depth=0, _seen=None):
        """Deep comparison of values to detect differences (overlap-only comparison)."""
        # Prevent infinite recursion
        if _depth > 50:
            return want_value != have_value
            
        if _seen is None:
            _seen = set()
            
        # Handle None values
        if want_value is None and have_value is None:
            return False
        if want_value is None or have_value is None:
            return want_value != have_value
            
        # Handle different types
        if type(want_value) != type(have_value):
            return True
            
        # Handle primitive types
        if not isinstance(want_value, (dict, list)):
            return want_value != have_value
            
        # Handle circular references
        want_id = id(want_value)
        have_id = id(have_value)
        if (want_id, have_id) in _seen:
            return False
        _seen.add((want_id, have_id))
        
        try:
            # Handle dictionaries (overlap-only comparison)
            if isinstance(want_value, dict):
                # Only compare keys that exist in wanted config (overlap-only)
                for key in want_value.keys():
                    if key not in have_value:
                        return True
                    if self._values_differ(want_value[key], have_value[key], _depth + 1, _seen):
                        return True
                return False
                
            # Handle lists
            elif isinstance(want_value, list):
                if len(want_value) != len(have_value):
                    return True
                for i, (want_item, have_item) in enumerate(zip(want_value, have_value)):
                    if self._values_differ(want_item, have_item, _depth + 1, _seen):
                        return True
                return False
                
        finally:
            _seen.discard((want_id, have_id))
            
        return False

    def _prune_none(self, data, user_specified_keys=None, current_path=""):
        """Recursively remove None values from nested dictionaries and lists."""
        if user_specified_keys is None:
            user_specified_keys = set()
            
        if isinstance(data, dict):
            new_obj = {}
            for k, v in data.items():
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
        elif isinstance(data, list):
            new_list = []
            for i, v in enumerate(data):
                item_path = f"{current_path}[{i}]" if current_path else f"[{i}]"
                pruned = self._prune_none(v, user_specified_keys, item_path)
                if pruned is not None:
                    new_list.append(pruned)
            return new_list
        else:
            return data

    def to_return(self):
        result = {}
        try:
            for returnable in self.returnables:
                value = getattr(self, returnable, None)
                if value is not None:
                    result[returnable] = value
            result = self._filter_params(result)
            
            # Extract user-specified empty keys for enhanced pruning
            temp_module = ModuleParameters({'metadata': result.get('metadata', {}), 'spec': result.get('spec', {})})
            user_specified_keys = temp_module._extract_user_specified_empty_keys(result)
            result = self._prune_none(result, user_specified_keys)
        except Exception:
            raise
        return result

    def to_update(self):
        result = {}
        try:
            for updatable in self.updatables:
                value = getattr(self, updatable, None)
                if value is not None:
                    result[updatable] = value
            result = self._filter_params(result)
            
            # Extract user-specified empty keys for enhanced pruning
            temp_module = ModuleParameters({'metadata': result.get('metadata', {}), 'spec': result.get('spec', {})})
            user_specified_keys = temp_module._extract_user_specified_empty_keys(result)
            result = self._prune_none(result, user_specified_keys)
        except Exception:
            raise
        return result


class ModuleManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = XcRestClient(**self.module.params)

        self.want = ModuleParameters(params=self.module.params)
        self.have = ApiParameters()
        self.changes = Changes()

    def _build_uri(self, operation='list'):
        """Build API URI for different operations."""
        name = self.want.metadata.get('name')
        
        base_uri = NAMESPACES_WEB_ENDPOINT
        
        if operation in ['get', 'put', 'delete'] and name:
            uri = f"{base_uri}/{name}"
        elif operation in ['list', 'create', 'post']:
            uri = base_uri
        else:
            uri = base_uri
            
        return uri

    def _handle_response(self, response, operation=''):
        """Handle API response with proper error handling."""
        if not response.ok:
            error_msg = f"API {operation} failed"
            
            try:
                error_data = response.json()
                
                if 'error' in error_data:
                    error_msg = f"{error_msg}: {error_data['error']}"
                elif 'message' in error_data:
                    error_msg = f"{error_msg}: {error_data['message']}"
                else:
                    error_msg = f"{error_msg}: {response.text}"
                    
            except ValueError:
                error_msg = f"{error_msg}: {response.text}"
                
            raise F5ModuleError(f"{error_msg} (Status: {response.status})")
            
        return response

    def exec_module(self):
        changed = False
        result = dict()
        state = self.want.state

        if state == 'present':
            changed = self.present()
        elif state == 'absent':
            changed = self.absent()

        # Return the current state from self.have, not changes
        if hasattr(self, 'have') and self.have._values:
            current_state = self.have.to_return()
            result.update(**current_state)
        
        result.update(dict(changed=changed))
        return result

    def present(self):
        if self.exists():
            return self.update()
        else:
            return self.create()

    def absent(self):
        if self.exists():
            return self.remove()
        return False

    def should_update(self):
        """Check if update is needed by comparing want vs have."""
        self.changes.update_changed_params(self.want, self.have)
        
        # Debug: let's see what we're comparing
        if self.changes.has_changes():
            changed_params = self.changes.changed_params
            # Only log in debug mode if available
            if hasattr(self.module, 'debug') and self.module.debug:
                self.module.debug(f"Changed parameters detected: {changed_params}")
        
        return self.changes.has_changes()

    def update(self):
        """Update existing namespace if changes are detected."""
        if not self.should_update():
            return False
            
        if self.module.check_mode:
            return True
            
        self.update_on_device()
        
        # Store the update response data in case read fails or returns empty data
        update_response = self.have
        
        # Try to refresh the current state after update to get the latest data
        try:
            self.read_current_from_device()
            # If read succeeds but returns empty metadata, use update response instead
            if (hasattr(self.have, 'metadata') and not self.have.metadata and 
                hasattr(update_response, 'metadata') and update_response.metadata):
                self.have = update_response
        except F5ModuleError:
            # Namespace might not be immediately readable after update
            # Use the update response data we saved
            self.have = update_response
            
        return True

    def remove(self):
        if self.module.check_mode:
            return True
            
        uri = NAMESPACE_CASCADE_DELETE_ENDPOINT.format(name=self.want.metadata['name'])
        response = self.client.api.post(url=uri)
        
        if response.status == 404:
            return False
            
        self._handle_response(response, 'delete')
        return True

    def create(self):
        if self.module.check_mode:
            return True
            
        self.create_on_device()
        
        # Store the creation response data in case read fails or returns empty data
        creation_response = self.have
        
        # Try to refresh the current state after creation to get the latest data
        try:
            self.read_current_from_device()
            # If read succeeds but returns empty metadata, use creation response instead
            if (hasattr(self.have, 'metadata') and not self.have.metadata and 
                hasattr(creation_response, 'metadata') and creation_response.metadata):
                self.have = creation_response
        except F5ModuleError:
            # Namespace might not be immediately readable after creation
            # Use the creation response data we saved
            self.have = creation_response
            
        # Final fallback: if we still don't have good data, construct from what we sent
        if not hasattr(self.have, 'metadata') or not self.have.metadata:
            # Create a minimal response from the data we sent for creation
            fallback_data = {
                'metadata': self.want.metadata,
                'spec': self.want.spec
            }
            self.have = ApiParameters(params=fallback_data)
            
        return True

    def exists(self):
        """Check if namespace exists and populate self.have."""
        try:
            uri = self._build_uri('get')
            response = self.client.api.get(url=uri)
            
            if response.status == 404:
                return False
                
            self._handle_response(response, 'read')
            
            result = response.json()
            if result.get('metadata'):
                self.have = ApiParameters(params=result)
                return True
            else:
                raise F5ModuleError("Invalid response format from API")
                
        except XcApiError as e:
            if hasattr(e, 'status_code') and e.status_code == 404:
                return False
            raise

    def read_current_from_device(self):
        """Read current namespace state from device."""
        uri = self._build_uri('get')
        response = self.client.api.get(url=uri)
        
        if response.status == 404:
            raise F5ModuleError("Namespace not found")
            
        self._handle_response(response, 'read')
        
        result = response.json()
        if result.get('metadata'):
            self.have = ApiParameters(params=result)
        else:
            raise F5ModuleError("Invalid response format from API")

    def create_on_device(self):
        """Create namespace on device."""
        uri = self._build_uri('create')
        params = self.want.to_update()
        
        response = self.client.api.post(url=uri, json=params)
        self._handle_response(response, 'create')
        
        result = response.json()
        self.have = ApiParameters(params=result)

    def update_on_device(self):
        """Update namespace on device."""
        uri = self._build_uri('put')
        params = self.want.to_update()
            
        response = self.client.api.put(url=uri, json=params)
        self._handle_response(response, 'update')
        
        result = response.json()
        self.have = ApiParameters(params=result)


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True

        argument_spec = dict(
            state=dict(
                default='present',
                choices=['present', 'absent']
            ),
            wait_for_completion=dict(
                type='bool',
                default=True
            ),
            timeout=dict(
                type='int',
                default=120
            ),
            metadata=dict(
                type='dict',
                required=True,
                options=dict(
                    name=dict(
                        type='str',
                        required=True
                    ),
                    namespace=dict(
                        type='str',
                        default='system',
                        # Note: This field is automatically set to '' for namespace resources
                        # The default 'system' is kept for compatibility but ignored
                    ),
                    labels=dict(
                        type='dict',
                        default={}
                    ),
                    annotations=dict(
                        type='dict',
                        default={}
                    ),
                    description=dict(type='str'),
                    disable=dict(
                        type='bool',
                        default=False
                    )
                )
            ),
            spec=dict(
                type='dict',
                default={}
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
