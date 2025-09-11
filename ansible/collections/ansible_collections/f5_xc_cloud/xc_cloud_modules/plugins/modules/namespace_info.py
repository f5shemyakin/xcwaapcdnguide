#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: namespace_info
short_description: Retrieve F5 Distributed Cloud Namespace information
description:
    - Retrieve information about F5 Distributed Cloud namespaces
    - Provides read-only access to namespace configuration and status
    - Supports filtering by namespace name or retrieving all namespaces
    - Returns detailed namespace metadata, specification, and system information
    - This module is for information gathering only (no modifications)
version_added: "0.0.1"
options:
    name:
        description:
            - Name of the specific namespace to retrieve
            - If not specified, all namespaces will be returned
            - Must follow DNS-1035 format
        type: str
    include_system_namespaces:
        description:
            - Include system namespaces in the results
            - System namespaces are typically managed by the platform
        type: bool
        default: false
    labels:
        description:
            - Filter namespaces by labels
            - Only namespaces matching all specified labels will be returned
        type: dict
    show_details:
        description:
            - Include detailed system metadata and status information
        type: bool
        default: true
author:
    - F5 Distributed Cloud Ansible Team
'''

EXAMPLES = r'''
---
# Get information about a specific namespace
- name: Get namespace details
  namespace_info:
    name: "production-namespace"
  register: namespace_result

- name: Display namespace status
  debug:
    msg: "Namespace {{ namespace_result.namespace.metadata.name }} is ready"
    when: namespace_result.namespace.system_metadata.initializers.pending | length == 0

# Get all user namespaces (excluding system namespaces)
- name: Get all user namespaces
  namespace_info:
  register: all_namespaces

- name: List namespace names
  debug:
    msg: "Found namespaces: {{ all_namespaces.namespaces | map(attribute='metadata.name') | list }}"

# Get namespaces with specific labels
- name: Get production namespaces
  namespace_info:
    labels:
      environment: "production"
      team: "platform"
  register: prod_namespaces

# Get namespace with minimal details
- name: Get basic namespace info
  namespace_info:
    name: "dev-namespace"
    show_details: false
  register: basic_info

# Check if namespace exists and is ready
- name: Check namespace status
  namespace_info:
    name: "my-namespace"
  register: ns_check

- name: Fail if namespace not ready
  fail:
    msg: "Namespace is not ready yet"
  when: ns_check.namespace.system_metadata.initializers.pending | length > 0
'''

RETURN = r'''
namespace:
    description: Namespace information (when name is specified)
    returned: when name parameter is provided
    type: dict
    contains:
        metadata:
            description: Namespace metadata
            type: dict
            contains:
                name:
                    description: Name of the namespace
                    type: str
                    sample: "production-namespace"
                namespace:
                    description: Parent namespace (usually "system")
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
                    sample: "Production environment namespace"
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
            type: dict
            sample: {}
        system_metadata:
            description: System-managed metadata
            type: dict
            contains:
                initializers:
                    description: Initialization status
                    type: dict
                    contains:
                        pending:
                            description: List of pending initializers
                            type: list
                            sample: []
                finalizers:
                    description: Cleanup handlers
                    type: list
                    sample: []
namespaces:
    description: List of namespaces (when name is not specified)
    returned: when name parameter is not provided
    type: list
    elements: dict
    contains:
        metadata:
            description: Namespace metadata
            type: dict
        spec:
            description: Namespace specification
            type: dict
        system_metadata:
            description: System-managed metadata
            type: dict
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.client import XcRestClient
from ..module_utils.common import (
    AnsibleF5Parameters, f5_argument_spec
)
from ..module_utils.exceptions import F5ModuleError
from ..module_utils.constants import NAMESPACES_WEB_ENDPOINT


class InfoParameters(AnsibleF5Parameters):
    api_map = {}

    api_attributes = []

    returnables = [
        'metadata',
        'spec',
        'system_metadata'
    ]

    @property
    def name(self):
        return self._values.get('name')

    @property
    def include_system_namespaces(self):
        return self._values.get('include_system_namespaces', False)

    @property
    def labels(self):
        return self._values.get('labels')

    @property
    def show_details(self):
        return self._values.get('show_details', True)

    @staticmethod
    def _prune_none(data):
        """
        Recursively remove None values from nested dictionaries and lists.
        
        Args:
            data: The data structure to prune
            
        Returns:
            The pruned data structure
        """
        if isinstance(data, dict):
            return {k: InfoParameters._prune_none(v) for k, v in data.items() if v is not None}
        elif isinstance(data, list):
            return [InfoParameters._prune_none(item) for item in data if item is not None]
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
            result = self._prune_none(result)
        except Exception:
            raise
        return result


class InfoManager(object):
    def __init__(self, *args, **kwargs):
        self.module = kwargs.get('module', None)
        self.client = XcRestClient(**self.module.params)
        self.want = InfoParameters(params=self.module.params)

    def exec_module(self):
        result = dict()
        
        if self.want.name:
            # Get specific namespace
            namespace_info = self.read_namespace_from_device(self.want.name)
            if namespace_info:
                params = InfoParameters(params=namespace_info)
                result.update(namespace=params.to_return())
            else:
                result.update(namespace={})
        else:
            # Get all namespaces
            namespaces_info = self.read_all_namespaces_from_device()
            filtered_namespaces = self._filter_namespaces(namespaces_info)
            
            processed_namespaces = []
            for ns_info in filtered_namespaces:
                params = InfoParameters(params=ns_info)
                processed_namespaces.append(params.to_return())
                
            result.update(namespaces=processed_namespaces)
            
        return result

    def read_namespace_from_device(self, name):
        """Read specific namespace from device."""
        uri = f"{NAMESPACES_WEB_ENDPOINT}/{name}"
        
        try:
            response = self.client.api.get(url=uri)
            
            if response.status == 404:
                return None
                
            if response.status not in [200, 201, 202]:
                raise F5ModuleError(f"Failed to retrieve namespace '{name}': {response.content}")
                
            return response.json()
            
        except Exception as ex:
            raise F5ModuleError(f"Error reading namespace '{name}': {str(ex)}")

    def read_all_namespaces_from_device(self):
        """Read all namespaces from device."""
        uri = NAMESPACES_WEB_ENDPOINT
        
        try:
            response = self.client.api.get(url=uri)
            
            if response.status not in [200, 201, 202]:
                raise F5ModuleError(f"Failed to retrieve namespaces: {response.content}")
                
            result = response.json()
            return result.get('items', [])
            
        except Exception as ex:
            raise F5ModuleError(f"Error reading namespaces: {str(ex)}")

    def _filter_namespaces(self, namespaces):
        """Filter namespaces based on module parameters."""
        filtered = []
        
        for namespace in namespaces:
            # Filter out system namespaces if not requested
            if not self.want.include_system_namespaces:
                ns_name = namespace.get('metadata', {}).get('name', '')
                if ns_name.startswith('system') or ns_name in ['ves-system', 'shared']:
                    continue
            
            # Filter by labels if specified
            if self.want.labels:
                ns_labels = namespace.get('metadata', {}).get('labels', {})
                if not all(ns_labels.get(k) == v for k, v in self.want.labels.items()):
                    continue
            
            # Include minimal details if requested
            if not self.want.show_details:
                namespace = self._minimize_namespace_details(namespace)
                
            filtered.append(namespace)
            
        return filtered

    def _minimize_namespace_details(self, namespace):
        """Remove detailed system information for minimal output."""
        minimal = {
            'metadata': {
                'name': namespace.get('metadata', {}).get('name'),
                'labels': namespace.get('metadata', {}).get('labels'),
                'description': namespace.get('metadata', {}).get('description'),
                'creation_timestamp': namespace.get('metadata', {}).get('creation_timestamp')
            },
            'spec': namespace.get('spec', {})
        }
        return minimal


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)
        self.argument_spec.update(
            dict(
                name=dict(
                    type='str'
                ),
                include_system_namespaces=dict(
                    type='bool',
                    default=False
                ),
                labels=dict(
                    type='dict'
                ),
                show_details=dict(
                    type='bool',
                    default=True
                )
            )
        )


def main():
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode
    )
    
    try:
        mm = InfoManager(module=module)
        results = mm.exec_module()
        module.exit_json(**results)
    except F5ModuleError as ex:
        module.fail_json(msg=str(ex))


if __name__ == '__main__':
    main()
