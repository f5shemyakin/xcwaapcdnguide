#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: tenant_settings_info
short_description: Gather information about F5 Distributed Cloud Tenant Settings
description:
    - Retrieve information about F5 Distributed Cloud Tenant Settings
    - This is a read-only module that does not modify any resources
    - Returns detailed tenant configuration and status information
version_added: "0.0.1"
options:
    include_credentials_expiry:
        description:
            - Include credential expiry information in the response
        type: bool
        default: true
    include_security_settings:
        description:
            - Include security settings (OTP, SSO, SCIM) in the response
        type: bool
        default: true
notes:
    - This module is read-only and will never modify resources
    - Always returns C(changed: false)
    - Supports check mode without any side effects
author:
    - F5 Networks (@f5networks)
requirements:
    - F5 Distributed Cloud Console access
    - Valid API token with read permissions
    - Access to tenant settings
'''

EXAMPLES = r'''
---
# Get tenant settings information
- name: Get tenant settings
  tenant_settings_info:
  register: tenant_info

- name: Display tenant name
  debug:
    msg: "Tenant name: {{ tenant_info.tenant.name }}"

# Get tenant settings with minimal information
- name: Get basic tenant info only
  tenant_settings_info:
    include_credentials_expiry: false
    include_security_settings: false
  register: basic_tenant_info

# Check if SSO is enabled
- name: Check SSO status
  tenant_settings_info:
  register: tenant_settings

- name: Display SSO status
  debug:
    msg: "SSO enabled: {{ tenant_settings.tenant.sso_enabled }}"

# Use tenant information in other tasks
- name: Set fact based on tenant domain
  set_fact:
    is_production: "{{ 'prod' in tenant_info.tenant.domain }}"
'''

RETURN = r'''
tenant:
    description: The tenant settings information
    returned: always
    type: dict
    contains:
        name:
            description: Tenant name
            type: str
            returned: when available
            sample: "example-tenant"
        domain:
            description: Tenant domain
            type: str
            returned: when available
            sample: "example.ves.volterra.io"
        company_name:
            description: Company name of the tenant
            type: str
            returned: when available
            sample: "Example Corp"
        tenant_id:
            description: Unique tenant identifier
            type: str
            returned: when available
            sample: "ves-io-tenant-abc123"
        sso_enabled:
            description: Whether SSO is enabled for the tenant
            type: bool
            returned: when available
            sample: true
        otp_enabled:
            description: Whether OTP is enabled for the tenant
            type: bool
            returned: when available
            sample: false
        metadata:
            description: Tenant metadata
            type: dict
            returned: when available
            sample: {
                "name": "example-tenant",
                "namespace": "system",
                "creation_timestamp": "2023-01-01T00:00:00.000Z"
            }
        spec:
            description: Tenant specification
            type: dict
            returned: when available
            sample: {
                "tenant_id": "ves-io-tenant-abc123",
                "business_info": {}
            }
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.client import XcRestClient
from ..module_utils.common import (
    AnsibleF5Parameters, f5_argument_spec
)
from ..module_utils.exceptions import F5ModuleError


class InfoParameters(AnsibleF5Parameters):
    api_map = {}

    api_attributes = []

    returnables = [
        'name',
        'domain',
        'company_name',
        'tenant_id',
        'sso_enabled',
        'otp_enabled',
        'metadata',
        'spec'
    ]

    @property
    def name(self):
        # Try to get name from metadata first, then fall back to root level
        if self._values.get('metadata', {}).get('name'):
            return self._values['metadata']['name']
        return self._values.get('name')

    @property
    def domain(self):
        return self._values.get('domain')

    @property
    def company_name(self):
        return self._values.get('company_name')

    @property
    def tenant_id(self):
        # Try to get from spec first, then fall back to root level
        if self._values.get('spec', {}).get('tenant_id'):
            return self._values['spec']['tenant_id']
        return self._values.get('tenant_id')

    @property
    def sso_enabled(self):
        return self._values.get('sso_enabled')

    @property
    def otp_enabled(self):
        return self._values.get('otp_enabled')

    @property
    def metadata(self):
        return self._values.get('metadata')

    @property
    def spec(self):
        return self._values.get('spec')

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
        
        tenant_info = self.read_current_from_device()
        
        if tenant_info:
            params = InfoParameters(params=tenant_info)
            result.update(tenant=params.to_return())
        else:
            result.update(tenant={})
            
        return result

    def read_current_from_device(self):
        uri = "/api/web/namespaces/system/tenant/settings"
        
        try:
            response = self.client.api.get(url=uri)
            
            if response.status == 404:
                return None
                
            if response.status not in [200, 201, 202]:
                raise F5ModuleError(f"Failed to retrieve tenant settings: {response.content}")
                
            return response.json()
            
        except Exception as ex:
            raise F5ModuleError(f"Error reading tenant settings: {str(ex)}")


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True
        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)
        self.argument_spec.update(
            dict(
                include_credentials_expiry=dict(
                    type='bool',
                    default=True
                ),
                include_security_settings=dict(
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
