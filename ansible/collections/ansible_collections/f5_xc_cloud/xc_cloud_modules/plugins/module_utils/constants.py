# -*- coding: utf-8 -*-
#
# Copyright: (c) 2021, F5 Networks Inc.
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

# HTTP Headers
BASE_HEADERS = {'Content-Type': 'application/json'}

# Retry Configuration
MAX_RETRIES = 3
BACKOFF_FACTOR = 2
RETRY_CODES = [429, 502, 503, 504]  # Rate limit, bad gateway, service unavailable, gateway timeout

# API Endpoints
API_VERSION = 'v1'
TENANT_SETTINGS_ENDPOINT = f'/api/settings/{API_VERSION}/tenant_settings'
NAMESPACES_ENDPOINT = f'/api/config/{API_VERSION}/namespaces'
NAMESPACES_WEB_ENDPOINT = '/api/web/namespaces'
NAMESPACE_CASCADE_DELETE_ENDPOINT = '/api/web/namespaces/{name}/cascade_delete'
ORIGIN_POOLS_ENDPOINT = f'/api/config/{API_VERSION}/namespaces/{{namespace}}/origin_pools'
HTTP_LOADBALANCERS_ENDPOINT = '/api/config/namespaces/{namespace}/http_loadbalancers'
CDN_LOADBALANCERS_ENDPOINT = f'/api/config/{API_VERSION}/namespaces/{{namespace}}/cdn_loadbalancers'
APP_FIREWALLS_ENDPOINT = f'/api/config/{API_VERSION}/namespaces/{{namespace}}/app_firewalls'

# Timeouts
DEFAULT_TIMEOUT = 120
LONG_OPERATION_TIMEOUT = 300

# Validation Patterns removed; rely on server-side validation for domain and namespace
NAMESPACE_REGEX = r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'
