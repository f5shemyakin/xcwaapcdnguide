#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: http_loadbalancer
short_description: Manage F5 Distributed Cloud HTTP Load Balancer
description:
    - Create, update, delete, or fetch F5 Distributed Cloud HTTP Load Balancers
    - Supports both HTTP and HTTPS configurations with automatic certificate management
    - Provides comprehensive load balancing, security, and traffic management features
    - Includes advanced security features like WAF, bot protection, DDoS mitigation, and API protection
    - Supports complex routing, rate limiting, and client management capabilities
    - This module manages the lifecycle of load balancers (create, update, delete)
version_added: "0.0.1"
options:
    state:
        description:
            - Desired state of the HTTP Load Balancer
            - C(present) ensures the load balancer is created or updated
            - C(absent) ensures the load balancer is removed
        type: str
        choices: [present, absent]
        default: present
    wait_for_completion:
        description:
            - Wait for load balancer to reach active state after operations
        type: bool
        default: true
    timeout:
        description:
            - Timeout in seconds for operations that wait for completion
        type: int
        default: 120
    metadata:
        description:
            - Metadata for the HTTP Load Balancer resource
        type: dict
        required: true
        suboptions:
            name:
                description:
                    - Name of the HTTP Load Balancer (DNS-1035 format)
                    - Must be unique within the namespace
                type: str
                required: true
            namespace:
                description:
                    - Namespace where the load balancer will be created
                    - Must be a valid DNS label format
                type: str
                required: true
            labels:
                description:
                    - Key-value pairs for organizing and selecting objects
                type: dict
            annotations:
                description:
                    - Unstructured key-value metadata
                type: dict
            description:
                description:
                    - Human readable description
                type: str
            disable:
                description:
                    - Administratively disable the load balancer
                type: bool
    spec:
        description:
            - HTTP Load Balancer specification
            - Comprehensive configuration including security, routing, and advanced features
            - See F5 Distributed Cloud API documentation for detailed options
        type: dict
        suboptions:
            domains:
                description:
                    - List of domains that this load balancer will serve
                    - Must be valid FQDN format
                type: list
                elements: str
                required: true
            http:
                description:
                    - HTTP configuration (port 80)
                    - Mutually exclusive with https and https_auto_cert
                type: dict
                suboptions:
                    port:
                        description: HTTP port number
                        type: int
                        default: 80
                    dns_volterra_managed:
                        description: Use F5 XC managed DNS
                        type: bool
            https:
                description:
                    - HTTPS configuration with custom certificates
                    - Mutually exclusive with http and https_auto_cert
                type: dict
                suboptions:
                    port:
                        description: HTTPS port number
                        type: int
                        default: 443
                    add_hsts:
                        description: Add HTTP Strict Transport Security header
                        type: bool
                    http_redirect:
                        description: Redirect HTTP to HTTPS
                        type: bool
                    tls_cert_params:
                        description: TLS certificate parameters
                        type: dict
            https_auto_cert:
                description:
                    - HTTPS configuration with automatic certificate management
                    - Mutually exclusive with http and https
                type: dict
                suboptions:
                    port:
                        description: HTTPS port number
                        type: int
                        default: 443
                    add_hsts:
                        description: Add HTTP Strict Transport Security header
                        type: bool
                    http_redirect:
                        description: Redirect HTTP to HTTPS
                        type: bool
                    tls_config:
                        description: TLS security configuration
                        type: dict
            default_route_pools:
                description:
                    - Default origin pools for routing traffic
                    - List of pool references with weights and priorities
                type: list
                elements: dict
            routes:
                description:
                    - Custom routing rules for specific paths or conditions
                    - Supports simple routes, redirects, and direct responses
                type: list
                elements: dict
            app_firewall:
                description:
                    - Web Application Firewall configuration
                    - Reference to WAF policy
                type: dict
                suboptions:
                    name:
                        description: WAF policy name
                        type: str
                        required: true
                    namespace:
                        description: WAF policy namespace
                        type: str
                    tenant:
                        description: WAF policy tenant
                        type: str
            bot_defense:
                description:
                    - Bot protection configuration
                    - Comprehensive bot detection and mitigation
                type: dict
                suboptions:
                    policy:
                        description: Bot defense policy configuration
                        type: dict
                    regional_endpoint:
                        description: Regional endpoint for bot defense
                        type: str
                        choices: [AUTO, US, EU, ASIA]
                    timeout:
                        description: Bot defense timeout in milliseconds
                        type: int
            rate_limit:
                description:
                    - Rate limiting configuration
                    - Controls request rates per client
                type: dict
                suboptions:
                    rate_limiter:
                        description: Rate limiter configuration
                        type: dict
                    ip_allowed_list:
                        description: IP addresses exempt from rate limiting
                        type: dict
            api_protection_rules:
                description:
                    - API-specific protection rules
                    - Endpoint and group-based protection
                type: dict
            api_specification:
                description:
                    - API specification and validation
                    - OpenAPI-based validation rules
                type: dict
            enable_api_discovery:
                description:
                    - API discovery configuration
                    - Automatic API endpoint detection
                type: dict
            cors_policy:
                description:
                    - Cross-Origin Resource Sharing policy
                    - CORS headers and restrictions
                type: dict
                suboptions:
                    allow_credentials:
                        description: Allow credentials in CORS requests
                        type: bool
                    allow_headers:
                        description: Allowed headers
                        type: str
                    allow_methods:
                        description: Allowed HTTP methods
                        type: str
                    allow_origin:
                        description: Allowed origins
                        type: list
                        elements: str
            enable_ip_reputation:
                description:
                    - IP reputation and threat detection
                    - Blocks traffic from malicious IP addresses
                type: dict
                suboptions:
                    ip_threat_categories:
                        description: IP threat categories to block
                        type: list
                        elements: str
            ddos_mitigation_rules:
                description:
                    - DDoS mitigation rules
                    - Layer 7 DDoS protection
                type: list
                elements: dict
            l7_ddos_protection:
                description:
                    - Layer 7 DDoS protection configuration
                    - Advanced DDoS mitigation strategies
                type: dict
            trusted_clients:
                description:
                    - Trusted client configurations
                    - Clients exempt from certain security checks
                type: list
                elements: dict
            blocked_clients:
                description:
                    - Blocked client configurations
                    - Clients denied access
                type: list
                elements: dict
            user_identification:
                description:
                    - User identification policy reference
                    - Custom user identification methods
                type: dict
            jwt_validation:
                description:
                    - JWT token validation
                    - Validates JWT tokens for API access
                type: dict
            cookie_stickiness:
                description:
                    - Cookie-based session stickiness
                    - Routes requests to same backend based on cookies
                type: dict
            more_option:
                description:
                    - Advanced configuration options
                    - Headers, compression, buffering, and other advanced settings
                type: dict
notes:
    - This module manages the lifecycle of HTTP Load Balancers (create, update, delete)
    - Many configuration options are mutually exclusive (e.g., different protocol types, challenge types)
    - Complex nested configurations support extensive customization
    - Reference configurations (pools, policies) must exist in accessible namespaces
    - Some features require specific F5 XC license tiers
    - Always validate configuration in a test environment first
    - Supports check mode for validating changes without applying them
    - Module is idempotent - repeated runs with same configuration will not cause changes
    - Returns C(changed: false) when no modifications are needed
author:
    - F5 Networks (@f5networks)
requirements:
    - F5 Distributed Cloud Console access
    - Valid API token with appropriate permissions
    - Referenced resources (pools, policies) must exist
'''

EXAMPLES = r'''
---
# Basic HTTP Load Balancer with WAF
- name: Create HTTP Load Balancer with WAF
  http_loadbalancer:
    state: present
    metadata:
      name: "demo-http-lb"
      namespace: "default"
      description: "Demo HTTP Load Balancer with WAF protection"
      labels:
        app: "demo"
        environment: "production"
    spec:
      domains:
        - "app.example.com"
      https_auto_cert:
        http_redirect: true
        add_hsts: true
        port: 443
        tls_config:
          default_security: {}
      default_route_pools:
        - pool:
            tenant: "{{ ansible_f5_tenant }}"
            namespace: "default"
            name: "demo-origin-pool"
          weight: 1
          priority: 1
      app_firewall:
        tenant: "{{ ansible_f5_tenant }}"
        namespace: "default"
        name: "demo-waf-policy"

# Advanced Security Configuration
- name: Create Load Balancer with Advanced Security
  http_loadbalancer:
    state: present
    metadata:
      name: "secure-lb"
      namespace: "production"
      description: "Load Balancer with comprehensive security features"
    spec:
      domains:
        - "secure.example.com"
        - "api.example.com"
      https_auto_cert:
        http_redirect: true
        add_hsts: true
        port: 443
        tls_config:
          default_security: {}
      default_route_pools:
        - pool:
            namespace: "production"
            name: "secure-pool"
          weight: 1
      # Bot Defense Configuration
      bot_defense:
        enable_cors_support: {}
        policy:
          js_insert_all_pages:
            javascript_location: "AFTER_HEAD"
          protected_app_endpoints:
            - any_domain: {}
              path:
                prefix: "/api"
              mitigation:
                block:
                  status: 403
        regional_endpoint: "AUTO"
        timeout: 1000
      # Rate Limiting
      rate_limit:
        rate_limiter:
          total_number: 100
          unit: "SECOND"
          burst_multiplier: 2
          action_block:
            seconds:
              duration: 60
        ip_allowed_list:
          prefixes:
            - "10.0.0.0/8"
            - "192.168.0.0/16"
      # IP Reputation
      enable_ip_reputation:
        ip_threat_categories:
          - "SPAM_SOURCES"
          - "MALWARE"
          - "PHISHING"
      # CORS Policy
      cors_policy:
        allow_credentials: true
        allow_headers: "Content-Type,Authorization"
        allow_methods: "GET,POST,PUT,DELETE,OPTIONS"
        allow_origin:
          - "https://app.example.com"
          - "https://admin.example.com"
        maximum_age: 86400

# API Protection Configuration
- name: Create API Load Balancer with Protection
  http_loadbalancer:
    state: present
    metadata:
      name: "api-lb"
      namespace: "api"
      description: "API Load Balancer with comprehensive API protection"
    spec:
      domains:
        - "api.mycompany.com"
      https_auto_cert:
        http_redirect: true
        port: 443
      default_route_pools:
        - pool:
            namespace: "api"
            name: "api-backend-pool"
      # API Discovery
      enable_api_discovery:
        default_api_auth_discovery: {}
        discovered_api_settings:
          purge_duration_for_inactive_discovered_apis: 2592000  # 30 days
      # API Specification
      api_specification:
        api_definition:
          name: "api-spec"
          namespace: "api"
        validation_all_spec_endpoints:
          validation_mode:
            validation_mode_active:
              enforcement_block: {}
              request_validation_properties:
                - "PROPERTY_QUERY_PARAMETERS"
                - "PROPERTY_REQUEST_HEADERS"
          settings:
            property_validation_settings_default: {}
      # API Rate Limiting
      api_rate_limit:
        api_endpoint_rules:
          - api_endpoint_path: "/api/v1/users"
            api_endpoint_method:
              methods: ["GET", "POST"]
            inline_rate_limiter:
              threshold: 50
              unit: "MINUTE"
              use_http_lb_user_id: {}
            any_domain: {}
        server_url_rules:
          - api_group: "user-management"
            base_path: "/api/v1"
            inline_rate_limiter:
              threshold: 200
              unit: "MINUTE"
            any_domain: {}
      # JWT Validation
      jwt_validation:
        action:
          block: {}
        jwks_config:
          cleartext: |
            {
              "keys": [
                {
                  "kty": "RSA",
                  "use": "sig",
                  "kid": "example-key",
                  "n": "...",
                  "e": "AQAB"
                }
              ]
            }
        target:
          base_paths:
            base_paths: ["/api/v1/secure"]
        token_location:
          bearer_token: {}
        reserved_claims:
          issuer: "https://auth.mycompany.com"
          audience:
            audiences: ["api.mycompany.com"]

# DDoS Protection Configuration
- name: Create Load Balancer with DDoS Protection
  http_loadbalancer:
    state: present
    metadata:
      name: "ddos-protected-lb"
      namespace: "production"
      description: "Load Balancer with DDoS protection"
    spec:
      domains:
        - "protected.example.com"
      https_auto_cert:
        http_redirect: true
        port: 443
      default_route_pools:
        - pool:
            namespace: "production"
            name: "protected-pool"
      # L7 DDoS Protection
      l7_ddos_protection:
        mitigation_js_challenge:
          cookie_expiry: 3600
          js_script_delay: 5000
        clientside_action_js_challenge:
          cookie_expiry: 1800
          custom_page: |
            <html>
              <head><title>Security Check</title></head>
              <body><h1>Please wait while we verify your request...</h1></body>
            </html>
      # DDoS Mitigation Rules
      ddos_mitigation_rules:
        - block: {}
          ddos_client_source:
            country_list: ["COUNTRY_CN", "COUNTRY_RU"]
          metadata:
            name: "block-suspicious-countries"
            description: "Block traffic from high-risk countries"
        - block: {}
          ip_prefix_list:
            ip_prefixes:
              - "192.0.2.0/24"  # Example malicious subnet
          metadata:
            name: "block-known-bad-ips"
      # Slow DDoS Mitigation
      slow_ddos_mitigation:
        request_timeout: 30
        request_headers_timeout: 10

# Multi-Pool Load Balancer with Custom Routing
- name: Create Multi-Pool Load Balancer
  http_loadbalancer:
    state: present
    metadata:
      name: "multi-pool-lb"
      namespace: "production"
    spec:
      domains:
        - "app.example.com"
      https_auto_cert:
        http_redirect: true
        port: 443
      # Custom Routes
      routes:
        - simple_route:
            path:
              prefix: "/api/v1"
            http_method: "ANY"
            origin_pools:
              - pool:
                  namespace: "production"
                  name: "api-v1-pool"
                weight: 100
            advanced_options:
              request_headers_to_add:
                - name: "X-API-Version"
                  value: "v1"
                  append: false
        - simple_route:
            path:
              prefix: "/api/v2"
            http_method: "ANY"
            origin_pools:
              - pool:
                  namespace: "production"
                  name: "api-v2-pool"
                weight: 100
            advanced_options:
              request_headers_to_add:
                - name: "X-API-Version"
                  value: "v2"
                  append: false
        - redirect_route:
            path:
              prefix: "/old-api"
            route_redirect:
              prefix_rewrite: "/api/v2"
              response_code: 301
      # Default pool for unmatched routes
      default_route_pools:
        - pool:
            namespace: "production"
            name: "default-pool"
          weight: 1

# Client Management Configuration
- name: Create Load Balancer with Client Management
  http_loadbalancer:
    state: present
    metadata:
      name: "client-managed-lb"
      namespace: "production"
    spec:
      domains:
        - "managed.example.com"
      https_auto_cert:
        http_redirect: true
        port: 443
      default_route_pools:
        - pool:
            namespace: "production"
            name: "managed-pool"
      # Trusted Clients
      trusted_clients:
        - ip_prefix: "10.0.0.0/8"
          actions: ["SKIP_PROCESSING_WAF"]
          metadata:
            name: "internal-network"
            description: "Trust internal network traffic"
        - ip_prefix: "203.0.113.0/24"
          actions: ["SKIP_PROCESSING_WAF", "SKIP_PROCESSING_BOT_DEFENSE"]
          metadata:
            name: "partner-network"
            description: "Trust partner network"
      # Blocked Clients
      blocked_clients:
        - ip_prefix: "192.0.2.0/24"
          metadata:
            name: "blocked-subnet"
            description: "Known malicious subnet"
        - as_number: 64512
          expiration_timestamp: "2025-12-31T23:59:59Z"
          metadata:
            name: "temporary-as-block"
            description: "Temporary block for problematic AS"
      # User Identification
      user_identification:
        name: "custom-user-id"
        namespace: "production"

# Advanced HTTP/HTTPS Configuration
- name: Create Load Balancer with Advanced Protocol Settings
  http_loadbalancer:
    state: present
    metadata:
      name: "advanced-protocol-lb"
      namespace: "production"
    spec:
      domains:
        - "advanced.example.com"
      # Custom HTTPS Configuration
      https:
        port: 8443
        add_hsts: true
        connection_idle_timeout: 300
        tls_cert_params:
          certificates:
            - name: "custom-cert"
              namespace: "production"
          tls_config:
            custom_security:
              min_version: "TLS_1_2"
              max_version: "TLS_1_3"
              cipher_suites:
                - "TLS_AES_256_GCM_SHA384"
                - "TLS_CHACHA20_POLY1305_SHA256"
          use_mtls:
            trusted_ca:
              name: "client-ca"
              namespace: "production"
            client_certificate_optional: false
            xfcc_options:
              xfcc_header_elements: ["CERT", "SUBJECT", "URI"]
      default_route_pools:
        - pool:
            namespace: "production"
            name: "advanced-pool"
      # Advanced Options
      more_option:
        max_request_header_size: 65536
        idle_timeout: 300
        buffer_policy:
          max_request_bytes: 10485760  # 10MB
        compression_params:
          content_length: 1024
          content_type: ["text/html", "application/json", "text/css"]
          remove_accept_encoding_header: false
        request_headers_to_add:
          - name: "X-Forwarded-Proto"
            value: "https"
            append: false
        response_headers_to_add:
          - name: "X-Content-Type-Options"
            value: "nosniff"
            append: false
          - name: "X-Frame-Options"
            value: "DENY"
            append: false

# Load Balancer with Advanced Policy-Based Challenges
- name: Create Load Balancer with Policy-Based Challenge Rules
  http_loadbalancer:
    state: present
    metadata:
      name: "challenge-policy-lb"
      namespace: "security"
      description: "Load Balancer with advanced challenge policies"
    spec:
      domains:
        - "secure-app.example.com"
      https_auto_cert:
        http_redirect: true
        port: 443
      default_route_pools:
        - pool:
            namespace: "security"
            name: "secure-app-pool"
      # Advanced Policy-Based Challenge Configuration
      policy_based_challenge:
        js_challenge_parameters:
          cookie_expiry: 3600
          js_script_delay: 5000
          custom_page: |
            <html>
              <head><title>Security Verification</title></head>
              <body><h1>Verifying your browser...</h1></body>
            </html>
        captcha_challenge_parameters:
          cookie_expiry: 1800
          custom_page: |
            <html>
              <head><title>CAPTCHA Challenge</title></head>
              <body><h1>Please complete the CAPTCHA</h1></body>
            </html>
        rule_list:
          rules:
            - metadata:
                name: "protect-login-endpoint"
                description: "Enhanced protection for login page"
              spec:
                enable_javascript_challenge: {}
                path:
                  exact_values: ["/login", "/api/auth/login"]
                http_method:
                  methods: ["POST"]
                ip_prefix_list:
                  invert_match: true
                  ip_prefixes: ["10.0.0.0/8", "192.168.0.0/16"]
            - metadata:
                name: "captcha-for-suspicious-ips" 
                description: "CAPTCHA challenge for external IPs"
              spec:
                enable_captcha_challenge: {}
                ip_prefix_list:
                  ip_prefixes: ["0.0.0.0/0"]
                  invert_match: false
      # Bot Defense Advanced
      bot_defense_advanced:
        js_insert_all_pages:
          javascript_location: "AFTER_HEAD"
        web:
          name: "advanced-bot-policy"
          namespace: "security"
          tenant: "{{ ansible_f5_tenant }}"

# Load Balancer with Cookie Stickiness
- name: Create Load Balancer with Session Stickiness
  http_loadbalancer:
    state: present
    metadata:
      name: "sticky-lb"
      namespace: "production"
    spec:
      domains:
        - "sticky.example.com"
      https_auto_cert:
        http_redirect: true
        port: 443
      default_route_pools:
        - pool:
            namespace: "production"
            name: "sticky-pool"
      # Cookie-based Stickiness
      cookie_stickiness:
        name: "JSESSIONID"
        path: "/"
        ttl: 3600
        add_httponly: {}
        add_secure: {}
        samesite_strict: {}
      # Protected Cookies
      protected_cookies:
        - name: "session_token"
          enable_tampering_protection: {}
          add_secure: {}
          add_httponly: {}
          samesite_strict: {}
        - name: "auth_token"
          enable_tampering_protection: {}
          max_age_value: 1800

# Simple HTTP-only Load Balancer
- name: Create HTTP-only Load Balancer
  http_loadbalancer:
    state: present
    metadata:
      name: "simple-http-lb"
      namespace: "default"
    spec:
      domains:
        - "simple.example.com"
      http:
        port: 80
        dns_volterra_managed: false
      default_route_pools:
        - pool:
            namespace: "default"
            name: "simple-pool"

# Update Load Balancer
- name: Update Load Balancer
  http_loadbalancer:
    state: present
    metadata:
      name: "demo-http-lb"
      namespace: "default"
    spec:
      rate_limit:
        rate_limiter:
          total_number: 200
          unit: "SECOND"

# Check mode - validate configuration without applying changes
- name: Check what changes would be made
  http_loadbalancer:
    state: present
    metadata:
      name: "demo-http-lb"
      namespace: "default"
    spec:
      domains:
        - "app.example.com"
      https_auto_cert:
        http_redirect: true
  check_mode: true
  register: check_result

- name: Display what would change
  debug:
    msg: "Would make changes: {{ check_result.changed }}, Changed params: {{ check_result.changed_params | default([]) }}"

# Remove Load Balancer
- name: Remove Load Balancer
  http_loadbalancer:
    state: absent
    metadata:
      name: "demo-http-lb"
      namespace: "default"

# Create Load Balancer with custom timeout
- name: Create Load Balancer with custom timeout
  http_loadbalancer:
    state: present
    timeout: 300
    wait_for_completion: true
    metadata:
      name: "custom-lb"
      namespace: "default"
    spec:
      domains:
        - "custom.example.com"
      https_auto_cert:
        http_redirect: true
'''

RETURN = r'''
---
changed:
    description: Whether the load balancer was changed
    type: bool
    returned: always
    sample: true
changed_params:
    description: List of parameters that were changed
    type: list
    elements: str
    returned: when changed=true
    sample: ["metadata", "spec"]
metadata:
    description: Load balancer metadata
    type: dict
    returned: when load balancer exists
    contains:
        name:
            description: Load balancer name
            type: str
            sample: "my-load-balancer"
        namespace:
            description: Load balancer namespace
            type: str
            sample: "production"
        labels:
            description: Load balancer labels
            type: dict
            sample: {"app": "web", "env": "prod"}
        annotations:
            description: Load balancer annotations
            type: dict
        description:
            description: Load balancer description
            type: str
            sample: "Production web load balancer"
        disable:
            description: Whether load balancer is disabled
            type: bool
            sample: false
spec:
    description: Load balancer specification
    type: dict
    returned: when load balancer exists
    contains:
        domains:
            description: Domains served by the load balancer
            type: list
            elements: str
            sample: ["app.example.com", "www.example.com"]
        https_auto_cert:
            description: HTTPS auto-certificate configuration
            type: dict
        default_route_pools:
            description: Default routing pools
            type: list
        app_firewall:
            description: WAF configuration
            type: dict
status:
    description: Load balancer status
    type: dict
    returned: when load balancer exists
    contains:
        state:
            description: Current state of the load balancer
            type: str
            sample: "ACTIVE"
        conditions:
            description: Status conditions
            type: list
'''

from ansible.module_utils.basic import AnsibleModule
from collections import defaultdict

from ..module_utils.client import XcRestClient
from ..module_utils.common import (
    AnsibleF5Parameters, f5_argument_spec, validate_domain, validate_namespace, sanitize_name
)
from ..module_utils.exceptions import F5ModuleError, XcApiError, XcValidationError
from ..module_utils.constants import HTTP_LOADBALANCERS_ENDPOINT, DEFAULT_TIMEOUT
from ..module_utils.utils import wait_for_state, safe_get, normalize_response


class Parameters(AnsibleF5Parameters):
    updatables = ['metadata', 'spec']
    returnables = ['metadata', 'spec', 'status']

    def to_return(self):
        result = {}
        for returnable in self.returnables:
            value = getattr(self, returnable)
            if value is not None:
                result[returnable] = value
        result = self._filter_params(result)
        return result

    def to_update(self):
        result = {}
        for updateable in self.updatables:
            value = getattr(self, updateable)
            if value is not None:
                result[updateable] = value
        result = self._filter_params(result)
        return result

    def _normalize_reference(self, ref_config, default_tenant=None, default_namespace=None):
        """Normalize reference configurations to include tenant/namespace."""
        if not isinstance(ref_config, dict):
            return ref_config
        
        normalized = ref_config.copy()
        
        # Add default tenant if not specified
        if 'tenant' not in normalized and default_tenant:
            normalized['tenant'] = default_tenant
        
        # Add default namespace if not specified
        if 'namespace' not in normalized and default_namespace:
            normalized['namespace'] = default_namespace
        
        return normalized

    def _normalize_pool_references(self, pools_config):
        """Normalize pool reference configurations."""
        if not isinstance(pools_config, list):
            return pools_config
        
        normalized_pools = []
        for pool in pools_config:
            if isinstance(pool, dict) and 'pool' in pool:
                normalized_pool = pool.copy()
                normalized_pool['pool'] = self._normalize_reference(
                    pool['pool'],
                    default_tenant=self.metadata.get('tenant') if self.metadata else None,
                    default_namespace=self.metadata.get('namespace') if self.metadata else None
                )
                normalized_pools.append(normalized_pool)
            else:
                normalized_pools.append(pool)
        
        return normalized_pools

    def _validate_and_normalize_spec(self, raw_spec):
        """Validate and normalize the spec configuration.

        NOTE: This function must NOT call self.spec (property) because the
        property itself invokes this function. Always work off the raw_spec
        dict passed in to avoid infinite recursion. The caller (spec property
        or to_update) is responsible for supplying the original user-provided
        spec structure.
        """
        if not raw_spec:
            return {}

        # Work on a shallow copy so we never mutate caller's dict
        spec = raw_spec.copy()
        
        # Normalize pool references
        if 'default_route_pools' in spec:
            spec['default_route_pools'] = self._normalize_pool_references(spec['default_route_pools'])

        if 'default_pool_list' in spec and isinstance(spec['default_pool_list'], dict):
            if 'pools' in spec['default_pool_list']:
                spec['default_pool_list']['pools'] = self._normalize_pool_references(
                    spec['default_pool_list']['pools']
                )
        
        # Normalize security references
        security_refs = ['app_firewall', 'user_identification']
        for ref_key in security_refs:
            if ref_key in spec:
                spec[ref_key] = self._normalize_reference(
                    spec[ref_key],
                    default_tenant=self.metadata.get('tenant') if self.metadata else None,
                    default_namespace=self.metadata.get('namespace') if self.metadata else None
                )

        # Validate all spec configurations comprehensively
        # NOTE: We temporarily set a normalized spec for validation methods to use
        old_cache = getattr(self, '_normalized_spec_cache', None)
        self._normalized_spec_cache = spec
        try:
            self._validate_protocol_config_raw(spec)
            self._validate_security_config_raw(spec)
            self._validate_pool_config_raw(spec)
            self._validate_lb_algorithm_config_raw(spec)
            self._validate_user_identification_config_raw(spec)
            self._validate_security_references(spec)
        finally:
            # Restore original cache state
            if old_cache is not None:
                self._normalized_spec_cache = old_cache
            else:
                if hasattr(self, '_normalized_spec_cache'):
                    delattr(self, '_normalized_spec_cache')

        return spec

    def _validate_security_references(self, spec):
        """Validate security reference configurations."""
        # Helper: treat None/empty dict as absence (skip validation)
        def _is_effectively_empty(value):
            if value is None:
                return True
            if isinstance(value, dict) and len([v for v in value.values() if v is not None]) == 0:
                return True
            return False

        # Validate app_firewall only if provided with some data
        if 'app_firewall' in spec and not _is_effectively_empty(spec['app_firewall']):
            app_firewall = spec['app_firewall']
            if not isinstance(app_firewall, dict) or not app_firewall.get('name'):
                raise XcValidationError("app_firewall must include a 'name' field when provided")

        # Validate user_identification only if provided with some data
        if 'user_identification' in spec and not _is_effectively_empty(spec['user_identification']):
            user_id = spec['user_identification']
            if not isinstance(user_id, dict) or not user_id.get('name'):
                raise XcValidationError("user_identification must include a 'name' field when provided")

        # Validate service policy references (skip if empty)
        if 'active_service_policies' in spec and not _is_effectively_empty(spec['active_service_policies']):
            policies = spec['active_service_policies']
            if isinstance(policies, dict) and 'policies' in policies and policies['policies'] is not None:
                for policy in policies['policies']:
                    if not isinstance(policy, dict) or not policy.get('name'):
                        raise XcValidationError("Each policy in active_service_policies.policies must include a 'name' field")

    def validate_params(self):
        """Validate module parameters."""
        # Validate metadata
        if not self.metadata:
            raise XcValidationError("metadata is required")
        
        metadata = self.metadata
        if not metadata.get('name'):
            raise XcValidationError("metadata.name is required")
        # Per user instruction, do not pre-validate namespace existence/format; allow server to return error
        # if not metadata.get('namespace'):
        #     raise XcValidationError("metadata.namespace is required")
        # if metadata.get('namespace'):
        #     validate_namespace(metadata['namespace'])
        
        # Validate domains if present in spec - access raw spec to avoid triggering validation during validation
        raw_spec = self._values.get('spec')
        if raw_spec and 'domains' in raw_spec:
            domains = raw_spec['domains']
            if not isinstance(domains, list) or len(domains) == 0:
                raise XcValidationError("spec.domains must be a non-empty list")
            
            for domain in domains:
                validate_domain(domain)
        
        # Validate protocol configuration - this will trigger comprehensive spec validation
        if raw_spec:
            # Accessing self.spec will trigger _validate_and_normalize_spec which now includes all validations
            _ = self.spec
        
        return True

    def _validate_protocol_config(self):
        """Validate HTTP/HTTPS protocol configuration."""
        return self._validate_protocol_config_raw(self.spec)
    
    def _validate_protocol_config_raw(self, spec):
        """Validate HTTP/HTTPS protocol configuration using raw spec dict."""
        
        # Helper function to check if a value is effectively configured
        def _is_effectively_configured(value):
            """Check if a value is meaningfully configured (not None, empty dict, or empty list)."""
            if value is None:
                return False
            if isinstance(value, dict) and len(value) == 0:
                return False
            if isinstance(value, list) and len(value) == 0:
                return False
            # For dictionaries, check if all values are None/empty
            if isinstance(value, dict):
                return any(v is not None and v not in ({}, []) for v in value.values())
            return True
        
        protocol_configs = ['http', 'https', 'https_auto_cert']
        configured_protocols = [p for p in protocol_configs if p in spec and _is_effectively_configured(spec[p])]
        
        if len(configured_protocols) == 0:
            raise XcValidationError("At least one protocol configuration (http, https, or https_auto_cert) is required")
        
        # Validate port configurations
        for protocol in configured_protocols:
            config = spec[protocol]
            if isinstance(config, dict):
                port = config.get('port')
                port_ranges = config.get('port_ranges')
                
                if port and port_ranges:
                    raise XcValidationError(f"Cannot specify both 'port' and 'port_ranges' for {protocol}")
                
                if port and not isinstance(port, int):
                    raise XcValidationError(f"Port must be an integer for {protocol}")
                
                if port and (port < 1 or port > 65535):
                    raise XcValidationError(f"Port must be between 1 and 65535 for {protocol}")

    def _validate_security_config(self):
        """Validate security-related configurations."""
        return self._validate_security_config_raw(self.spec)
    
    def _validate_security_config_raw(self, spec):
        """Validate security-related configurations using raw spec dict."""
        
        # Helper function to check if a value is effectively configured
        def _is_effectively_configured(value):
            """Check if a value is meaningfully configured (not None, empty dict, or empty list)."""
            if value is None:
                return False
            if isinstance(value, dict) and len(value) == 0:
                return False
            if isinstance(value, list) and len(value) == 0:
                return False
            # For dictionaries, check if all values are None/empty
            if isinstance(value, dict):
                return any(v is not None and v not in ({}, []) for v in value.values())
            return True
        
        # Validate WAF configuration
        if 'app_firewall' in spec and _is_effectively_configured(spec['app_firewall']):
            waf_config = spec['app_firewall']
            if not isinstance(waf_config, dict) or not waf_config.get('name'):
                raise XcValidationError("app_firewall.name is required when app_firewall is specified")
        
        # Validate bot defense configuration
        bot_configs = ['bot_defense', 'bot_defense_advanced']
        configured_bots = [b for b in bot_configs if b in spec and _is_effectively_configured(spec[b])]
        
        if len(configured_bots) > 1:
            raise XcValidationError("Cannot configure multiple bot defense types simultaneously")
        
        # Validate challenge configurations
        challenge_configs = ['captcha_challenge', 'js_challenge', 'no_challenge', 'enable_challenge', 'policy_based_challenge']
        configured_challenges = [c for c in challenge_configs if c in spec and _is_effectively_configured(spec[c])]
        
        if len(configured_challenges) > 1:
            raise XcValidationError("Cannot configure multiple challenge types simultaneously")
        
        # Validate IP reputation settings
        ip_rep_configs = ['enable_ip_reputation', 'disable_ip_reputation']
        configured_ip_rep = [i for i in ip_rep_configs if i in spec and _is_effectively_configured(spec[i])]
        
        if len(configured_ip_rep) > 1:
            raise XcValidationError("Cannot both enable and disable IP reputation simultaneously")
        
        # Validate rate limiting configuration
        rate_configs = ['rate_limit', 'disable_rate_limit']
        configured_rates = [r for r in rate_configs if r in spec and _is_effectively_configured(spec[r])]
        
        if len(configured_rates) > 1:
            raise XcValidationError("Cannot both enable and disable rate limiting simultaneously")

    def _validate_pool_config(self):
        """Validate pool configuration."""
        return self._validate_pool_config_raw(self.spec)
    
    def _validate_pool_config_raw(self, spec):
        """Validate pool configuration using raw spec dict."""
        
        # Helper function to check if a value is effectively configured
        def _is_effectively_configured(value):
            """Check if a value is meaningfully configured (not None, empty dict, or empty list)."""
            if value is None:
                return False
            if isinstance(value, dict) and len(value) == 0:
                return False
            if isinstance(value, list) and len(value) == 0:
                return False
            # For dictionaries, check if all values are None/empty
            if isinstance(value, dict):
                return any(v is not None and v not in ({}, []) for v in value.values())
            return True
        
        pool_configs = ['default_pool', 'default_pool_list', 'default_route_pools']
        configured_pools = [p for p in pool_configs if p in spec and _is_effectively_configured(spec[p])]
        
        if len(configured_pools) == 0:
            raise XcValidationError("At least one pool configuration is required (default_pool, default_pool_list, or default_route_pools)")
        
        if len(configured_pools) > 1:
            raise XcValidationError("Cannot configure multiple pool types simultaneously")
        
        # Validate pool references
        for pool_type in configured_pools:
            pool_config = spec[pool_type]
            
            if pool_type == 'default_pool' and isinstance(pool_config, dict):
                if 'origin_servers' in pool_config:
                    origin_servers = pool_config['origin_servers']
                    if not isinstance(origin_servers, list) or len(origin_servers) == 0:
                        raise XcValidationError("default_pool.origin_servers must be a non-empty list")
                    
                    # Validate each origin server
                    for i, server in enumerate(origin_servers):
                        if not isinstance(server, dict):
                            raise XcValidationError(f"Origin server {i} must be a dictionary")
                        
                        # Check required fields based on server type
                        if 'public_name' in server:
                            public_name = server['public_name']
                            if isinstance(public_name, dict):
                                if not public_name.get('dns_name'):
                                    raise XcValidationError(f"Origin server {i}: public_name.dns_name is required")
                        elif 'private_name' in server:
                            private_name = server['private_name']
                            if isinstance(private_name, dict):
                                if not private_name.get('dns_name') and not private_name.get('ip'):
                                    raise XcValidationError(f"Origin server {i}: private_name requires dns_name or ip")
                        elif 'k8s_service' in server:
                            k8s_service = server['k8s_service']
                            if isinstance(k8s_service, dict):
                                if not k8s_service.get('service_name'):
                                    raise XcValidationError(f"Origin server {i}: k8s_service.service_name is required")
                        else:
                            raise XcValidationError(f"Origin server {i}: Must specify public_name, private_name, or k8s_service")
            
            elif pool_type in ['default_pool_list', 'default_route_pools'] and isinstance(pool_config, (list, dict)):
                pools = pool_config.get('pools') if isinstance(pool_config, dict) else pool_config
                if isinstance(pools, list):
                    for i, pool in enumerate(pools):
                        if isinstance(pool, dict) and 'pool' in pool:
                            pool_ref = pool['pool']
                            if not isinstance(pool_ref, dict) or not pool_ref.get('name'):
                                raise XcValidationError(f"Pool reference {i} must include a name in {pool_type}")
                            
                            # Validate weight and priority if present
                            if 'weight' in pool and not isinstance(pool['weight'], int):
                                raise XcValidationError(f"Pool {i} weight must be an integer")
                            if 'priority' in pool and not isinstance(pool['priority'], int):
                                raise XcValidationError(f"Pool {i} priority must be an integer")
                        else:
                            raise XcValidationError(f"Pool {i} in {pool_type} must be a dictionary with 'pool' reference")

    def _validate_lb_algorithm_config(self):
        """Validate load balancing algorithm configuration."""
        return self._validate_lb_algorithm_config_raw(self.spec)
    
    def _validate_lb_algorithm_config_raw(self, spec):
        """Validate load balancing algorithm configuration using raw spec dict."""
        
        # Helper function to check if a value is effectively configured
        def _is_effectively_configured(value):
            """Check if a value is meaningfully configured (not None, empty dict, or empty list)."""
            if value is None:
                return False
            if isinstance(value, dict) and len(value) == 0:
                return False
            if isinstance(value, list) and len(value) == 0:
                return False
            # For dictionaries, check if all values are None/empty
            if isinstance(value, dict):
                return any(v is not None and v not in ({}, []) for v in value.values())
            return True
        
        lb_algorithms = ['least_active', 'random', 'ring_hash', 'round_robin']
        configured_algorithms = [a for a in lb_algorithms if a in spec and _is_effectively_configured(spec[a])]
        
        if len(configured_algorithms) > 1:
            raise XcValidationError("Cannot configure multiple load balancing algorithms simultaneously")
        
        # Validate ring hash specific configuration
        if 'ring_hash' in configured_algorithms:
            ring_hash_config = spec['ring_hash']
            if isinstance(ring_hash_config, dict) and 'hash_policy' in ring_hash_config:
                hash_policy = ring_hash_config['hash_policy']
                if not isinstance(hash_policy, list) or len(hash_policy) == 0:
                    raise XcValidationError("ring_hash.hash_policy must be a non-empty list")
                
                # Validate hash policy entries
                for i, policy in enumerate(hash_policy):
                    if not isinstance(policy, dict):
                        raise XcValidationError(f"Hash policy {i} must be a dictionary")
                    
                    # At least one hash source must be specified
                    hash_sources = ['header', 'cookie', 'source_ip', 'query_parameter']
                    if not any(source in policy for source in hash_sources):
                        raise XcValidationError(f"Hash policy {i} must specify at least one hash source: {', '.join(hash_sources)}")
                    
                    # Validate header hash configuration
                    if 'header' in policy:
                        header_config = policy['header']
                        if not isinstance(header_config, dict) or not header_config.get('name'):
                            raise XcValidationError(f"Hash policy {i}: header.name is required")
                    
                    # Validate cookie hash configuration
                    if 'cookie' in policy:
                        cookie_config = policy['cookie']
                        if not isinstance(cookie_config, dict) or not cookie_config.get('name'):
                            raise XcValidationError(f"Hash policy {i}: cookie.name is required")
                    
                    # Validate query parameter hash configuration
                    if 'query_parameter' in policy:
                        query_config = policy['query_parameter']
                        if not isinstance(query_config, dict) or not query_config.get('name'):
                            raise XcValidationError(f"Hash policy {i}: query_parameter.name is required")

    def _validate_user_identification_config_raw(self, spec):
        """Validate user identification configuration using raw spec dict."""
        
        # Helper function to check if a value is effectively configured
        def _is_effectively_configured(value):
            """Check if a value is meaningfully configured (not None, empty dict, or empty list)."""
            if value is None:
                return False
            if isinstance(value, dict) and len(value) == 0:
                return False
            if isinstance(value, list) and len(value) == 0:
                return False
            # For dictionaries, check if all values are None/empty
            if isinstance(value, dict):
                return any(v is not None and v not in ({}, []) for v in value.values())
            return True
        
        user_id_configs = ['user_identification', 'user_id_client_ip']
        configured_user_ids = [u for u in user_id_configs if u in spec and _is_effectively_configured(spec[u])]
        
        if len(configured_user_ids) > 1:
            raise XcValidationError("Cannot configure multiple user identification methods simultaneously")
        
        if 'user_identification' in configured_user_ids:
            user_id_config = spec['user_identification']
            if not isinstance(user_id_config, dict) or not user_id_config.get('name'):
                raise XcValidationError("user_identification.name is required when user_identification is specified")
            
            # Validate namespace and tenant references
            if 'namespace' in user_id_config and not user_id_config['namespace']:
                raise XcValidationError("user_identification.namespace cannot be empty")
            if 'tenant' in user_id_config and not user_id_config['tenant']:
                raise XcValidationError("user_identification.tenant cannot be empty")


class ModuleParameters(Parameters):
    @property
    def metadata(self):
        metadata = self._values.get('metadata', {})
        if not metadata:
            return None
        name = metadata.get('name')
        if name:
            metadata['name'] = sanitize_name(name)
        # Remove None values to prevent false diffs
        cleaned = {k: v for k, v in metadata.items() if v is not None}
        return cleaned

    @property
    def spec(self):
        """Return normalized & cached spec.

        Avoids infinite recursion by operating only on the raw stored spec.
        Returns None if no spec provided.
        """
        raw_spec = self._values.get('spec')
        if not raw_spec:
            return None

        # Return cached result if available
        if getattr(self, '_normalized_spec_cache', None) is not None:
            return self._normalized_spec_cache

        if getattr(self, '_normalizing_spec', False):
            # Re-entrancy guard – return raw spec rather than looping
            return raw_spec

        self._normalizing_spec = True
        try:
            normalized = self._validate_and_normalize_spec(raw_spec)
            normalized = self._prune_nulls(normalized)
            self._normalized_spec_cache = normalized
            return normalized
        except XcValidationError:
            raise
        except Exception as e:
            raise XcValidationError(f"Error processing spec configuration: {str(e)}")
        finally:
            self._normalizing_spec = False
    
    @property
    def state(self):
        return self._values.get('state', 'present')

    @property
    def wait_for_completion(self):
        return self._values.get('wait_for_completion', True)
    
    @property
    def timeout(self):
        return self._values.get('timeout', DEFAULT_TIMEOUT)

    def to_update(self):
        """Override to ensure spec normalization during updates."""
        result = super().to_update()
        
        # Ensure spec is normalized for API calls
        if 'spec' in result and result['spec']:
            normalized = self._validate_and_normalize_spec(self._values.get('spec'))
            # Prune None values deeply to avoid sending massive null-laden payload
            normalized = self._prune_nulls(normalized)
            result['spec'] = normalized
        
        return result

    def _prune_nulls(self, value):
        """Recursively remove keys with None values and empty containers.

        This reduces payload size and prevents server 500 errors caused by
        large objects filled with nulls.
        """
        if isinstance(value, dict):
            pruned = {}
            for k, v in value.items():
                if v is None:
                    continue
                cleaned = self._prune_nulls(v)
                # Skip empty dict/list after pruning
                if cleaned in (None, {}, []):
                    continue
                pruned[k] = cleaned
            return pruned
        if isinstance(value, list):
            cleaned_list = [self._prune_nulls(v) for v in value]
            cleaned_list = [v for v in cleaned_list if v not in (None, {}, [])]
            return cleaned_list
        return value


class ApiParameters(Parameters):
    @property
    def metadata(self):
        return self._values.get('metadata')

    @property
    def spec(self):
        return self._values.get('spec')
    
    @property
    def status(self):
        return self._values.get('status')
    
    @property
    def state(self):
        """Get the current state; fall back to EXISTS when status unsupported."""
        status_obj = self._values.get('status')
        if not status_obj:
            # Resource returned but no status structure; treat as ready
            return 'EXISTS'
        return safe_get(self._values, 'status', 'state', default='EXISTS')


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
        if not hasattr(self, '_changed_params'):
            self._changed_params = set()
        for param in self.updatables:
            want_value = getattr(want_params, param, None)
            have_value = getattr(have_params, param, None)
            if self._values_differ(want_value, have_value):
                self._changed_params.add(param)
                self._values[param] = want_value
    
    @property
    def changed_params(self):
        """Return list of parameters that have been changed."""
        return list(self._changed_params) if hasattr(self, '_changed_params') else []
    
    def has_changes(self):
        """Check if any changes have been made."""
        return len(self.changed_params) > 0
    
    def update_changed_params(self, want_params, have_params):
        """Compare want vs have and update changed parameters."""
        self._changed_params = set()
        
        for param in self.updatables:
            want_value = getattr(want_params, param, None)
            have_value = getattr(have_params, param, None)
            
            if self._values_differ(want_value, have_value):
                self._changed_params.add(param)
                setattr(self, param, want_value)
    
    def _values_differ(self, want_value, have_value, _depth=0, _seen=None):
        """Deep comparison of values to detect differences."""
        # Prevent infinite recursion
        if _depth > 50:  # Maximum recursion depth
            return want_value != have_value
        
        # Initialize seen objects tracker for circular reference detection
        if _seen is None:
            _seen = set()
        
        if want_value is None and have_value is None:
            return False
        
        if want_value is None or have_value is None:
            return True
        
        # For dictionaries, do deep comparison
        if isinstance(want_value, dict) and isinstance(have_value, dict):
            return self._dict_differ(want_value, have_value, _depth + 1, _seen)
        
        # For lists, compare contents
        elif isinstance(want_value, list) and isinstance(have_value, list):
            return self._list_differ(want_value, have_value, _depth + 1, _seen)
        
        # For simple values, direct comparison
        else:
            return want_value != have_value
    
    def _dict_differ(self, want_dict, have_dict, _depth=0, _seen=None):
        """Compare two dictionaries for differences."""
        # Prevent infinite recursion
        if _depth > 50:
            return want_dict != have_dict
        
        if _seen is None:
            _seen = set()
        
        # Check for circular references
        want_id = id(want_dict)
        have_id = id(have_dict)
        if want_id in _seen or have_id in _seen:
            return False  # Assume no difference for circular refs
        
        _seen.add(want_id)
        _seen.add(have_id)
        
        try:
            # Compare keys in want - detect missing keys as changes
            for key in want_dict.keys():
                if key not in have_dict:
                    # Treat missing have key as equal only if desired is empty dict
                    if want_dict[key] == {}:
                        continue
                    return True
                if self._values_differ(want_dict[key], have_dict[key], _depth + 1, _seen.copy()):
                    return True
            
            # Check for fields that should be removed (exist in have but not in want)
            # Only consider user-controllable fields, ignore system-generated ones
            user_controllable_fields = {
                'app_firewall', 'api_protection_rules', 'bot_defense', 'rate_limit', 
                'cors_policy', 'csrf_policy', 'jwt_validation', 'user_identification',
                'blocked_clients', 'trusted_clients', 'routes', 'domains', 'http', 'https',
                'default_route_pools', 'default_pool', 'default_pool_list'
            }
            
            for key in have_dict.keys():
                if key in user_controllable_fields and key not in want_dict:
                    # Field exists in current config but not in desired config - needs removal
                    # Only treat as change if the current value is not empty/default
                    if have_dict[key] not in [None, {}, []]:
                        return True
            
            return False
        finally:
            # Clean up seen objects
            _seen.discard(want_id)
            _seen.discard(have_id)
    
    def _list_differ(self, want_list, have_list, _depth=0, _seen=None):
        """Compare two lists for differences."""
        # Prevent infinite recursion
        if _depth > 50:
            return want_list != have_list
        
        if _seen is None:
            _seen = set()
        
        if len(want_list) != len(have_list):
            return True
        
        # For lists of dictionaries (common in our use case)
        if all(isinstance(item, dict) for item in want_list + have_list):
            # Sort both lists for comparison if they contain sortable dicts
            try:
                want_sorted = sorted(want_list, key=lambda x: str(sorted(x.items()))[:100])  # Limit key length
                have_sorted = sorted(have_list, key=lambda x: str(sorted(x.items()))[:100])
                
                for want_item, have_item in zip(want_sorted, have_sorted):
                    if self._dict_differ(want_item, have_item, _depth + 1, _seen.copy()):
                        return True
                return False
            except (TypeError, AttributeError, RecursionError):
                # Fall back to order-dependent comparison
                pass
        
        # Order-dependent comparison for other types
        for want_item, have_item in zip(want_list, have_list):
            if self._values_differ(want_item, have_item, _depth + 1, _seen.copy()):
                return True
        
        return False

    def to_return(self):
        result = {}
        try:
            for returnable in self.returnables:
                result[returnable] = getattr(self, returnable)
            result = self._filter_params(result)
        except Exception:
            raise
        return result

    def to_update(self):
        result = {}
        try:
            for updateable in self.updatables:
                result[updateable] = getattr(self, updateable)
            result = self._filter_params(result)
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
        
        # Validate parameters early
        try:
            self.want.validate_params()
        except XcValidationError as e:
            self.module.fail_json(msg=f"Parameter validation failed: {str(e)}")

    def _build_uri(self, operation='list'):
        """Build API URI for different operations."""
        namespace = self.want.metadata['namespace']
        name = self.want.metadata.get('name')
        
        base_uri = HTTP_LOADBALANCERS_ENDPOINT.format(namespace=namespace)
        
        if operation in ['get', 'put', 'delete'] and name:
            return f"{base_uri}/{name}"
        elif operation in ['list', 'create', 'post']:
            return base_uri
        return base_uri

    def _endpoint_candidates(self, namespace, name=None):
        # Only non-versioned path is authoritative per latest spec
        base_candidates = [
            f"/api/config/namespaces/{namespace}/http_loadbalancers"
        ]
        if name:
            return [f"{b}/{name}" for b in base_candidates]
        return base_candidates

    def _retry_endpoint_variants(self, method, uri, json=None):
        """On API group resolution 404, try alternative endpoint forms."""
        namespace = self.want.metadata['namespace']
        name = self.want.metadata.get('name')
        for candidate in self._endpoint_candidates(namespace, name if uri.endswith(name or '') else None):
            if candidate == uri:
                continue
            resp = getattr(self.client.api, method)(url=candidate, json=json) if json is not None else getattr(self.client.api, method)(url=candidate)
            if resp.status_code != 404:
                return resp
        return None

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
                    
                    # Look for field-specific errors
                    if isinstance(error_data.get('error'), dict):
                        error_details = error_data['error']
                        
                elif 'message' in error_data:
                    error_msg = f"{error_msg}: {error_data['message']}"
                    
                elif 'errors' in error_data and isinstance(error_data['errors'], list):
                    # Handle multiple validation errors
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
                
                # Provide helpful context for common error scenarios
                error_msg = self._enhance_error_message(error_msg, response.status, error_details)
                
            except (ValueError, KeyError, TypeError) as e:
                # Fallback to basic error message if JSON parsing fails
                error_msg = f"{error_msg}: HTTP {response.status_code}"
                if hasattr(response, 'text') and response.text:
                    error_msg = f"{error_msg} - {response.text[:200]}"
            
            raise XcApiError(error_msg, status_code=response.status_code, response=response)
        
        return normalize_response(response)

    def _enhance_error_message(self, base_message, status_code, error_details):
        """Enhance error messages with helpful context."""
        enhanced_message = base_message
        
        # Add context based on status code
        if status_code == 400:
            enhanced_message += " (Bad Request - Check configuration parameters)"
        elif status_code == 401:
            enhanced_message += " (Unauthorized - Check API credentials)"
        elif status_code == 403:
            enhanced_message += " (Forbidden - Check namespace permissions)"
        elif status_code == 404:
            enhanced_message += " (Not Found - Check resource name and namespace)"
        elif status_code == 409:
            enhanced_message += " (Conflict - Resource may already exist or have conflicting configuration)"
        elif status_code == 422:
            enhanced_message += " (Unprocessable Entity - Check configuration validity)"
        elif status_code >= 500:
            enhanced_message += " (Server Error - Try again later or contact support)"
        
        # Add specific guidance for common configuration errors
        if error_details:
            if any(key in str(error_details).lower() for key in ['domain', 'domains']):
                enhanced_message += "\nHint: Check domain format and DNS configuration"
            elif any(key in str(error_details).lower() for key in ['pool', 'origin']):
                enhanced_message += "\nHint: Verify origin pool exists and configuration is correct"
            elif any(key in str(error_details).lower() for key in ['certificate', 'tls', 'ssl']):
                enhanced_message += "\nHint: Check certificate configuration and TLS settings"
            elif any(key in str(error_details).lower() for key in ['policy', 'firewall', 'waf']):
                enhanced_message += "\nHint: Verify security policy references exist in the specified namespace"
        
        return enhanced_message

    def _wait_for_state(self, expected_state='ACTIVE', timeout=None):
        """Wait for load balancer to reach expected state."""
        if not self.want.wait_for_completion:
            return True
        
        timeout = timeout or self.want.timeout
        
        def check_state():
            if self.exists():
                current = self.have.state
                # If backend does not expose status, short-circuit success
                if current in ('EXISTS', 'UNKNOWN'):
                    return expected_state
                return current
            return 'NOT_FOUND'
        
        try:
            final_state = wait_for_state(
                check_state,
                expected_state,
                timeout=timeout,
                interval=10,
                log_func=self.module.warn
            )
            return final_state == expected_state
        except Exception as e:
            self.module.warn(f"State check failed: {str(e)}")
            return False

    def exec_module(self):
        """Main execution method."""
        changed = False
        result = dict()
        state = self.want.state

        try:
            if state == 'present':
                changed = self.present()
            elif state == 'absent':
                changed = self.absent()
            else:
                raise XcValidationError(f"Invalid state: {state}")

            # Return current state and changes
            if changed and self.changes.has_changes():
                # Include information about what changed
                result.update(self.changes.to_return())
                result.update(dict(
                    changed=changed,
                    changed_params=self.changes.changed_params
                ))
            else:
                # No changes made, return current state
                changes = self.have.to_return()
                result.update(**changes)
                result.update(dict(changed=changed))
            
        except XcApiError as e:
            # Enhanced API error handling
            error_msg = f"API Error: {str(e)}"
            
            # Add helpful troubleshooting information
            troubleshooting = self._get_troubleshooting_info(e)
            if troubleshooting:
                error_msg += f"\n\nTroubleshooting:\n{troubleshooting}"
            
            self.module.fail_json(msg=error_msg)
            
        except XcValidationError as e:
            # Enhanced validation error handling
            error_msg = f"Validation Error: {str(e)}"
            
            # Add configuration examples for common validation errors
            examples = self._get_configuration_examples(str(e))
            if examples:
                error_msg += f"\n\nExample Configuration:\n{examples}"
            
            self.module.fail_json(msg=error_msg)
            
        except Exception as e:
            # Enhanced general error handling
            error_msg = f"Unexpected error: {str(e)}"
            
            # Add debug information in case of unexpected errors
            debug_info = {
                'module_params': self.want._values if hasattr(self.want, '_values') else {},
                'current_state': getattr(self.have, 'state', 'UNKNOWN'),
                'operation': state
            }
            
            self.module.fail_json(msg=error_msg, debug_info=debug_info)
        
        return result

    def _get_troubleshooting_info(self, api_error):
        """Get troubleshooting information based on API error."""
        troubleshooting = []
        
        if hasattr(api_error, 'status_code'):
            status_code = api_error.status_code
            
            if status_code == 401:
                troubleshooting.append("- Verify your API token is valid and not expired")
                troubleshooting.append("- Check that your API credentials have proper permissions")
                
            elif status_code == 403:
                troubleshooting.append("- Verify you have access to the specified namespace")
                troubleshooting.append("- Check that your API token has the required permissions")
                troubleshooting.append("- Ensure the namespace exists and is accessible")
                
            elif status_code == 404:
                troubleshooting.append("- Verify the load balancer name and namespace are correct")
                troubleshooting.append("- Check that referenced resources (pools, policies) exist")
                troubleshooting.append("- Ensure the namespace exists")
                
            elif status_code == 409:
                troubleshooting.append("- Check if a load balancer with the same name already exists")
                troubleshooting.append("- Verify domain names are not in use by other load balancers")
                
            elif status_code == 422:
                troubleshooting.append("- Review configuration for invalid values or format")
                troubleshooting.append("- Check that referenced resources exist and are accessible")
                troubleshooting.append("- Verify mutually exclusive options are not both specified")
                
        return "\n".join(troubleshooting) if troubleshooting else ""

    def _get_configuration_examples(self, validation_error):
        """Get configuration examples based on validation error."""
        error_lower = validation_error.lower()
        
        if "domain" in error_lower:
            return '''domains:
  - "example.com"
  - "www.example.com"

Note: Domains must be valid FQDNs'''
        
        elif "pool" in error_lower:
            return '''default_route_pools:
  - pool:
      name: "my-pool"
      namespace: "default"
    weight: 1

Or for inline pool:
default_pool:
  origin_servers:
    - public_name:
                dns_name: "backend.example.com"'''
        elif "app_firewall" in error_lower or "waf" in error_lower:
                        return '''app_firewall:
    name: "my-waf-policy"
    namespace: "default"

Note: WAF policy must exist first'''
        
        return ""

    def present(self):
        """Ensure load balancer is present."""
        if self.exists():
            if self._needs_update():
                if self.module.check_mode:
                    # In check mode, populate changes for preview
                    self.changes.update_changed_params(self.want, self.have)
                    return True
                return self.update()
            return False
        else:
            if self.module.check_mode:
                # In check mode, show what would be created
                self.changes = Changes(params=self.want.to_update())
                for param in self.changes.updatables:
                    if hasattr(self.want, param) and getattr(self.want, param) is not None:
                        setattr(self.changes, param, getattr(self.want, param))
                        self.changes._changed_params.add(param)
                return True
            return self.create()

    def absent(self):
        """Ensure load balancer is absent."""
        if self.exists():
            if self.module.check_mode:
                # In check mode, show what would be removed
                self.changes = Changes(params=self.have.to_return())
                for param in self.changes.updatables:
                    if hasattr(self.have, param) and getattr(self.have, param) is not None:
                        setattr(self.changes, param, None)  # Will be removed
                        self.changes._changed_params.add(param)
                return True
            return self.remove()
        return False

    def _needs_update(self):
        """Check if update is needed by comparing current and desired state."""
        # Use the Changes class to detect differences
        self.changes.update_changed_params(self.want, self.have)
        return self.changes.has_changes()

    def _config_differs(self, config_key):
        """Compare a specific configuration section."""
        current_config = safe_get(self.have.spec, config_key)
        wanted_config = safe_get(self.want.spec, config_key)
        
        # Handle None/missing configurations
        if current_config is None and wanted_config is None:
            return False
        if current_config is None or wanted_config is None:
            return True
        
        # For simple comparisons
        if not isinstance(current_config, dict) or not isinstance(wanted_config, dict):
            return current_config != wanted_config
        
        # For complex nested configurations, do a deep comparison
        return self._deep_compare_config(current_config, wanted_config)

    def _deep_compare_config(self, current, wanted, _depth=0, _seen=None):
        """Perform deep comparison of configuration objects."""
        # Prevent infinite recursion
        if _depth > 50:
            return current != wanted
        
        # Initialize seen objects tracker for circular reference detection
        if _seen is None:
            _seen = set()
        
        if type(current) != type(wanted):
            return True
        
        if isinstance(current, dict):
            # Check for circular references
            current_id = id(current)
            wanted_id = id(wanted)
            if current_id in _seen or wanted_id in _seen:
                return False  # Assume no difference for circular refs
            
            _seen.add(current_id)
            _seen.add(wanted_id)
            
            try:
                # Check for different keys
                if set(current.keys()) != set(wanted.keys()):
                    return True
                
                # Recursively compare values
                for key in current.keys():
                    if self._deep_compare_config(current[key], wanted[key], _depth + 1, _seen.copy()):
                        return True
                return False
            finally:
                # Clean up seen objects
                _seen.discard(current_id)
                _seen.discard(wanted_id)
        
        elif isinstance(current, list):
            if len(current) != len(wanted):
                return True
            
            # Compare list elements (order matters for some configurations)
            for i, (curr_item, want_item) in enumerate(zip(current, wanted)):
                if self._deep_compare_config(curr_item, want_item, _depth + 1, _seen.copy() if _seen else None):
                    return True
            return False
        
        else:
            # Simple value comparison
            return current != wanted

    def remove(self):
        """Remove the load balancer."""
        try:
            uri = self._build_uri('delete')
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
        """Check if load balancer exists."""
        try:
            uri = self._build_uri('get')
            response = self.client.api.get(url=uri)
            
            if response.status_code == 404:
                return False
                
            response_data = self._handle_response(response, 'GET')
            
            if response_data.get('metadata'):
                self.have = ApiParameters(params=response_data)
                return True
                
            return False
            
        except XcApiError as e:
            if hasattr(e, 'status_code') and e.status_code == 404:
                return False
            raise

    def create(self):
        """Create new load balancer."""
        try:
            uri = self._build_uri('create')
            payload = self.want.to_update()
            # Rely on server to validate namespace existence per user instruction
            response = self.client.api.post(url=uri, json=payload)
            if response.status_code == 404:
                pass

            # Accept 200, 201, 202 as success (some operations may be async)
            if getattr(response, 'status', None) in [201, 202] and not response.ok:
                # Some intermediate responses might not set ok properly if body empty; mark as ok
                response.status_code = response.status  # ensure property present
            response_data = self._handle_response(response, 'CREATE')
            
            self.have = ApiParameters(params=response_data)
            
            # Wait for load balancer to become active
            if self.want.wait_for_completion:
                self._wait_for_state('ACTIVE')
            
            return True
            
        except XcApiError as e:
            # Provide extra context for 404 on create (often namespace or endpoint path)
            if hasattr(e, 'status_code') and e.status_code == 404:
                raise F5ModuleError(
                    f"Failed to create load balancer: Namespace '{self.want.metadata.get('namespace')}' or endpoint not found. Original error: {str(e)}"
                )
            raise F5ModuleError(f"Failed to create load balancer: {str(e)}")

    def update(self):
        """Update existing load balancer."""
        try:
            payload = self.want.to_update()
            
            uri = self._build_uri('put')
            response = self.client.api.put(url=uri, json=payload)
            if response.status_code == 404:
                pass
            response_data = self._handle_response(response, 'UPDATE')
            
            self.have = ApiParameters(params=response_data)
            
            # Wait for update to complete
            if self.want.wait_for_completion:
                self._wait_for_state('ACTIVE')
            
            return True
            
        except XcApiError as e:
            raise F5ModuleError(f"Failed to update load balancer: {str(e)}")


class ArgumentSpec(object):
    def __init__(self):
        self.supports_check_mode = True

        argument_spec = dict(
            state=dict(
                default='present',
                choices=['present', 'absent'],
                type='str'
            ),
            wait_for_completion=dict(
                type='bool',
                default=True
            ),
            timeout=dict(
                type='int',
                default=DEFAULT_TIMEOUT
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
                        required=True
                    ),
                    labels=dict(
                        type='dict'
                    ),
                    annotations=dict(
                        type='dict'
                    ),
                    description=dict(
                        type='str'
                    ),
                    disable=dict(
                        type='bool'
                    )
                )
            ),
            spec=dict(
                type='dict',
                options=dict(
                    domains=dict(
                        type='list',
                        elements='str',
                        required=True
                    ),
                    
                    # HTTP/HTTPS Configuration
                    http=dict(
                        type='dict',
                        options=dict(
                            dns_volterra_managed=dict(type='bool'),
                            port=dict(type='int', default=80),
                            port_ranges=dict(type='str')
                        )
                    ),
                    https=dict(
                        type='dict',
                        options=dict(
                            add_hsts=dict(type='bool'),
                            append_server_name=dict(type='str'),
                            connection_idle_timeout=dict(type='int'),
                            default_header=dict(type='dict'),
                            default_loadbalancer=dict(type='dict'),
                            disable_path_normalize=dict(type='dict'),
                            enable_path_normalize=dict(type='dict'),
                            http_redirect=dict(type='bool'),
                            non_default_loadbalancer=dict(type='dict'),
                            pass_through=dict(type='dict'),
                            port=dict(type='int', default=443),
                            port_ranges=dict(type='str'),
                            server_name=dict(type='str'),
                            tls_cert_params=dict(type='dict'),
                            tls_parameters=dict(type='dict')
                        )
                    ),
                    https_auto_cert=dict(
                        type='dict',
                        options=dict(
                            add_hsts=dict(type='bool'),
                            append_server_name=dict(type='str'),
                            connection_idle_timeout=dict(type='int'),
                            default_header=dict(type='dict'),
                            default_loadbalancer=dict(type='dict'),
                            disable_path_normalize=dict(type='dict'),
                            enable_path_normalize=dict(type='dict'),
                            http_redirect=dict(type='bool'),
                            no_mtls=dict(type='dict'),
                            non_default_loadbalancer=dict(type='dict'),
                            pass_through=dict(type='dict'),
                            port=dict(type='int', default=443),
                            port_ranges=dict(type='str'),
                            server_name=dict(type='str'),
                            tls_config=dict(type='dict'),
                            use_mtls=dict(type='dict')
                        )
                    ),
                    
                    # Pool Configuration
                    default_pool=dict(
                        type='dict',
                        options=dict(
                            advanced_options=dict(type='dict'),
                            automatic_port=dict(type='dict'),
                            endpoint_selection=dict(
                                type='str',
                                choices=['DISTRIBUTED', 'LOCAL_PREFERRED', 'ROUND_ROBIN']
                            ),
                            health_check_port=dict(type='int'),
                            healthcheck=dict(type='list'),
                            lb_port=dict(type='dict'),
                            loadbalancer_algorithm=dict(
                                type='str',
                                choices=['ROUND_ROBIN', 'LEAST_REQUEST', 'RING_HASH', 'RANDOM', 'MAGLEV']
                            ),
                            no_tls=dict(type='dict'),
                            origin_servers=dict(type='list'),
                            port=dict(type='int'),
                            same_as_endpoint_port=dict(type='dict'),
                            use_tls=dict(type='dict')
                        )
                    ),
                    default_pool_list=dict(
                        type='dict',
                        options=dict(
                            pools=dict(type='list')
                        )
                    ),
                    default_route_pools=dict(type='list'),
                    routes=dict(type='list'),
                    
                    # Load Balancing Algorithms
                    least_active=dict(type='dict'),
                    random=dict(type='dict'),
                    ring_hash=dict(
                        type='dict',
                        options=dict(
                            hash_policy=dict(type='list')
                        )
                    ),
                    round_robin=dict(type='dict'),
                    
                    # Stickiness
                    cookie_stickiness=dict(
                        type='dict',
                        options=dict(
                            add_httponly=dict(type='dict'),
                            add_secure=dict(type='dict'),
                            ignore_httponly=dict(type='dict'),
                            ignore_samesite=dict(type='dict'),
                            ignore_secure=dict(type='dict'),
                            name=dict(type='str'),
                            path=dict(type='str'),
                            samesite_lax=dict(type='dict'),
                            samesite_none=dict(type='dict'),
                            samesite_strict=dict(type='dict'),
                            ttl=dict(type='int')
                        )
                    ),
                    source_ip_stickiness=dict(type='dict'),
                    
                    # Security Features - WAF
                    app_firewall=dict(
                        type='dict',
                        options=dict(
                            name=dict(type='str', required=True),
                            namespace=dict(type='str'),
                            tenant=dict(type='str')
                        )
                    ),
                    disable_waf=dict(type='dict'),
                    
                    # Bot Protection & Challenges
                    bot_defense=dict(
                        type='dict',
                        options=dict(
                            disable_cors_support=dict(type='dict'),
                            enable_cors_support=dict(type='dict'),
                            policy=dict(type='dict'),
                            regional_endpoint=dict(
                                type='str',
                                choices=['AUTO', 'US', 'EU', 'ASIA']
                            ),
                            timeout=dict(type='int')
                        )
                    ),
                    bot_defense_advanced=dict(
                        type='dict',
                        options=dict(
                            disable_js_insert=dict(type='dict'),
                            disable_mobile_sdk=dict(type='dict'),
                            js_insert_all_pages=dict(
                                type='dict',
                                options=dict(
                                    javascript_location=dict(type='str', choices=['AFTER_HEAD'])
                                )
                            ),
                            js_insert_all_pages_except=dict(
                                type='dict',
                                options=dict(
                                    exclude_list=dict(type='list'),
                                    javascript_location=dict(type='str', choices=['AFTER_HEAD'])
                                )
                            ),
                            js_insertion_rules=dict(
                                type='dict',
                                options=dict(
                                    exclude_list=dict(type='list'),
                                    rules=dict(type='list')
                                )
                            ),
                            mobile=dict(
                                type='dict',
                                options=dict(
                                    name=dict(type='str'),
                                    namespace=dict(type='str'),
                                    tenant=dict(type='str')
                                )
                            ),
                            mobile_sdk_config=dict(
                                type='dict',
                                options=dict(
                                    mobile_identifier=dict(
                                        type='dict',
                                        options=dict(
                                            headers=dict(type='list')
                                        )
                                    )
                                )
                            ),
                            web=dict(
                                type='dict',
                                options=dict(
                                    name=dict(type='str'),
                                    namespace=dict(type='str'),
                                    tenant=dict(type='str')
                                )
                            )
                        )
                    ),
                    disable_bot_defense=dict(type='dict'),
                    
                    captcha_challenge=dict(
                        type='dict',
                        options=dict(
                            cookie_expiry=dict(type='int'),
                            custom_page=dict(type='str')
                        )
                    ),
                    js_challenge=dict(
                        type='dict',
                        options=dict(
                            cookie_expiry=dict(type='int'),
                            custom_page=dict(type='str'),
                            js_script_delay=dict(type='int')
                        )
                    ),
                    policy_based_challenge=dict(
                        type='dict',
                        options=dict(
                            always_enable_captcha_challenge=dict(type='dict'),
                            always_enable_js_challenge=dict(type='dict'),
                            captcha_challenge_parameters=dict(
                                type='dict',
                                options=dict(
                                    cookie_expiry=dict(type='int'),
                                    custom_page=dict(type='str')
                                )
                            ),
                            default_captcha_challenge_parameters=dict(type='dict'),
                            default_js_challenge_parameters=dict(type='dict'),
                            default_mitigation_settings=dict(type='dict'),
                            default_temporary_blocking_parameters=dict(type='dict'),
                            js_challenge_parameters=dict(
                                type='dict',
                                options=dict(
                                    cookie_expiry=dict(type='int'),
                                    custom_page=dict(type='str'),
                                    js_script_delay=dict(type='int')
                                )
                            ),
                            malicious_user_mitigation=dict(
                                type='dict',
                                options=dict(
                                    name=dict(type='str'),
                                    namespace=dict(type='str'),
                                    tenant=dict(type='str')
                                )
                            ),
                            no_challenge=dict(type='dict'),
                            rule_list=dict(
                                type='dict',
                                options=dict(
                                    rules=dict(type='list')
                                )
                            ),
                            temporary_user_blocking=dict(
                                type='dict',
                                options=dict(
                                    custom_page=dict(type='str')
                                )
                            )
                        )
                    ),
                    
                    # Rate Limiting
                    rate_limit=dict(
                        type='dict',
                        options=dict(
                            custom_ip_allowed_list=dict(type='dict'),
                            ip_allowed_list=dict(type='dict'),
                            no_ip_allowed_list=dict(type='dict'),
                            no_policies=dict(type='dict'),
                            policies=dict(type='dict'),
                            rate_limiter=dict(type='dict')
                        )
                    ),
                    disable_rate_limit=dict(type='dict'),
                    api_rate_limit=dict(
                        type='dict',
                        options=dict(
                            api_endpoint_rules=dict(type='list'),
                            bypass_rate_limiting_rules=dict(type='dict'),
                            custom_ip_allowed_list=dict(type='dict'),
                            ip_allowed_list=dict(type='dict'),
                            no_ip_allowed_list=dict(type='dict'),
                            server_url_rules=dict(type='list')
                        )
                    ),
                    
                    # Client Management
                    blocked_clients=dict(
                        type='list',
                        elements='dict',
                        options=dict(
                            actions=dict(type='list'),
                            as_number=dict(type='int'),
                            bot_skip_processing=dict(type='dict'),
                            expiration_timestamp=dict(type='str'),
                            http_header=dict(type='dict'),
                            ip_prefix=dict(type='str'),
                            ipv6_prefix=dict(type='str'),
                            metadata=dict(type='dict'),
                            skip_processing=dict(type='dict'),
                            user_identifier=dict(type='str'),
                            waf_skip_processing=dict(type='dict')
                        )
                    ),
                    trusted_clients=dict(
                        type='list',
                        elements='dict',
                        options=dict(
                            actions=dict(type='list'),
                            as_number=dict(type='int'),
                            bot_skip_processing=dict(type='dict'),
                            expiration_timestamp=dict(type='str'),
                            http_header=dict(type='dict'),
                            ip_prefix=dict(type='str'),
                            ipv6_prefix=dict(type='str'),
                            metadata=dict(type='dict'),
                            skip_processing=dict(type='dict'),
                            user_identifier=dict(type='str'),
                            waf_skip_processing=dict(type='dict')
                        )
                    ),
                    user_identification=dict(
                        type='dict',
                        options=dict(
                            name=dict(type='str', required=True),
                            namespace=dict(type='str'),
                            tenant=dict(type='str')
                        )
                    ),
                    user_id_client_ip=dict(type='dict'),
                    
                    # API Protection and Security
                    api_protection_rules=dict(
                        type='dict',
                        options=dict(
                            api_endpoint_rules=dict(type='list'),
                            api_groups_rules=dict(type='list')
                        )
                    ),
                    api_specification=dict(
                        type='dict',
                        options=dict(
                            api_definition=dict(type='dict'),
                            validation_all_spec_endpoints=dict(type='dict'),
                            validation_custom_list=dict(type='dict'),
                            validation_disabled=dict(type='dict')
                        )
                    ),
                    disable_api_definition=dict(type='dict'),
                    
                    # Discovery and Testing
                    enable_api_discovery=dict(
                        type='dict',
                        options=dict(
                            api_crawler=dict(type='dict'),
                            api_discovery_from_code_scan=dict(type='dict'),
                            custom_api_auth_discovery=dict(type='dict'),
                            default_api_auth_discovery=dict(type='dict'),
                            disable_learn_from_redirect_traffic=dict(type='dict'),
                            discovered_api_settings=dict(type='dict'),
                            enable_learn_from_redirect_traffic=dict(type='dict')
                        )
                    ),
                    disable_api_discovery=dict(type='dict'),
                    api_testing=dict(
                        type='dict',
                        options=dict(
                            custom_header_value=dict(type='str'),
                            domains=dict(type='list'),
                            every_day=dict(type='dict'),
                            every_month=dict(type='dict'),
                            every_week=dict(type='dict')
                        )
                    ),
                    disable_api_testing=dict(type='dict'),
                    
                    # Additional Security Features
                    cors_policy=dict(
                        type='dict',
                        options=dict(
                            allow_credentials=dict(type='bool'),
                            allow_headers=dict(type='str'),
                            allow_methods=dict(type='str'),
                            allow_origin=dict(type='list'),
                            allow_origin_regex=dict(type='list'),
                            disabled=dict(type='bool'),
                            expose_headers=dict(type='str'),
                            maximum_age=dict(type='int')
                        )
                    ),
                    csrf_policy=dict(
                        type='dict',
                        options=dict(
                            all_load_balancer_domains=dict(type='dict'),
                            custom_domain_list=dict(type='dict'),
                            disabled=dict(type='dict')
                        )
                    ),
                    
                    # Data Protection
                    data_guard_rules=dict(type='list'),
                    sensitive_data_disclosure_rules=dict(type='dict'),
                    sensitive_data_policy=dict(type='dict'),
                    default_sensitive_data_policy=dict(type='dict'),
                    
                    # DDoS Protection
                    ddos_mitigation_rules=dict(type='list'),
                    l7_ddos_action_block=dict(type='dict'),
                    l7_ddos_action_default=dict(type='dict'),
                    l7_ddos_action_js_challenge=dict(type='dict'),
                    l7_ddos_protection=dict(type='dict'),
                    slow_ddos_mitigation=dict(type='dict'),
                    
                    # IP Reputation and Threat Protection
                    enable_ip_reputation=dict(
                        type='dict',
                        options=dict(
                            ip_threat_categories=dict(type='list')
                        )
                    ),
                    disable_ip_reputation=dict(type='dict'),
                    enable_malicious_user_detection=dict(type='dict'),
                    disable_malicious_user_detection=dict(type='dict'),
                    enable_threat_mesh=dict(type='dict'),
                    disable_threat_mesh=dict(type='dict'),
                    
                    # Client-Side Defense
                    client_side_defense=dict(type='dict'),
                    disable_client_side_defense=dict(type='dict'),
                    
                    # Malware Protection
                    malware_protection_settings=dict(type='dict'),
                    disable_malware_protection=dict(type='dict'),
                    
                    # Caching
                    caching_policy=dict(
                        type='dict',
                        options=dict(
                            custom_cache_rule=dict(type='dict'),
                            default_cache_action=dict(type='dict')
                        )
                    ),
                    disable_caching=dict(type='dict'),
                    
                    # Service Policies
                    active_service_policies=dict(
                        type='dict',
                        options=dict(
                            policies=dict(type='list')
                        )
                    ),
                    no_service_policies=dict(type='dict'),
                    service_policies_from_namespace=dict(type='dict'),
                    
                    # Advertising and Location
                    advertise_custom=dict(type='dict'),
                    advertise_on_public=dict(type='dict'),
                    advertise_on_public_default_vip=dict(type='dict'),
                    do_not_advertise=dict(type='dict'),
                    add_location=dict(type='bool'),
                    
                    # Trust and Headers
                    enable_trust_client_ip_headers=dict(
                        type='dict',
                        options=dict(
                            client_ip_headers=dict(type='list')
                        )
                    ),
                    disable_trust_client_ip_headers=dict(type='dict'),
                    
                    # Application Types
                    single_lb_app=dict(type='dict'),
                    multi_lb_app=dict(type='dict'),
                    
                    # JWT Validation
                    jwt_validation=dict(
                        type='dict',
                        options=dict(
                            action=dict(type='dict'),
                            jwks_config=dict(type='dict'),
                            mandatory_claims=dict(type='dict'),
                            reserved_claims=dict(type='dict'),
                            target=dict(type='dict'),
                            token_location=dict(type='dict')
                        )
                    ),
                    
                    # GraphQL
                    graphql_rules=dict(type='list'),
                    
                    # Origin Server Management
                    origin_server_subset_rule_list=dict(type='dict'),
                    
                    # Cookie Protection
                    protected_cookies=dict(type='list'),
                    
                    # Advanced Options
                    more_option=dict(
                        type='dict',
                        options=dict(
                            buffer_policy=dict(type='dict'),
                            compression_params=dict(type='dict'),
                            custom_errors=dict(type='dict'),
                            disable_default_error_pages=dict(type='bool'),
                            disable_path_normalize=dict(type='dict'),
                            enable_path_normalize=dict(type='dict'),
                            idle_timeout=dict(type='int'),
                            max_request_header_size=dict(type='int'),
                            request_cookies_to_add=dict(type='list'),
                            request_cookies_to_remove=dict(type='list'),
                            request_headers_to_add=dict(type='list'),
                            request_headers_to_remove=dict(type='list'),
                            response_cookies_to_add=dict(type='list'),
                            response_cookies_to_remove=dict(type='list'),
                            response_headers_to_add=dict(type='list'),
                            response_headers_to_remove=dict(type='list')
                        )
                    ),
                    
                    # System Settings
                    system_default_timeouts=dict(type='dict')
                )
            )
        )
        
        self.argument_spec = {}
        self.argument_spec.update(f5_argument_spec)
        self.argument_spec.update(argument_spec)
        
        # Add mutual exclusions and required together
        self.mutually_exclusive = [
            # Protocol options
            ['http', 'https', 'https_auto_cert'],
            
            # Pool configuration
            ['default_pool', 'default_pool_list', 'default_route_pools'],
            
            # Load balancing algorithms
            ['least_active', 'random', 'ring_hash', 'round_robin'],
            
            # Stickiness options
            ['cookie_stickiness', 'source_ip_stickiness'],
            
            # Security features
            ['app_firewall', 'disable_waf'],
            ['enable_ip_reputation', 'disable_ip_reputation'],
            ['enable_malicious_user_detection', 'disable_malicious_user_detection'],
            ['enable_threat_mesh', 'disable_threat_mesh'],
            ['enable_trust_client_ip_headers', 'disable_trust_client_ip_headers'],
            ['client_side_defense', 'disable_client_side_defense'],
            ['disable_malware_protection', 'malware_protection_settings'],
            
            # Rate limiting
            ['rate_limit', 'disable_rate_limit'],
            
            # Bot defense
            ['bot_defense', 'bot_defense_advanced', 'disable_bot_defense'],
            
            # Challenge types
            ['captcha_challenge', 'js_challenge', 'no_challenge', 'enable_challenge', 'policy_based_challenge'],
            
            # Session stickiness
            ['cookie_stickiness', 'source_ip_stickiness'],
            
            # DDoS actions
            ['l7_ddos_action_block', 'l7_ddos_action_default', 'l7_ddos_action_js_challenge'],
            
            # API features
            ['enable_api_discovery', 'disable_api_discovery'],
            ['api_testing', 'disable_api_testing'],
            ['disable_api_definition', 'api_specification'],
            
            # Caching
            ['caching_policy', 'disable_caching'],
            
            # Service policies
            ['active_service_policies', 'no_service_policies', 'service_policies_from_namespace'],
            
            # Advertising options
            ['advertise_custom', 'advertise_on_public', 'advertise_on_public_default_vip', 'do_not_advertise'],
            
            # Application types
            ['single_lb_app', 'multi_lb_app'],
            
            # User identification
            ['user_identification', 'user_id_client_ip'],
            
            # Data protection
            ['sensitive_data_policy', 'default_sensitive_data_policy']
        ]
        
        self.required_together = [
            ['metadata', 'spec']
        ]


def main():
    """Main entry point for the module."""
    spec = ArgumentSpec()

    module = AnsibleModule(
        argument_spec=spec.argument_spec,
        supports_check_mode=spec.supports_check_mode,
        mutually_exclusive=getattr(spec, 'mutually_exclusive', []),
        required_together=getattr(spec, 'required_together', [])
    )
    
    try:
        # Initialize module manager and execute
        mm = ModuleManager(module=module)
        results = mm.exec_module()
        module.exit_json(**results)
        
    except F5ModuleError as ex:
        module.fail_json(msg=f"Module execution failed: {str(ex)}")
    except XcApiError as ex:
        module.fail_json(msg=f"API error: {str(ex)}")
    except XcValidationError as ex:
        module.fail_json(msg=f"Validation error: {str(ex)}")
    except Exception as ex:
        module.fail_json(msg=f"Unexpected error: {str(ex)}")


if __name__ == '__main__':
    main()
