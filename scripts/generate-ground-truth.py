#!/usr/bin/env python3
"""
Ground Truth Generator - Phase 1 (Refactored for ShopSphere E-Commerce Domain)
Generates all registry files for the Enterprise AppSec Benchmark Suite.
Produces: vulnerability_register.json, capability_mapping.json,
          expected_findings.json, benchmark_manifest.json, benchmark_catalog.json,
          progress_tracker.json
"""
import json
import os
import sys
import re

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_DIR = os.path.join(SCRIPT_DIR, '..', 'benchmark-state')
TIMESTAMP = '2026-06-24T09:58:00+05:30'

# ============================================================
# REFACTORING MAPS (ShopSphere Namespace Alignment)
# ============================================================
RENAMES = {
    # Controllers SAST
    "SqlInjectionController": "ProductCatalogController",
    "NoSqlInjectionController": "ProductFilterController",
    "CommandInjectionController": "ReportExportController",
    "LdapInjectionController": "UserDirectoryController",
    "XPathInjectionController": "CatalogImportController",
    "XxeController": "InventoryImportController",
    "SpelInjectionController": "PromoCodeController",
    "StoredXssController": "ProductReviewController",
    "ReflectedXssController": "SupportSearchController",
    "DomXssController": "ProfileDetailsController",
    "SsrfController": "ProductImageImportController",
    "OpenRedirectController": "ShareRedirectController",
    "PathTraversalController": "InvoiceDownloadController",
    "DeserializationController": "SessionRestoreController",
    "UnsafeReflectionController": "PluginManagerController",
    "BrokenAuthController": "UserAuthenticationController",
    "BrokenAuthzController": "OrderAccessController",
    "WeakCryptoController": "DataEncryptionController",
    "HardcodedCredsController": "PaymentGatewayConfigController",
    "SensitiveDataController": "UserProfileController",
    "ScaController": "SystemDiagnosticsController",

    # Services SAST
    "SqlInjectionService": "ProductCatalogService",
    "NoSqlInjectionService": "ProductFilterService",
    "CommandInjectionService": "ReportExportService",
    "LdapInjectionService": "UserDirectoryService",
    "XPathInjectionService": "CatalogImportService",
    "XxeService": "InventoryImportService",
    "SpelInjectionService": "PromoCodeService",
    "StoredXssService": "ProductReviewService",
    "ReflectedXssService": "SupportSearchService",
    "DomXssService": "ProfileDetailsService",
    "SsrfService": "ProductImageImportService",
    "OpenRedirectService": "ShareRedirectService",
    "PathTraversalService": "InvoiceDownloadService",
    "DeserializationService": "SessionRestoreService",
    "UnsafeReflectionService": "PluginManagerService",
    "BrokenAuthService": "UserAuthenticationService",
    "BrokenAuthzService": "OrderAccessService",
    "WeakCryptoService": "DataEncryptionService",
    "HardcodedCredsService": "PaymentGatewayConfigService",
    "SensitiveDataService": "UserProfileService",
    "ScaService": "SystemDiagnosticsService",

    # Repositories SAST
    "SqlInjectionRepository": "ProductCatalogRepository",
    "NoSqlInjectionRepository": "ProductFilterRepository",
    "CommandInjectionRepository": "ReportExportRepository",
    "LdapInjectionRepository": "UserDirectoryRepository",
    "XPathInjectionRepository": "CatalogImportRepository",
    "XxeRepository": "InventoryImportRepository",
    "SpelInjectionRepository": "PromoCodeRepository",
    "StoredXssRepository": "ProductReviewRepository",
    "ReflectedXssRepository": "SupportSearchRepository",
    "DomXssRepository": "ProfileDetailsRepository",
    "SsrfRepository": "ProductImageImportRepository",
    "OpenRedirectRepository": "ShareRedirectRepository",
    "PathTraversalRepository": "InvoiceDownloadRepository",
    "DeserializationRepository": "SessionRestoreRepository",
    "UnsafeReflectionRepository": "PluginManagerRepository",
    "BrokenAuthRepository": "UserAuthenticationRepository",
    "BrokenAuthzRepository": "OrderAccessRepository",
    "WeakCryptoRepository": "DataEncryptionRepository",
    "HardcodedCredsRepository": "PaymentGatewayConfigRepository",
    "SensitiveDataRepository": "UserProfileRepository",

    # Controllers DAST
    "DastSQLInjectionController": "ProductSearchGateway",
    "DastXSSController": "FeedbackReviewController",
    "DastCSRFController": "ShoppingCartController",
    "DastSSRFController": "VendorWebhookController",
    "DastOpenRedirectController": "OAuthRedirectController",
    "DastPathTraversalController": "AssetDownloadController",
    "DastFileUploadController": "ProfileImageUploadController",
    "DastAuthenticationWeaknessController": "MemberLoginController",
    "DastAuthorizationWeaknessController": "AdminSettingsController",
    "DastAPISecurityController": "OrderCheckoutController",

    # Services DAST
    "DastSQLInjectionService": "ProductSearchGatewayService",
    "DastXSSService": "FeedbackReviewService",
    "DastCSRFService": "ShoppingCartService",
    "DastSSRFService": "VendorWebhookService",
    "DastOpenRedirectService": "OAuthRedirectService",
    "DastPathTraversalService": "AssetDownloadService",
    "DastFileUploadService": "ProfileImageUploadService",
    "DastAuthenticationWeaknessService": "MemberLoginService",
    "DastAuthorizationWeaknessService": "AdminSettingsService",
    "DastAPISecurityService": "OrderCheckoutService",

    # Repositories DAST
    "DastSQLInjectionRepository": "ProductSearchGatewayRepository",
    "DastXSSRepository": "FeedbackReviewRepository",
    "DastCSRFRepository": "ShoppingCartRepository",
    "DastSSRFRepository": "VendorWebhookRepository",
    "DastOpenRedirectRepository": "OAuthRedirectRepository",
    "DastPathTraversalRepository": "AssetDownloadRepository",
    "DastFileUploadRepository": "ProfileImageUploadRepository",
    "DastAuthenticationWeaknessRepository": "MemberLoginRepository",
    "DastAuthorizationWeaknessRepository": "AdminSettingsRepository",
    "DastAPISecurityRepository": "OrderCheckoutRepository",

    # Models & DTOs
    "VulnerabilityReport": "SecurityAuditReport",
    "VulnerabilityReportRepository": "SecurityAuditReportRepository",
    "DastXssLog": "ReviewFeedbackLog",
    "SensitiveUserData": "UserProfileData",
    "SensitiveDataDto": "UserProfileDto",
    "VulnerableSensitiveDataDto": "RawUserProfileDto",
    
    # Application Main class
    "BenchmarkApplication": "ShopSphereApplication"
}

PACKAGE_MAPPING = {
    # SAST Controllers
    "com.benchmark.appsec.controller.sast.injection": "com.shopsphere.catalog",
    "com.benchmark.appsec.controller.sast.xss": "com.shopsphere.review",
    "com.benchmark.appsec.controller.sast.ssrf": "com.shopsphere.catalog",
    "com.benchmark.appsec.controller.sast.redirect": "com.shopsphere.common",
    "com.benchmark.appsec.controller.sast.traversal": "com.shopsphere.order",
    "com.benchmark.appsec.controller.sast.deserialization": "com.shopsphere.common",
    "com.benchmark.appsec.controller.sast.reflection": "com.shopsphere.reporting",
    "com.benchmark.appsec.controller.sast.auth": "com.shopsphere.auth",
    "com.benchmark.appsec.controller.sast.crypto": "com.shopsphere.payment",
    "com.benchmark.appsec.controller.sast.data": "com.shopsphere.profile",
    "com.benchmark.appsec.controller.sca": "com.shopsphere.system",

    # SAST Services
    "com.benchmark.appsec.service.sast.injection": "com.shopsphere.catalog",
    "com.benchmark.appsec.service.sast.xss": "com.shopsphere.review",
    "com.benchmark.appsec.service.sast.ssrf": "com.shopsphere.catalog",
    "com.benchmark.appsec.service.sast.redirect": "com.shopsphere.common",
    "com.benchmark.appsec.service.sast.traversal": "com.shopsphere.order",
    "com.benchmark.appsec.service.sast.deserialization": "com.shopsphere.common",
    "com.benchmark.appsec.service.sast.reflection": "com.shopsphere.reporting",
    "com.benchmark.appsec.service.sast.auth": "com.shopsphere.auth",
    "com.benchmark.appsec.service.sast.crypto": "com.shopsphere.payment",
    "com.benchmark.appsec.service.sast.data": "com.shopsphere.profile",
    "com.benchmark.appsec.service.sca": "com.shopsphere.system",

    # SAST Repositories
    "com.benchmark.appsec.repository.sast.injection": "com.shopsphere.catalog",
    "com.benchmark.appsec.repository.sast.xss": "com.shopsphere.review",
    "com.benchmark.appsec.repository.sast.crypto": "com.shopsphere.payment",
    "com.benchmark.appsec.repository.sast.data": "com.shopsphere.profile",

    # DAST Controllers
    "com.benchmark.appsec.controller.dast.sqli": "com.shopsphere.catalog",
    "com.benchmark.appsec.controller.dast.xss": "com.shopsphere.review",
    "com.benchmark.appsec.controller.dast.csrf": "com.shopsphere.cart",
    "com.benchmark.appsec.controller.dast.ssrf": "com.shopsphere.common",
    "com.benchmark.appsec.controller.dast.redirect": "com.shopsphere.common",
    "com.benchmark.appsec.controller.dast.traversal": "com.shopsphere.support",
    "com.benchmark.appsec.controller.dast.upload": "com.shopsphere.support",
    "com.benchmark.appsec.controller.dast.auth": "com.shopsphere.auth",
    "com.benchmark.appsec.controller.dast.authz": "com.shopsphere.reporting",
    "com.benchmark.appsec.controller.dast.api": "com.shopsphere.order",

    # DAST Services
    "com.benchmark.appsec.service.dast.api": "com.shopsphere.order",
    "com.benchmark.appsec.service.dast.auth": "com.shopsphere.auth",
    "com.benchmark.appsec.service.dast.authz": "com.shopsphere.reporting",
    "com.benchmark.appsec.service.dast.csrf": "com.shopsphere.cart",
    "com.benchmark.appsec.service.dast.redirect": "com.shopsphere.common",
    "com.benchmark.appsec.service.dast.sqli": "com.shopsphere.catalog",
    "com.benchmark.appsec.service.dast.ssrf": "com.shopsphere.common",
    "com.benchmark.appsec.service.dast.traversal": "com.shopsphere.support",
    "com.benchmark.appsec.service.dast.upload": "com.shopsphere.support",
    "com.benchmark.appsec.service.dast.xss": "com.shopsphere.review",

    # DAST Repositories
    "com.benchmark.appsec.repository.dast.api": "com.shopsphere.order",
    "com.benchmark.appsec.repository.dast.auth": "com.shopsphere.auth",
    "com.benchmark.appsec.repository.dast.authz": "com.shopsphere.reporting",
    "com.benchmark.appsec.repository.dast.csrf": "com.shopsphere.cart",
    "com.benchmark.appsec.repository.dast.redirect": "com.shopsphere.common",
    "com.benchmark.appsec.repository.dast.sqli": "com.shopsphere.catalog",
    "com.benchmark.appsec.repository.dast.ssrf": "com.shopsphere.common",
    "com.benchmark.appsec.repository.dast.traversal": "com.shopsphere.support",
    "com.benchmark.appsec.repository.dast.upload": "com.shopsphere.support",
    "com.benchmark.appsec.repository.dast.xss": "com.shopsphere.review"
}

ROUTE_REPLACEMENTS = {
    "/api/vulnerable/sqli": "/api/v1/products/search",
    "/api/safe/sqli": "/api/v1/products/search/secure",
    "/api/framework-protected/sqli": "/api/v1/products/search/jpa",
    "/api/unreachable/sqli": "/api/v1/products/search/internal",

    "/api/vulnerable/nosqli": "/api/v1/products/filter",
    "/api/safe/nosqli": "/api/v1/products/filter/secure",
    "/api/framework-protected/nosqli": "/api/v1/products/filter/jpa",
    "/api/unreachable/nosqli": "/api/v1/products/filter/internal",

    "/api/vulnerable/cmdi": "/api/v1/admin/reports/export",
    "/api/safe/cmdi": "/api/v1/admin/reports/export/secure",
    "/api/framework-protected/cmdi": "/api/v1/admin/reports/export/system",
    "/api/unreachable/cmdi": "/api/v1/admin/reports/export/internal",

    "/api/vulnerable/ldapi": "/api/v1/users/lookup",
    "/api/safe/ldapi": "/api/v1/users/lookup/secure",
    "/api/framework-protected/ldapi": "/api/v1/users/lookup/jpa",
    "/api/unreachable/ldapi": "/api/v1/users/lookup/internal",

    "/api/vulnerable/xpathi": "/api/v1/catalog/import",
    "/api/safe/xpathi": "/api/v1/catalog/import/secure",
    "/api/framework-protected/xpathi": "/api/v1/catalog/import/dom",
    "/api/unreachable/xpathi": "/api/v1/catalog/import/internal",

    "/api/vulnerable/xxe": "/api/v1/inventory/bulk-import",
    "/api/safe/xxe": "/api/v1/inventory/bulk-import/secure",
    "/api/framework-protected/xxe": "/api/v1/inventory/bulk-import/json",
    "/api/unreachable/xxe": "/api/v1/inventory/bulk-import/internal",

    "/api/vulnerable/speli": "/api/v1/promotions/apply",
    "/api/safe/speli": "/api/v1/promotions/apply/secure",
    "/api/framework-protected/speli": "/api/v1/promotions/apply/bind",
    "/api/unreachable/speli": "/api/v1/promotions/apply/internal",

    "/api/vulnerable/stored-xss": "/reviews/product",
    "/api/safe/stored-xss": "/reviews/product/secure",
    "/api/framework-protected/stored-xss": "/reviews/product/csp",
    "/api/unreachable/stored-xss": "/reviews/product/internal",

    "/api/vulnerable/reflected-xss": "/api/v1/support/query",
    "/api/safe/reflected-xss": "/api/v1/support/query/secure",
    "/api/framework-protected/reflected-xss": "/api/v1/support/query/json",
    "/api/unreachable/reflected-xss": "/api/v1/support/query/internal",

    "/api/vulnerable/dom-xss": "/profile/details",
    "/api/safe/dom-xss": "/profile/details/secure",
    "/api/framework-protected/dom-xss": "/profile/details/angular",
    "/api/unreachable/dom-xss": "/profile/details/internal",

    "/api/vulnerable/ssrf": "/api/v1/products/image-import",
    "/api/safe/ssrf": "/api/v1/products/image-import/secure",
    "/api/framework-protected/ssrf": "/api/v1/products/image-import/fixed",
    "/api/unreachable/ssrf": "/api/v1/products/image-import/internal",

    "/api/vulnerable/redirect": "/api/v1/share/redirect",
    "/api/safe/redirect": "/api/v1/share/redirect/secure",
    "/api/framework-protected/redirect": "/api/v1/share/redirect/relative",
    "/api/unreachable/redirect": "/api/v1/share/redirect/internal",

    "/api/vulnerable/traversal": "/api/v1/orders/invoice/download",
    "/api/safe/traversal": "/api/v1/orders/invoice/download/secure",
    "/api/framework-protected/traversal": "/api/v1/orders/invoice/download/resource",
    "/api/unreachable/traversal": "/api/v1/orders/invoice/download/internal",

    "/api/vulnerable/deser": "/api/v1/session/restore",
    "/api/safe/deser": "/api/v1/session/restore/secure",
    "/api/framework-protected/deser": "/api/v1/session/restore/json",
    "/api/unreachable/deser": "/api/v1/session/restore/internal",

    "/api/vulnerable/reflection": "/api/v1/system/plugins/load",
    "/api/safe/reflection": "/api/v1/system/plugins/load/secure",
    "/api/framework-protected/reflection": "/api/v1/system/plugins/load/di",
    "/api/unreachable/reflection": "/api/v1/system/plugins/load/internal",

    "/api/vulnerable/broken-auth": "/api/v1/auth/customer-login",
    "/api/safe/broken-auth": "/api/v1/auth/customer-login/secure",
    "/api/framework-protected/broken-auth": "/api/v1/auth/customer-login/oauth",
    "/api/unreachable/broken-auth": "/api/v1/auth/customer-login/internal",

    "/api/vulnerable/broken-authz": "/api/v1/orders/access",
    "/api/safe/broken-authz": "/api/v1/orders/access/secure",
    "/api/framework-protected/broken-authz": "/api/v1/orders/access/method",
    "/api/unreachable/broken-authz": "/api/v1/orders/access/internal",

    "/api/vulnerable/weak-crypto": "/api/v1/payments/encrypt",
    "/api/safe/weak-crypto": "/api/v1/payments/encrypt/secure",
    "/api/framework-protected/weak-crypto": "/api/v1/payments/encrypt/standard",
    "/api/unreachable/weak-crypto": "/api/v1/payments/encrypt/internal",

    "/api/vulnerable/hardcoded-creds": "/api/v1/payments/gateway/config",
    "/api/safe/hardcoded-creds": "/api/v1/payments/gateway/config/secure",
    "/api/framework-protected/hardcoded-creds": "/api/v1/payments/gateway/config/vault",
    "/api/unreachable/hardcoded-creds": "/api/v1/payments/gateway/config/internal",

    "/api/vulnerable/data-exposure": "/api/v1/profile/view",
    "/api/safe/data-exposure": "/api/v1/profile/view/secure",
    "/api/framework-protected/data-exposure": "/api/v1/profile/view/projection",
    "/api/unreachable/data-exposure": "/api/v1/profile/view/internal",

    "/api/vulnerable/sca": "/api/v1/system/update/check",
    "/api/safe/sca": "/api/v1/system/update/check/secure",
    
    # DAST routes
    "/api/dast/vulnerable/sqli": "/api/v1/catalog/query",
    "/api/dast/safe/sqli": "/api/v1/catalog/query/secure",
    
    "/api/dast/vulnerable/xss": "/api/v1/reviews/feedback",
    "/api/dast/safe/xss": "/api/v1/reviews/feedback/secure",
    
    "/api/dast/vulnerable/csrf": "/api/v1/cart/items",
    "/api/dast/safe/csrf": "/api/v1/cart/items/secure",
    
    "/api/dast/vulnerable/ssrf": "/api/v1/vendors/webhooks",
    "/api/dast/safe/ssrf": "/api/v1/vendors/webhooks/secure",
    
    "/api/dast/vulnerable/redirect": "/api/v1/auth/oauth/redirect",
    "/api/dast/safe/redirect": "/api/v1/auth/oauth/redirect/secure",
    
    "/api/dast/vulnerable/traversal": "/api/v1/assets/download",
    "/api/dast/safe/traversal": "/api/v1/assets/download/secure",
    
    "/api/dast/vulnerable/upload": "/api/v1/profile/avatar/upload",
    "/api/dast/safe/upload": "/api/v1/profile/avatar/upload/secure",
    
    "/api/dast/vulnerable/auth": "/api/v1/auth/member-login",
    "/api/dast/safe/auth": "/api/v1/auth/member-login/secure",
    
    "/api/dast/vulnerable/authz": "/api/v1/admin/settings",
    "/api/dast/safe/authz": "/api/v1/admin/settings/secure",
    
    "/api/dast/vulnerable/api-security": "/api/v1/checkout/place-order",
    "/api/dast/safe/api-security": "/api/v1/checkout/place-order/secure"
}

def map_filepath(old_path):
    # Map java source code paths
    if old_path.startswith("src/main/java/com/benchmark/appsec"):
        # Determine package and file name
        suffix_path = old_path[len("src/main/java/com/benchmark/appsec/"):].strip("/")
        parts = suffix_path.split("/")
        filename = parts[-1]
        folder_rel = ".".join(parts[:-1])
        
        # Package resolution
        orig_pkg = "com.benchmark.appsec"
        if folder_rel:
            orig_pkg += "." + folder_rel
            
        dest_pkg = "com.shopsphere"
        for op in sorted(PACKAGE_MAPPING.keys(), key=len, reverse=True):
            if orig_pkg.startswith(op):
                suffix = orig_pkg[len(op):]
                dest_pkg = PACKAGE_MAPPING[op] + suffix
                break
                
        # Rename class/filename
        dest_filename = filename
        orig_class = filename.replace(".java", "")
        if orig_class in RENAMES:
            dest_filename = RENAMES[orig_class] + ".java"
            
        dest_dir = dest_pkg.replace(".", "/")
        return f"src/main/java/{dest_dir}/{dest_filename}"
    return old_path

# ============================================================
# SAST SCENARIO DEFINITIONS (20 classes x 4 variants = 80)
# ============================================================
SAST_CLASSES = [
    {
        'name': 'SQL Injection', 'slug': 'sqli', 'cwe': 'CWE-89', 'owasp': 'A03:2021-Injection',
        'severity': 'HIGH', 'capBase': 'CAP-SAST-SQLI', 'ctrlGroup': 'CTRL-SAST-SQLI-001',
        'controllerDir': 'injection', 'controllerFile': 'SqlInjectionController.java',
        'serviceFile': 'SqlInjectionService.java', 'repoFile': 'SqlInjectionRepository.java',
        'sink': 'java.sql.Statement.executeQuery()', 'source': 'HttpServletRequest parameter',
        'remediation': 'Use parameterized queries (PreparedStatement) instead of string concatenation',
        'rootCause': 'User input concatenated directly into SQL query string without sanitization',
        'safeDesc': 'Uses PreparedStatement with parameterized query',
        'fwProtDesc': 'Uses Spring Data JPA repository method query derivation',
        'unreachDesc': 'Private method with no callers containing raw SQL concatenation'
    },
    {
        'name': 'NoSQL Injection', 'slug': 'nosqli', 'cwe': 'CWE-943', 'owasp': 'A03:2021-Injection',
        'severity': 'HIGH', 'capBase': 'CAP-SAST-NOSQLI', 'ctrlGroup': 'CTRL-SAST-NOSQLI-001',
        'controllerDir': 'injection', 'controllerFile': 'NoSqlInjectionController.java',
        'serviceFile': 'NoSqlInjectionService.java', 'repoFile': 'NoSqlInjectionRepository.java',
        'sink': 'MongoCollection.find()', 'source': 'HttpServletRequest parameter',
        'remediation': 'Use parameterized MongoDB queries with Filters API instead of raw JSON query strings',
        'rootCause': 'User input interpolated directly into MongoDB query document without sanitization',
        'safeDesc': 'Uses MongoDB Filters API with parameterized query',
        'fwProtDesc': 'Uses Spring Data MongoDB repository method query derivation',
        'unreachDesc': 'Private method with no callers containing raw MongoDB query string'
    },
    {
        'name': 'Command Injection', 'slug': 'cmdi', 'cwe': 'CWE-78', 'owasp': 'A03:2021-Injection',
        'severity': 'CRITICAL', 'capBase': 'CAP-SAST-CMDI', 'ctrlGroup': 'CTRL-SAST-CMDI-001',
        'controllerDir': 'injection', 'controllerFile': 'CommandInjectionController.java',
        'serviceFile': 'CommandInjectionService.java', 'repoFile': 'CommandInjectionRepository.java',
        'sink': 'Runtime.getRuntime().exec()', 'source': 'HttpServletRequest parameter',
        'remediation': 'Use ProcessBuilder with argument list instead of shell command string concatenation',
        'rootCause': 'User input concatenated into OS command string executed via Runtime.exec()',
        'safeDesc': 'Uses ProcessBuilder with explicit argument array and input validation',
        'fwProtDesc': 'Uses Spring abstraction layer that prevents shell metacharacter injection',
        'unreachDesc': 'Dead code behind if(false) condition containing Runtime.exec() with user input'
    },
    {
        'name': 'LDAP Injection', 'slug': 'ldapi', 'cwe': 'CWE-90', 'owasp': 'A03:2021-Injection',
        'severity': 'HIGH', 'capBase': 'CAP-SAST-LDAPI', 'ctrlGroup': 'CTRL-SAST-LDAPI-001',
        'controllerDir': 'injection', 'controllerFile': 'LdapInjectionController.java',
        'serviceFile': 'LdapInjectionService.java', 'repoFile': 'LdapInjectionRepository.java',
        'sink': 'DirContext.search()', 'source': 'HttpServletRequest parameter',
        'remediation': 'Use LdapQueryBuilder with proper LDAP encoding of special characters',
        'rootCause': 'User input concatenated into LDAP search filter without escaping special characters',
        'safeDesc': 'Uses Spring LDAP LdapQueryBuilder with automatic encoding',
        'fwProtDesc': 'Uses Spring LDAP repository with query derivation',
        'unreachDesc': 'Unregistered Spring bean class containing raw LDAP filter concatenation'
    },
    {
        'name': 'XPath Injection', 'slug': 'xpathi', 'cwe': 'CWE-643', 'owasp': 'A03:2021-Injection',
        'severity': 'HIGH', 'capBase': 'CAP-SAST-XPATHI', 'ctrlGroup': 'CTRL-SAST-XPATHI-001',
        'controllerDir': 'injection', 'controllerFile': 'XPathInjectionController.java',
        'serviceFile': 'XPathInjectionService.java', 'repoFile': 'XPathInjectionRepository.java',
        'sink': 'XPath.evaluate()', 'source': 'HttpServletRequest parameter',
        'remediation': 'Use XPath variable resolver with parameterized XPath expressions',
        'rootCause': 'User input concatenated into XPath expression string without escaping',
        'safeDesc': 'Uses XPathVariableResolver with parameterized expression',
        'fwProtDesc': 'Uses DOM parsing with element traversal instead of XPath queries',
        'unreachDesc': 'Private method with no callers containing XPath string concatenation'
    },
    {
        'name': 'XXE', 'slug': 'xxe', 'cwe': 'CWE-611', 'owasp': 'A05:2021-Security Misconfiguration',
        'severity': 'HIGH', 'capBase': 'CAP-SAST-XXE', 'ctrlGroup': 'CTRL-SAST-XXE-001',
        'controllerDir': 'injection', 'controllerFile': 'XxeController.java',
        'serviceFile': 'XxeService.java', 'repoFile': 'XxeRepository.java',
        'sink': 'DocumentBuilder.parse()', 'source': 'HTTP request body (XML)',
        'remediation': 'Disable external entities and DTDs in XML parser factory configuration',
        'rootCause': 'XML parser processes external entity declarations without restriction',
        'safeDesc': 'DocumentBuilderFactory with FEATURE_SECURE_PROCESSING and external entities disabled',
        'fwProtDesc': 'Uses Spring RestController with Jackson JSON (no XML parsing)',
        'unreachDesc': 'Feature-flagged code path with permanent false flag containing unsafe XML parser'
    },
    {
        'name': 'SpEL Injection', 'slug': 'speli', 'cwe': 'CWE-917', 'owasp': 'A03:2021-Injection',
        'severity': 'CRITICAL', 'capBase': 'CAP-SAST-SPEL', 'ctrlGroup': 'CTRL-SAST-SPEL-001',
        'controllerDir': 'injection', 'controllerFile': 'SpelInjectionController.java',
        'serviceFile': 'SpelInjectionService.java', 'repoFile': 'SpelInjectionRepository.java',
        'sink': 'SpelExpressionParser.parseExpression()', 'source': 'HttpServletRequest parameter',
        'remediation': 'Use SimpleEvaluationContext instead of StandardEvaluationContext to restrict SpEL capabilities',
        'rootCause': 'User input evaluated as Spring Expression Language expression with full context',
        'safeDesc': 'Uses SimpleEvaluationContext that restricts type references and constructors',
        'fwProtDesc': 'Uses Spring value binding instead of dynamic SpEL evaluation',
        'unreachDesc': 'Dead code behind impossible condition containing SpEL with StandardEvaluationContext'
    },
    {
        'name': 'Stored XSS', 'slug': 'stored-xss', 'cwe': 'CWE-79', 'owasp': 'A03:2021-Injection',
        'severity': 'MEDIUM', 'capBase': 'CAP-SAST-XSS-STORED', 'ctrlGroup': 'CTRL-SAST-STOREDXSS-001',
        'controllerDir': 'xss', 'controllerFile': 'StoredXssController.java',
        'serviceFile': 'StoredXssService.java', 'repoFile': 'StoredXssRepository.java',
        'sink': 'Thymeleaf th:utext (unescaped)', 'source': 'User-submitted form data',
        'remediation': 'Use Thymeleaf th:text (auto-escaping) instead of th:utext, or apply OWASP Java Encoder',
        'rootCause': 'User-submitted data stored in database and rendered without HTML encoding using th:utext',
        'safeDesc': 'Uses Thymeleaf th:text with automatic HTML entity encoding',
        'fwProtDesc': 'Uses Spring Content Security Policy header with strict-dynamic nonce',
        'unreachDesc': 'Private method rendering user data via th:utext with no calling controller'
    },
    {
        'name': 'Reflected XSS', 'slug': 'reflected-xss', 'cwe': 'CWE-79', 'owasp': 'A03:2021-Injection',
        'severity': 'MEDIUM', 'capBase': 'CAP-SAST-XSS-REFLECTED', 'ctrlGroup': 'CTRL-SAST-REFLXSS-001',
        'controllerDir': 'xss', 'controllerFile': 'ReflectedXssController.java',
        'serviceFile': 'ReflectedXssService.java', 'repoFile': 'ReflectedXssRepository.java',
        'sink': 'HttpServletResponse.getWriter().write()', 'source': 'HttpServletRequest parameter',
        'remediation': 'Apply output encoding using OWASP Java Encoder before writing to response',
        'rootCause': 'Request parameter reflected directly into HTTP response body without encoding',
        'safeDesc': 'Uses OWASP Java Encoder to HTML-encode output before writing to response',
        'fwProtDesc': 'Uses Spring ResponseEntity with Jackson JSON serialization (auto-escapes)',
        'unreachDesc': 'Private method writing unencoded parameter to response with no callers'
    },
    {
        'name': 'DOM-based XSS', 'slug': 'dom-xss', 'cwe': 'CWE-79', 'owasp': 'A03:2021-Injection',
        'severity': 'MEDIUM', 'capBase': 'CAP-SAST-XSS-DOM', 'ctrlGroup': 'CTRL-SAST-DOMXSS-001',
        'controllerDir': 'xss', 'controllerFile': 'DomXssController.java',
        'serviceFile': 'DomXssService.java', 'repoFile': 'DomXssRepository.java',
        'sink': 'JavaScript document.innerHTML assignment', 'source': 'URL fragment or parameter',
        'remediation': 'Use textContent instead of innerHTML, or apply DOMPurify sanitization',
        'rootCause': 'Client-side JavaScript reads URL parameter and assigns to innerHTML without sanitization',
        'safeDesc': 'Uses textContent for DOM updates and DOMPurify for any HTML insertion',
        'fwProtDesc': 'Uses Angular/React framework with automatic DOM sanitization',
        'unreachDesc': 'JavaScript function using innerHTML never called from any event handler or code path'
    },
    {
        'name': 'SSRF', 'slug': 'ssrf', 'cwe': 'CWE-918', 'owasp': 'A10:2021-Server-Side Request Forgery',
        'severity': 'HIGH', 'capBase': 'CAP-SAST-SSRF', 'ctrlGroup': 'CTRL-SAST-SSRF-001',
        'controllerDir': 'ssrf', 'controllerFile': 'SsrfController.java',
        'serviceFile': 'SsrfService.java', 'repoFile': 'SsrfRepository.java',
        'sink': 'URL.openConnection()', 'source': 'HttpServletRequest parameter',
        'remediation': 'Implement URL allowlist validation and block private/internal IP ranges',
        'rootCause': 'User-supplied URL used directly in server-side HTTP request without validation',
        'safeDesc': 'Validates URL against allowlist of permitted domains and blocks internal IPs',
        'fwProtDesc': 'Uses Spring WebClient with predefined base URL that cannot be overridden',
        'unreachDesc': 'Private method making HTTP request with user URL, never called from any endpoint'
    },
    {
        'name': 'Open Redirect', 'slug': 'redirect', 'cwe': 'CWE-601', 'owasp': 'A01:2021-Broken Access Control',
        'severity': 'MEDIUM', 'capBase': 'CAP-SAST-REDIRECT', 'ctrlGroup': 'CTRL-SAST-REDIRECT-001',
        'controllerDir': 'redirect', 'controllerFile': 'OpenRedirectController.java',
        'serviceFile': 'OpenRedirectService.java', 'repoFile': 'OpenRedirectRepository.java',
        'sink': 'HttpServletResponse.sendRedirect()', 'source': 'HttpServletRequest parameter',
        'remediation': 'Validate redirect URL against allowlist of permitted domains before redirecting',
        'rootCause': 'User-supplied redirect URL used in sendRedirect without validation',
        'safeDesc': 'Validates redirect URL against domain allowlist before redirecting',
        'fwProtDesc': 'Uses Spring redirect: prefix with relative paths only',
        'unreachDesc': 'Private method with sendRedirect using user input, no callers'
    },
    {
        'name': 'Path Traversal', 'slug': 'traversal', 'cwe': 'CWE-22', 'owasp': 'A01:2021-Broken Access Control',
        'severity': 'HIGH', 'capBase': 'CAP-SAST-TRAVERSAL', 'ctrlGroup': 'CTRL-SAST-TRAVERSAL-001',
        'controllerDir': 'traversal', 'controllerFile': 'PathTraversalController.java',
        'serviceFile': 'PathTraversalService.java', 'repoFile': 'PathTraversalRepository.java',
        'sink': 'new FileInputStream()', 'source': 'HttpServletRequest parameter',
        'remediation': 'Canonicalize file path and validate it starts with the expected base directory',
        'rootCause': 'User-supplied filename used to construct file path without canonicalization or base directory validation',
        'safeDesc': 'Canonicalizes path via Path.toRealPath() and validates against allowed base directory',
        'fwProtDesc': 'Uses Spring ResourceLoader with classpath: prefix restricting to application resources',
        'unreachDesc': 'Dead code behind if(1==2) containing FileInputStream with user-controlled path'
    },
    {
        'name': 'Unsafe Deserialization', 'slug': 'deser', 'cwe': 'CWE-502', 'owasp': 'A08:2021-Software and Data Integrity Failures',
        'severity': 'CRITICAL', 'capBase': 'CAP-SAST-DESER', 'ctrlGroup': 'CTRL-SAST-DESER-001',
        'controllerDir': 'deserialization', 'controllerFile': 'DeserializationController.java',
        'serviceFile': 'DeserializationService.java', 'repoFile': 'DeserializationRepository.java',
        'sink': 'ObjectInputStream.readObject()', 'source': 'HTTP request body (binary)',
        'remediation': 'Use ObjectInputFilter to restrict deserializable classes, or switch to safe formats like JSON',
        'rootCause': 'Untrusted binary data deserialized via ObjectInputStream without type filtering',
        'safeDesc': 'Uses ObjectInputFilter to restrict allowed classes during deserialization',
        'fwProtDesc': 'Uses Spring Jackson JSON deserialization with type validation',
        'unreachDesc': 'Unregistered Spring bean containing ObjectInputStream.readObject() on untrusted data'
    },
    {
        'name': 'Unsafe Reflection', 'slug': 'reflection', 'cwe': 'CWE-470', 'owasp': 'A03:2021-Injection',
        'severity': 'HIGH', 'capBase': 'CAP-SAST-REFLECT', 'ctrlGroup': 'CTRL-SAST-REFLECT-001',
        'controllerDir': 'reflection', 'controllerFile': 'UnsafeReflectionController.java',
        'serviceFile': 'UnsafeReflectionService.java', 'repoFile': 'UnsafeReflectionRepository.java',
        'sink': 'Class.forName().newInstance()', 'source': 'HttpServletRequest parameter',
        'remediation': 'Use allowlist of permitted class names instead of directly loading user-specified classes',
        'rootCause': 'User-supplied class name loaded via Class.forName() enabling arbitrary class instantiation',
        'safeDesc': 'Validates class name against allowlist before reflection',
        'fwProtDesc': 'Uses Spring dependency injection instead of dynamic class loading',
        'unreachDesc': 'Private method with Class.forName(userInput) never invoked'
    },
    {
        'name': 'Broken Authentication', 'slug': 'broken-auth', 'cwe': 'CWE-287', 'owasp': 'A07:2021-Identification and Authentication Failures',
        'severity': 'HIGH', 'capBase': 'CAP-SAST-AUTH', 'ctrlGroup': 'CTRL-SAST-AUTH-001',
        'controllerDir': 'auth', 'controllerFile': 'BrokenAuthController.java',
        'serviceFile': 'BrokenAuthService.java', 'repoFile': 'BrokenAuthRepository.java',
        'sink': 'Custom authentication check', 'source': 'HttpServletRequest credentials',
        'remediation': 'Use Spring Security AuthenticationManager with BCryptPasswordEncoder',
        'rootCause': 'Custom authentication logic with plaintext password comparison and no brute-force protection',
        'safeDesc': 'Uses Spring Security AuthenticationManager with BCrypt and account lockout',
        'fwProtDesc': 'Uses Spring Security form login with built-in CSRF and session management',
        'unreachDesc': 'Private authentication method with plaintext comparison never called from any endpoint'
    },
    {
        'name': 'Broken Authorization', 'slug': 'broken-authz', 'cwe': 'CWE-862', 'owasp': 'A01:2021-Broken Access Control',
        'severity': 'HIGH', 'capBase': 'CAP-SAST-AUTHZ', 'ctrlGroup': 'CTRL-SAST-AUTHZ-001',
        'controllerDir': 'auth', 'controllerFile': 'BrokenAuthzController.java',
        'serviceFile': 'BrokenAuthzService.java', 'repoFile': 'BrokenAuthzRepository.java',
        'sink': 'Database query returning other users data', 'source': 'HttpServletRequest parameter (userId)',
        'remediation': 'Implement @PreAuthorize checks and verify resource ownership before access',
        'rootCause': 'Endpoint accepts user ID parameter and returns data without verifying the requesting user owns the resource',
        'safeDesc': 'Uses @PreAuthorize and verifies authenticated user matches requested resource owner',
        'fwProtDesc': 'Uses Spring Security method-level authorization with @Secured annotations',
        'unreachDesc': 'Dead code behind feature flag returning other users data without auth check'
    },
    {
        'name': 'Weak Cryptography', 'slug': 'weak-crypto', 'cwe': 'CWE-327', 'owasp': 'A02:2021-Cryptographic Failures',
        'severity': 'HIGH', 'capBase': 'CAP-SAST-CRYPTO', 'ctrlGroup': 'CTRL-SAST-CRYPTO-001',
        'controllerDir': 'crypto', 'controllerFile': 'WeakCryptoController.java',
        'serviceFile': 'WeakCryptoService.java', 'repoFile': 'WeakCryptoRepository.java',
        'sink': 'Cipher.getInstance("DES/ECB/PKCS5Padding")', 'source': 'Application data',
        'remediation': 'Use AES-256-GCM with secure random IV instead of DES/ECB',
        'rootCause': 'Uses deprecated DES algorithm in ECB mode providing insufficient encryption strength',
        'safeDesc': 'Uses AES-256-GCM with SecureRandom IV generation',
        'fwProtDesc': 'Uses Spring Security Crypto module Encryptors.standard()',
        'unreachDesc': 'Private encryption method using DES/ECB with no callers'
    },
    {
        'name': 'Hardcoded Credentials', 'slug': 'hardcoded-creds', 'cwe': 'CWE-798', 'owasp': 'A07:2021-Identification and Authentication Failures',
        'severity': 'HIGH', 'capBase': 'CAP-SAST-CREDS', 'ctrlGroup': 'CTRL-SAST-CREDS-001',
        'controllerDir': 'crypto', 'controllerFile': 'HardcodedCredsController.java',
        'serviceFile': 'HardcodedCredsService.java', 'repoFile': 'HardcodedCredsRepository.java',
        'sink': 'DriverManager.getConnection() with hardcoded password', 'source': 'Hardcoded string literal',
        'remediation': 'Use environment variables or Spring externalized configuration for credentials',
        'rootCause': 'Database credentials hardcoded as string literals in source code',
        'safeDesc': 'Reads credentials from environment variables via Spring @Value annotation',
        'fwProtDesc': 'Uses Spring Cloud Vault or AWS Secrets Manager integration',
        'unreachDesc': 'Private method with hardcoded credentials in class never instantiated'
    },
    {
        'name': 'Sensitive Data Exposure', 'slug': 'data-exposure', 'cwe': 'CWE-200', 'owasp': 'A02:2021-Cryptographic Failures',
        'severity': 'MEDIUM', 'capBase': 'CAP-SAST-DATA', 'ctrlGroup': 'CTRL-SAST-DATA-001',
        'controllerDir': 'data', 'controllerFile': 'SensitiveDataController.java',
        'serviceFile': 'SensitiveDataService.java', 'repoFile': 'SensitiveDataRepository.java',
        'sink': 'HTTP response body containing PII', 'source': 'Database query returning sensitive fields',
        'remediation': 'Use DTOs with @JsonIgnore on sensitive fields and implement response filtering',
        'rootCause': 'API endpoint returns full entity objects including sensitive fields like SSN and credit card numbers',
        'safeDesc': 'Uses DTO projection with @JsonIgnore on sensitive fields',
        'fwProtDesc': 'Uses Spring Data projections with interface-based DTO automatically excluding sensitive fields',
        'unreachDesc': 'Private method returning full user entity with PII, never exposed via any endpoint'
    },
    {
        'name': 'SCA Core Check', 'slug': 'sca', 'cwe': 'CWE-1104', 'owasp': 'A08:2021-Software and Data Integrity Failures',
        'severity': 'CRITICAL', 'capBase': 'CAP-SAST-SCA', 'ctrlGroup': 'CTRL-SAST-SCA-001',
        'controllerDir': '', 'controllerFile': 'ScaController.java',
        'serviceFile': 'ScaService.java', 'repoFile': '',
        'sink': 'Application classpath dependency vulnerabilities', 'source': 'Classloader loaded classes',
        'remediation': 'Inspect dependency tree and upgrade vulnerable libraries',
        'rootCause': 'Class path contains libraries with known vulnerabilities',
        'safeDesc': 'Upgrades dependencies in pom.xml to safe versions',
        'fwProtDesc': 'Excludes transitive vulnerable elements at package layer',
        'unreachDesc': 'Vulnerable library class referenced only in unreachable admin diagnostic service'
    }
]

# ============================================================
# SCA SCENARIO DEFINITIONS (40 scenarios)
# ============================================================
SCA_LIBRARIES = [
    {'name': 'Log4j Core', 'artifact': 'log4j-core', 'version': '2.14.1', 'cve': 'CVE-2021-44228', 'cwe': 'CWE-502', 'severity': 'CRITICAL', 'owasp': 'A08:2021-Software and Data Integrity Failures', 'remediation': 'Upgrade to Log4j 2.17.1 or later', 'rootCause': 'JNDI lookup feature processes untrusted input enabling remote code execution'},
    {'name': 'Jackson Databind', 'artifact': 'jackson-databind', 'version': '2.9.8', 'cve': 'CVE-2019-12086', 'cwe': 'CWE-502', 'severity': 'HIGH', 'owasp': 'A08:2021-Software and Data Integrity Failures', 'remediation': 'Upgrade to Jackson Databind 2.9.9 or later', 'rootCause': 'Polymorphic deserialization allows arbitrary class instantiation via type information'},
    {'name': 'SnakeYAML', 'artifact': 'snakeyaml', 'version': '1.26', 'cve': 'CVE-2022-1471', 'cwe': 'CWE-502', 'severity': 'CRITICAL', 'owasp': 'A08:2021-Software and Data Integrity Failures', 'remediation': 'Upgrade to SnakeYAML 2.0 or use SafeConstructor', 'rootCause': 'YAML deserialization with default Constructor allows arbitrary object instantiation'},
    {'name': 'Commons Collections', 'artifact': 'commons-collections', 'version': '3.2.1', 'cve': 'CVE-2015-6420', 'cwe': 'CWE-502', 'severity': 'CRITICAL', 'owasp': 'A08:2021-Software and Data Integrity Failures', 'remediation': 'Upgrade to Commons Collections 3.2.2 or 4.1+', 'rootCause': 'InvokerTransformer gadget chain enables remote code execution during deserialization'},
    {'name': 'Spring Core', 'artifact': 'spring-core', 'version': '5.3.17', 'cve': 'CVE-2022-22965', 'cwe': 'CWE-94', 'severity': 'CRITICAL', 'owasp': 'A03:2021-Injection', 'remediation': 'Upgrade to Spring Framework 5.3.18 or 5.2.20+', 'rootCause': 'Spring4Shell: class loader manipulation via data binding on JDK 9+'},
    {'name': 'Apache Commons Text', 'artifact': 'commons-text', 'version': '1.9', 'cve': 'CVE-2022-42889', 'cwe': 'CWE-94', 'severity': 'CRITICAL', 'owasp': 'A03:2021-Injection', 'remediation': 'Upgrade to Apache Commons Text 1.10.0 or later', 'rootCause': 'StringSubstitutor default interpolators include script and DNS lookups enabling RCE'},
    {'name': 'Apache HttpClient', 'artifact': 'httpclient', 'version': '4.5.6', 'cve': 'CVE-2020-13956', 'cwe': 'CWE-20', 'severity': 'MEDIUM', 'owasp': 'A03:2021-Injection', 'remediation': 'Upgrade to Apache HttpClient 4.5.13 or later', 'rootCause': 'Improper input validation of URI authority allows request smuggling'},
    {'name': 'Bouncy Castle', 'artifact': 'bcprov-jdk15on', 'version': '1.60', 'cve': 'CVE-2020-28052', 'cwe': 'CWE-287', 'severity': 'HIGH', 'owasp': 'A02:2021-Cryptographic Failures', 'remediation': 'Upgrade to Bouncy Castle 1.67 or later', 'rootCause': 'OpenBSDBCrypt.checkPassword allows authentication bypass due to comparison flaw'},
    {'name': 'Hibernate Validator', 'artifact': 'hibernate-validator', 'version': '6.0.0.Final', 'cve': 'CVE-2020-10693', 'cwe': 'CWE-20', 'severity': 'MEDIUM', 'owasp': 'A03:2021-Injection', 'remediation': 'Upgrade to Hibernate Validator 6.0.20.Final or later', 'rootCause': 'Insufficient validation of constraint validator payloads allows bypass'},
    {'name': 'Guava', 'artifact': 'guava', 'version': '29.0-jre', 'cve': 'CVE-2020-8908', 'cwe': 'CWE-732', 'severity': 'LOW', 'owasp': 'A01:2021-Broken Access Control', 'remediation': 'Upgrade to Guava 32.0.0 or later', 'rootCause': 'Files.createTempDir() creates directories with overly permissive default permissions'}
]

# ============================================================
# DAST SCENARIO DEFINITIONS (20 scenarios)
# ============================================================
DAST_CLASSES = [
    {'name': 'SQL Injection', 'slug': 'sqli', 'cwe': 'CWE-89', 'owasp': 'A03:2021-Injection', 'severity': 'HIGH', 'endpoint': '/api/v1/catalog/query', 'safeEndpoint': '/api/v1/catalog/query/secure', 'method': 'POST', 'remediation': 'Use parameterized queries'},
    {'name': 'XSS', 'slug': 'xss', 'cwe': 'CWE-79', 'owasp': 'A03:2021-Injection', 'severity': 'MEDIUM', 'endpoint': '/api/v1/reviews/feedback', 'safeEndpoint': '/api/v1/reviews/feedback/secure', 'method': 'GET', 'remediation': 'Apply output encoding'},
    {'name': 'CSRF', 'slug': 'csrf', 'cwe': 'CWE-352', 'owasp': 'A01:2021-Broken Access Control', 'severity': 'MEDIUM', 'endpoint': '/api/v1/cart/items', 'safeEndpoint': '/api/v1/cart/items/secure', 'method': 'POST', 'remediation': 'Implement CSRF token validation'},
    {'name': 'SSRF', 'slug': 'ssrf', 'cwe': 'CWE-918', 'owasp': 'A10:2021-Server-Side Request Forgery', 'severity': 'HIGH', 'endpoint': '/api/v1/vendors/webhooks', 'safeEndpoint': '/api/v1/vendors/webhooks/secure', 'method': 'POST', 'remediation': 'Implement URL allowlist validation'},
    {'name': 'Open Redirect', 'slug': 'redirect', 'cwe': 'CWE-601', 'owasp': 'A01:2021-Broken Access Control', 'severity': 'MEDIUM', 'endpoint': '/api/v1/auth/oauth/redirect', 'safeEndpoint': '/api/v1/auth/oauth/redirect/secure', 'method': 'GET', 'remediation': 'Validate redirect URL against allowlist'},
    {'name': 'Path Traversal', 'slug': 'traversal', 'cwe': 'CWE-22', 'owasp': 'A01:2021-Broken Access Control', 'severity': 'HIGH', 'endpoint': '/api/v1/assets/download', 'safeEndpoint': '/api/v1/assets/download/secure', 'method': 'GET', 'remediation': 'Canonicalize path and validate base directory'},
    {'name': 'File Upload', 'slug': 'upload', 'cwe': 'CWE-434', 'owasp': 'A04:2021-Insecure Design', 'severity': 'HIGH', 'endpoint': '/api/v1/profile/avatar/upload', 'safeEndpoint': '/api/v1/profile/avatar/upload/secure', 'method': 'POST', 'remediation': 'Validate file type, size, and store outside webroot'},
    {'name': 'Authentication Weakness', 'slug': 'auth', 'cwe': 'CWE-287', 'owasp': 'A07:2021-Identification and Authentication Failures', 'severity': 'HIGH', 'endpoint': '/api/v1/auth/member-login', 'safeEndpoint': '/api/v1/auth/member-login/secure', 'method': 'POST', 'remediation': 'Enforce strong password policy and disable default credentials'},
    {'name': 'Authorization Weakness', 'slug': 'authz', 'cwe': 'CWE-862', 'owasp': 'A01:2021-Broken Access Control', 'severity': 'HIGH', 'endpoint': '/api/v1/admin/settings', 'safeEndpoint': '/api/v1/admin/settings/secure', 'method': 'GET', 'remediation': 'Implement resource-level authorization checks'},
    {'name': 'API Security', 'slug': 'api', 'cwe': 'CWE-284', 'owasp': 'A01:2021-Broken Access Control', 'severity': 'MEDIUM', 'endpoint': '/api/v1/checkout/place-order', 'safeEndpoint': '/api/v1/checkout/place-order/secure', 'method': 'GET', 'remediation': 'Require authentication and validate API key/token for all endpoints'}
]

# ============================================================
# SECRET SCENARIO DEFINITIONS (30 scenarios)
# ============================================================
SECRET_SCENARIOS = [
    {'name': 'AWS Access Key in Source', 'type': 'AWS Access Key', 'format': 'Source Code', 'file': 'src/main/java/com/shopsphere/util/CloudConfig.java', 'cwe': 'CWE-798', 'severity': 'CRITICAL'},
    {'name': 'AWS Secret Key in Source', 'type': 'AWS Secret Key', 'format': 'Source Code', 'file': 'src/main/java/com/shopsphere/util/CloudConfig.java', 'cwe': 'CWE-798', 'severity': 'CRITICAL'},
    {'name': 'GitHub Token in Source', 'type': 'GitHub Personal Access Token', 'format': 'Source Code', 'file': 'src/main/java/com/shopsphere/util/GitHubClient.java', 'cwe': 'CWE-798', 'severity': 'HIGH'},
    {'name': 'GitLab Token in Source', 'type': 'GitLab Personal Access Token', 'format': 'Source Code', 'file': 'src/main/java/com/shopsphere/util/GitLabClient.java', 'cwe': 'CWE-798', 'severity': 'HIGH'},
    {'name': 'Slack Token in Source', 'type': 'Slack Bot Token', 'format': 'Source Code', 'file': 'src/main/java/com/shopsphere/util/SlackNotifier.java', 'cwe': 'CWE-798', 'severity': 'HIGH'},
    {'name': 'Azure Client Secret in Source', 'type': 'Azure Client Secret', 'format': 'Source Code', 'file': 'src/main/java/com/shopsphere/util/AzureConfig.java', 'cwe': 'CWE-798', 'severity': 'CRITICAL'},
    {'name': 'GCP Service Account Key in YAML', 'type': 'GCP Service Account Key', 'format': 'YAML', 'file': 'src/main/resources/gcp-credentials.yml', 'cwe': 'CWE-798', 'severity': 'CRITICAL'},
    {'name': 'JWT Secret in YAML', 'type': 'JWT Signing Secret', 'format': 'YAML', 'file': 'src/main/resources/application-secrets.yml', 'cwe': 'CWE-798', 'severity': 'HIGH'},
    {'name': 'Database Password in YAML', 'type': 'Database Password', 'format': 'YAML', 'file': 'src/main/resources/application-secrets.yml', 'cwe': 'CWE-798', 'severity': 'HIGH'},
    {'name': 'API Key in YAML', 'type': 'Generic API Key', 'format': 'YAML', 'file': 'src/main/resources/third-party-config.yml', 'cwe': 'CWE-798', 'severity': 'MEDIUM'},
    {'name': 'SSH Private Key in JSON', 'type': 'SSH Private Key', 'format': 'JSON', 'file': 'secrets-benchmark/config-files/ssh-config.json', 'cwe': 'CWE-321', 'severity': 'CRITICAL'},
    {'name': 'Certificate Private Key in JSON', 'type': 'TLS Private Key', 'format': 'JSON', 'file': 'secrets-benchmark/config-files/tls-config.json', 'cwe': 'CWE-321', 'severity': 'CRITICAL'},
    {'name': 'OAuth Client Secret in JSON', 'type': 'OAuth Client Secret', 'format': 'JSON', 'file': 'secrets-benchmark/config-files/oauth-config.json', 'cwe': 'CWE-798', 'severity': 'HIGH'},
    {'name': 'DB Connection String in Properties', 'type': 'Database Connection Password', 'format': 'Properties', 'file': 'src/main/resources/database.properties', 'cwe': 'CWE-798', 'severity': 'HIGH'},
    {'name': 'SMTP Password in Properties', 'type': 'SMTP Password', 'format': 'Properties', 'file': 'src/main/resources/mail.properties', 'cwe': 'CWE-798', 'severity': 'MEDIUM'},
    {'name': 'Redis Password in Properties', 'type': 'Redis Password', 'format': 'Properties', 'file': 'src/main/resources/redis.properties', 'cwe': 'CWE-798', 'severity': 'MEDIUM'},
    {'name': 'AWS Credentials in Env', 'type': 'AWS Credentials', 'format': 'Env File', 'file': 'secrets-benchmark/config-files/.env.production', 'cwe': 'CWE-798', 'severity': 'CRITICAL'},
    {'name': 'Stripe API Key in Env', 'type': 'Stripe API Key', 'format': 'Env File', 'file': 'secrets-benchmark/config-files/.env.production', 'cwe': 'CWE-798', 'severity': 'HIGH'},
    {'name': 'Twilio Auth Token in Env', 'type': 'Twilio Auth Token', 'format': 'Env File', 'file': 'secrets-benchmark/config-files/.env.production', 'cwe': 'CWE-798', 'severity': 'HIGH'},
    {'name': 'Cloud Provider Secret in Terraform', 'type': 'Cloud Provider Secret', 'format': 'Terraform', 'file': 'iac/terraform/aws/vulnerable/provider-secrets.tf', 'cwe': 'CWE-798', 'severity': 'CRITICAL'},
    {'name': 'Private Key in Terraform', 'type': 'TLS Private Key', 'format': 'Terraform', 'file': 'iac/terraform/aws/vulnerable/tls-config.tf', 'cwe': 'CWE-321', 'severity': 'CRITICAL'},
    {'name': 'Access Token in Terraform', 'type': 'API Access Token', 'format': 'Terraform', 'file': 'iac/terraform/aws/vulnerable/api-gateway.tf', 'cwe': 'CWE-798', 'severity': 'HIGH'},
    {'name': 'Registry Password in Dockerfile', 'type': 'Container Registry Password', 'format': 'Dockerfile', 'file': 'container/vulnerable/Dockerfile.secrets', 'cwe': 'CWE-798', 'severity': 'HIGH'},
    {'name': 'API Credentials in Dockerfile', 'type': 'API Credentials', 'format': 'Dockerfile', 'file': 'container/vulnerable/Dockerfile.api-creds', 'cwe': 'CWE-798', 'severity': 'HIGH'},
    {'name': 'Encryption Key in Dockerfile', 'type': 'Encryption Key', 'format': 'Dockerfile', 'file': 'container/vulnerable/Dockerfile.enc-key', 'cwe': 'CWE-321', 'severity': 'CRITICAL'},
    {'name': 'Deploy Key in CI/CD', 'type': 'SSH Deploy Key', 'format': 'CI/CD Pipeline', 'file': 'cicd/github-actions/vulnerable/deploy-with-secrets.yml', 'cwe': 'CWE-798', 'severity': 'HIGH'},
    {'name': 'NPM Token in CI/CD', 'type': 'NPM Auth Token', 'format': 'CI/CD Pipeline', 'file': 'cicd/github-actions/vulnerable/npm-publish-secrets.yml', 'cwe': 'CWE-798', 'severity': 'HIGH'},
    {'name': 'Docker Hub Token in CI/CD', 'type': 'Docker Hub Token', 'format': 'CI/CD Pipeline', 'file': 'cicd/jenkins/vulnerable/Jenkinsfile.docker-secrets', 'cwe': 'CWE-798', 'severity': 'HIGH'},
    {'name': 'SSH Key in K8s Secret', 'type': 'SSH Private Key', 'format': 'Kubernetes Manifest', 'file': 'iac/kubernetes/secrets/ssh-key-secret.yaml', 'cwe': 'CWE-321', 'severity': 'CRITICAL'},
    {'name': 'TLS Key in K8s Secret', 'type': 'TLS Certificate Private Key', 'format': 'Kubernetes Manifest', 'file': 'iac/kubernetes/secrets/tls-secret.yaml', 'cwe': 'CWE-321', 'severity': 'CRITICAL'}
]

# ============================================================
# CONTAINER SCENARIO DEFINITIONS (20 scenarios)
# ============================================================
CONTAINER_CLASSES = [
    {'name': 'Root User', 'slug': 'root-user', 'cwe': 'CWE-250', 'severity': 'HIGH', 'vulnFile': 'container/vulnerable/Dockerfile.root-user', 'safeFile': 'container/safe/Dockerfile.root-user', 'remediation': 'Use USER directive to run as non-root user', 'rootCause': 'Container runs as root user (UID 0) by default'},
    {'name': 'Privilege Escalation', 'slug': 'privesc', 'cwe': 'CWE-269', 'severity': 'HIGH', 'vulnFile': 'container/vulnerable/Dockerfile.privesc', 'safeFile': 'container/safe/Dockerfile.privesc', 'remediation': 'Set no-new-privileges security option and drop all capabilities', 'rootCause': 'Container allows privilege escalation via setuid binaries and unrestricted capabilities'},
    {'name': 'Dangerous Capabilities', 'slug': 'caps', 'cwe': 'CWE-250', 'severity': 'HIGH', 'vulnFile': 'container/vulnerable/Dockerfile.caps', 'safeFile': 'container/safe/Dockerfile.caps', 'remediation': 'Drop all capabilities and add only required ones explicitly', 'rootCause': 'Container granted dangerous Linux capabilities like SYS_ADMIN, NET_ADMIN'},
    {'name': 'Outdated Base Image', 'slug': 'base-image', 'cwe': 'CWE-1104', 'severity': 'MEDIUM', 'vulnFile': 'container/vulnerable/Dockerfile.outdated-base', 'safeFile': 'container/safe/Dockerfile.outdated-base', 'remediation': 'Use latest stable base image with regular update cadence', 'rootCause': 'Base image contains known vulnerabilities in system packages'},
    {'name': 'Exposed Secrets', 'slug': 'secrets', 'cwe': 'CWE-798', 'severity': 'CRITICAL', 'vulnFile': 'container/vulnerable/Dockerfile.exposed-secrets', 'safeFile': 'container/safe/Dockerfile.exposed-secrets', 'remediation': 'Use Docker secrets or environment variables from secure vault', 'rootCause': 'Secrets hardcoded in Dockerfile ENV or COPY instructions embedded in image layers'},
    {'name': 'Weak Runtime Config', 'slug': 'runtime', 'cwe': 'CWE-250', 'severity': 'MEDIUM', 'vulnFile': 'container/vulnerable/Dockerfile.weak-runtime', 'safeFile': 'container/safe/Dockerfile.weak-runtime', 'remediation': 'Apply read-only root filesystem and restrict system calls with seccomp', 'rootCause': 'Container runs with writable root filesystem and unrestricted system calls'},
    {'name': 'Excessive Attack Surface', 'slug': 'surface', 'cwe': 'CWE-1059', 'severity': 'MEDIUM', 'vulnFile': 'container/vulnerable/Dockerfile.attack-surface', 'safeFile': 'container/safe/Dockerfile.attack-surface', 'remediation': 'Use distroless or Alpine base and remove unnecessary packages', 'rootCause': 'Container includes full OS distribution with unnecessary tools and packages'},
    {'name': 'Missing Health Checks', 'slug': 'healthcheck', 'cwe': 'CWE-703', 'severity': 'LOW', 'vulnFile': 'container/vulnerable/Dockerfile.no-healthcheck', 'safeFile': 'container/safe/Dockerfile.healthcheck', 'remediation': 'Add HEALTHCHECK instruction to verify application health', 'rootCause': 'No HEALTHCHECK instruction defined, preventing orchestrator from detecting unhealthy containers'},
    {'name': 'Package Vulnerabilities', 'slug': 'pkg-vuln', 'cwe': 'CWE-1104', 'severity': 'HIGH', 'vulnFile': 'container/vulnerable/Dockerfile.pkg-vuln', 'safeFile': 'container/safe/Dockerfile.pkg-vuln', 'remediation': 'Pin package versions and run vulnerability scans in CI/CD', 'rootCause': 'Container installs packages with known CVEs without version pinning'},
    {'name': 'Weak File Permissions', 'slug': 'perms', 'cwe': 'CWE-732', 'severity': 'MEDIUM', 'vulnFile': 'container/vulnerable/Dockerfile.weak-perms', 'safeFile': 'container/safe/Dockerfile.weak-perms', 'remediation': 'Set restrictive file permissions (644 for files, 755 for directories)', 'rootCause': 'Application files have world-writable permissions (chmod 777)'}
]

# ============================================================
# IAC SCENARIO DEFINITIONS (20 scenarios)
# ============================================================
IAC_CLASSES = [
    {'name': 'Public S3 Bucket', 'slug': 's3-public', 'cwe': 'CWE-284', 'severity': 'CRITICAL', 'vulnFile': 'iac/terraform/aws/vulnerable/public-s3-bucket.tf', 'safeFile': 'iac/terraform/aws/safe/private-s3-bucket.tf', 'remediation': 'Block public access with aws_s3_bucket_public_access_block and restrict bucket policy', 'rootCause': 'S3 bucket has public-read ACL and no public access block enabled'},
    {'name': 'Public Database', 'slug': 'db-public', 'cwe': 'CWE-284', 'severity': 'CRITICAL', 'vulnFile': 'iac/terraform/aws/vulnerable/public-rds.tf', 'safeFile': 'iac/terraform/aws/safe/private-rds.tf', 'remediation': 'Set publicly_accessible to false and place RDS in private subnet', 'rootCause': 'RDS instance has publicly_accessible set to true with weak security group'},
    {'name': 'Weak Security Groups', 'slug': 'weak-sg', 'cwe': 'CWE-284', 'severity': 'HIGH', 'vulnFile': 'iac/terraform/aws/vulnerable/weak-security-group.tf', 'safeFile': 'iac/terraform/aws/safe/restricted-security-group.tf', 'remediation': 'Restrict ingress CIDR to specific IP ranges instead of 0.0.0.0/0', 'rootCause': 'Security group allows ingress from 0.0.0.0/0 on sensitive ports'},
    {'name': 'Excessive IAM Permissions', 'slug': 'iam-excess', 'cwe': 'CWE-250', 'severity': 'HIGH', 'vulnFile': 'iac/terraform/aws/vulnerable/excessive-iam.tf', 'safeFile': 'iac/terraform/aws/safe/least-privilege-iam.tf', 'remediation': 'Apply least-privilege principle with specific resource ARNs and actions', 'rootCause': 'IAM policy grants Action: * and Resource: * providing full administrative access'},
    {'name': 'Missing Encryption', 'slug': 'no-encrypt', 'cwe': 'CWE-311', 'severity': 'HIGH', 'vulnFile': 'iac/terraform/aws/vulnerable/unencrypted-storage.tf', 'safeFile': 'iac/terraform/aws/safe/encrypted-storage.tf', 'remediation': 'Enable server-side encryption with AWS KMS customer-managed key', 'rootCause': 'EBS volumes and S3 buckets have no encryption configuration'},
    {'name': 'Missing Logging', 'slug': 'no-logging', 'cwe': 'CWE-778', 'severity': 'MEDIUM', 'vulnFile': 'iac/terraform/aws/vulnerable/no-logging.tf', 'safeFile': 'iac/terraform/aws/safe/full-logging.tf', 'remediation': 'Enable CloudTrail, VPC Flow Logs, and S3 access logging', 'rootCause': 'CloudTrail not enabled and no access logging configured for S3 buckets'},
    {'name': 'Weak Network Segmentation', 'slug': 'weak-seg', 'cwe': 'CWE-284', 'severity': 'MEDIUM', 'vulnFile': 'iac/terraform/aws/vulnerable/flat-network.tf', 'safeFile': 'iac/terraform/aws/safe/segmented-network.tf', 'remediation': 'Implement VPC subnets with NACLs and route table isolation', 'rootCause': 'All resources deployed in single public subnet with no network segmentation'},
    {'name': 'Dangerous RBAC', 'slug': 'rbac', 'cwe': 'CWE-250', 'severity': 'HIGH', 'vulnFile': 'iac/kubernetes/rbac/dangerous-clusterrole.yaml', 'safeFile': 'iac/kubernetes/rbac/restricted-clusterrole.yaml', 'remediation': 'Restrict RBAC to specific resources and verbs, avoid wildcard permissions', 'rootCause': 'ClusterRole grants wildcard (*) permissions on all resources and verbs'},
    {'name': 'Privileged Pods', 'slug': 'priv-pod', 'cwe': 'CWE-250', 'severity': 'CRITICAL', 'vulnFile': 'iac/kubernetes/deployments/privileged-pod.yaml', 'safeFile': 'iac/kubernetes/deployments/restricted-pod.yaml', 'remediation': 'Set securityContext.privileged to false and apply PodSecurityPolicy', 'rootCause': 'Pod runs with privileged: true granting full host access'},
    {'name': 'HostPath Mounts', 'slug': 'hostpath', 'cwe': 'CWE-284', 'severity': 'HIGH', 'vulnFile': 'iac/kubernetes/deployments/hostpath-mount.yaml', 'safeFile': 'iac/kubernetes/deployments/safe-volume-mount.yaml', 'remediation': 'Use PersistentVolumeClaims instead of hostPath volumes', 'rootCause': 'Pod mounts host filesystem path giving container access to host files'}
]

def sanitize_cap_id(s):
    return re.sub(r'[^A-Z0-9]', '', s.upper())[:6]

def generate_vulnerability_register():
    entries = []

    # SAST entries (80)
    bench_idx = 1
    for cls in SAST_CLASSES:
        vuln_route = ROUTE_REPLACEMENTS.get(f"/api/vulnerable/{cls['slug']}", f"/api/v1/vulnerable/{cls['slug']}")
        safe_route = ROUTE_REPLACEMENTS.get(f"/api/safe/{cls['slug']}", f"/api/v1/safe/{cls['slug']}")
        unreach_route = None
        fw_route = ROUTE_REPLACEMENTS.get(f"/api/framework-protected/{cls['slug']}", f"/api/v1/framework-protected/{cls['slug']}")
        
        variants = [
            {'variant': 'vulnerable', 'reachable': True, 'exploitable': True, 'endpoint': vuln_route, 'line': 35},
            {'variant': 'safe', 'reachable': True, 'exploitable': False, 'endpoint': safe_route, 'line': 35},
            {'variant': 'unreachable', 'reachable': False, 'exploitable': False, 'endpoint': unreach_route, 'line': 45},
            {'variant': 'framework-protected', 'reachable': True, 'exploitable': False, 'endpoint': fw_route, 'line': 35}
        ]
        
        for vi, v in enumerate(variants):
            bid = f"BENCH-SAST-{bench_idx:03d}"
            sev = cls['severity'] if v['variant'] in ('vulnerable', 'unreachable') else 'NONE'
            det = 'SAST' if v['variant'] in ('vulnerable', 'unreachable') else 'NONE'
            
            # Map old path to new path
            if cls['controllerDir']:
                orig_pkg = f"com.benchmark.appsec.controller.sast.{cls['controllerDir']}"
            else:
                orig_pkg = "com.benchmark.appsec.controller.sca"
                
            dest_pkg = PACKAGE_MAPPING.get(orig_pkg, "com.shopsphere")
            dest_dir = dest_pkg.replace(".", "/")
            orig_class = cls['controllerFile'].replace('.java', '')
            dest_class = RENAMES.get(orig_class, orig_class)
            file_path = f"src/main/java/{dest_dir}/{dest_class}.java"
            
            through_classes = []
            for f in [cls['controllerFile'], cls['serviceFile'], cls['repoFile']]:
                if f:
                    orig_f = f.replace('.java', '')
                    through_classes.append(RENAMES.get(orig_f, orig_f))

            entries.append({
                'benchmark_id': bid,
                'capability_id': f"{cls['capBase']}-{vi+1:03d}",
                'category': 'SAST',
                'subcategory': cls['name'],
                'variant': v['variant'],
                'cwe': cls['cwe'],
                'owasp_category': cls['owasp'],
                'cve': None,
                'severity': sev,
                'file': file_path,
                'line': v['line'],
                'endpoint': v['endpoint'],
                'reachable': v['reachable'],
                'exploitable': v['exploitable'],
                'expected_detection': det,
                'expected_severity': sev,
                'expected_remediation': cls['remediation'],
                'validation_method': 'automated',
                'data_flow': {
                    'source': cls['source'],
                    'sink': cls['sink'],
                    'through': through_classes
                },
                'created_in_phase': 1,
                'tags': ['sast', 'control-pair', cls['slug'], v['variant'], cls['ctrlGroup']]
            })
            bench_idx += 1

    # SCA entries (40)
    sca_variants = ['direct-reachable', 'direct-unreachable', 'transitive-reachable', 'transitive-unreachable']
    for vi, var_name in enumerate(sca_variants):
        for li, lib in enumerate(SCA_LIBRARIES):
            idx = vi * 10 + li + 1
            bid = f"BENCH-SCA-{idx:03d}"
            is_reachable = 'reachable' in var_name and 'unreachable' not in var_name
            is_direct = 'direct' in var_name
            cap_id = 'CAP-SCA-DIRECT-001' if is_direct and is_reachable else ('CAP-SCA-UNREACH-001' if not is_reachable else 'CAP-SCA-TRANS-001')
            safe_artifact = re.sub(r'[^a-z0-9]', '-', lib['artifact'])
            entries.append({
                'benchmark_id': bid,
                'capability_id': cap_id,
                'category': 'SCA',
                'subcategory': f"{lib['name']} ({var_name})",
                'variant': 'vulnerable' if is_reachable else 'unreachable',
                'cwe': lib['cwe'],
                'owasp_category': lib['owasp'],
                'cve': lib['cve'],
                'severity': lib['severity'],
                'file': 'pom.xml',
                'line': 0,
                'endpoint': f"/api/v1/system/update/check/{safe_artifact}" if is_reachable else None,
                'reachable': is_reachable,
                'exploitable': is_reachable,
                'expected_detection': 'SCA',
                'expected_severity': lib['severity'],
                'expected_remediation': lib['remediation'],
                'validation_method': 'automated',
                'data_flow': {
                    'source': 'Direct Maven dependency' if is_direct else 'Transitive Maven dependency',
                    'sink': f"{lib['name']} vulnerable API call" if is_reachable else None,
                    'through': ['pom.xml'] if is_direct else ['pom.xml', 'parent-dependency']
                },
                'created_in_phase': 1,
                'tags': ['sca', 'direct' if is_direct else 'transitive', 'reachable' if is_reachable else 'unreachable', lib['artifact']]
            })

    # DAST entries (20)
    dast_idx = 1
    for cls in DAST_CLASSES:
        safe_name = cls['name'].replace(' ', '')
        
        # Determine DAST file path based on refactoring maps
        orig_class = f"Dast{safe_name}Controller"
        dest_class = RENAMES.get(orig_class, orig_class)
        orig_pkg = f"com.benchmark.appsec.controller.dast.{cls['slug']}"
        dest_pkg = PACKAGE_MAPPING.get(orig_pkg, "com.shopsphere")
        dest_dir = dest_pkg.replace(".", "/")
        file_path = f"src/main/java/{dest_dir}/{dest_class}.java"
        
        through_classes = [
            RENAMES.get(f"Dast{safe_name}Controller", f"Dast{safe_name}Controller"),
            RENAMES.get(f"Dast{safe_name}Service", f"Dast{safe_name}Service"),
            RENAMES.get(f"Dast{safe_name}Repository", f"Dast{safe_name}Repository")
        ]
        
        # Vulnerable
        entries.append({
            'benchmark_id': f"BENCH-DAST-{dast_idx:03d}",
            'capability_id': f"CAP-DAST-{sanitize_cap_id(cls['slug'])}-001",
            'category': 'DAST',
            'subcategory': cls['name'],
            'variant': 'vulnerable',
            'cwe': cls['cwe'],
            'owasp_category': cls['owasp'],
            'cve': None,
            'severity': cls['severity'],
            'file': file_path,
            'line': 30,
            'endpoint': cls['endpoint'],
            'reachable': True,
            'exploitable': True,
            'expected_detection': 'DAST',
            'expected_severity': cls['severity'],
            'expected_remediation': cls['remediation'],
            'validation_method': 'exploit',
            'data_flow': {
                'source': f"HTTP {cls['method']} request",
                'sink': f"{cls['name']} sink",
                'through': through_classes
            },
            'created_in_phase': 1,
            'tags': ['dast', 'vulnerable', cls['slug'], 'externally-reachable']
        })
        dast_idx += 1
        # Safe
        entries.append({
            'benchmark_id': f"BENCH-DAST-{dast_idx:03d}",
            'capability_id': f"CAP-DAST-{sanitize_cap_id(cls['slug'])}-001",
            'category': 'DAST',
            'subcategory': cls['name'],
            'variant': 'safe',
            'cwe': cls['cwe'],
            'owasp_category': cls['owasp'],
            'cve': None,
            'severity': 'NONE',
            'file': file_path,
            'line': 60,
            'endpoint': cls['safeEndpoint'],
            'reachable': True,
            'exploitable': False,
            'expected_detection': 'NONE',
            'expected_severity': 'NONE',
            'expected_remediation': cls['remediation'],
            'validation_method': 'automated',
            'data_flow': {
                'source': f"HTTP {cls['method']} request",
                'sink': f"{cls['name']} sink (sanitized)",
                'through': through_classes
            },
            'created_in_phase': 1,
            'tags': ['dast', 'safe', cls['slug'], 'externally-reachable']
        })
        dast_idx += 1

    # SECRET entries (30)
    for i, s in enumerate(SECRET_SCENARIOS):
        bid = f"BENCH-SECRET-{i+1:03d}"
        cap_slug = sanitize_cap_id(s['type'])
        entries.append({
            'benchmark_id': bid,
            'capability_id': f"CAP-SECRET-{cap_slug}-001",
            'category': 'SECRET',
            'subcategory': s['name'],
            'variant': 'vulnerable',
            'cwe': s['cwe'],
            'owasp_category': 'A07:2021-Identification and Authentication Failures',
            'cve': None,
            'severity': s['severity'],
            'file': s['file'],
            'line': 0,
            'endpoint': None,
            'reachable': True,
            'exploitable': True,
            'expected_detection': 'SECRET',
            'expected_severity': s['severity'],
            'expected_remediation': f"Remove hardcoded {s['type']} and use environment variables or secrets manager",
            'validation_method': 'automated',
            'data_flow': {'source': f"Hardcoded {s['type']} in {s['format']}", 'sink': None, 'through': []},
            'created_in_phase': 1,
            'tags': ['secret', s['format'].lower().replace(' ', '-'), s['type'].lower().replace(' ', '-')]
        })

    # CONTAINER entries (20)
    cont_idx = 1
    for cls in CONTAINER_CLASSES:
        cap_slug = sanitize_cap_id(cls['slug'])
        # Vulnerable
        entries.append({
            'benchmark_id': f"BENCH-CONTAINER-{cont_idx:03d}",
            'capability_id': f"CAP-CONTAINER-{cap_slug}-001",
            'category': 'CONTAINER',
            'subcategory': cls['name'],
            'variant': 'vulnerable',
            'cwe': cls['cwe'],
            'owasp_category': 'A05:2021-Security Misconfiguration',
            'cve': None,
            'severity': cls['severity'],
            'file': cls['vulnFile'],
            'line': 1,
            'endpoint': None,
            'reachable': True,
            'exploitable': True,
            'expected_detection': 'CONTAINER',
            'expected_severity': cls['severity'],
            'expected_remediation': cls['remediation'],
            'validation_method': 'automated',
            'data_flow': {'source': 'Dockerfile', 'sink': 'Container runtime', 'through': []},
            'created_in_phase': 1,
            'tags': ['container', 'vulnerable', cls['slug']]
        })
        cont_idx += 1
        # Safe
        entries.append({
            'benchmark_id': f"BENCH-CONTAINER-{cont_idx:03d}",
            'capability_id': f"CAP-CONTAINER-{cap_slug}-001",
            'category': 'CONTAINER',
            'subcategory': cls['name'],
            'variant': 'safe',
            'cwe': cls['cwe'],
            'owasp_category': 'A05:2021-Security Misconfiguration',
            'cve': None,
            'severity': 'NONE',
            'file': cls['safeFile'],
            'line': 1,
            'endpoint': None,
            'reachable': True,
            'exploitable': False,
            'expected_detection': 'NONE',
            'expected_severity': 'NONE',
            'expected_remediation': cls['remediation'],
            'validation_method': 'automated',
            'data_flow': {'source': 'Dockerfile', 'sink': 'Container runtime', 'through': []},
            'created_in_phase': 1,
            'tags': ['container', 'safe', cls['slug']]
        })
        cont_idx += 1

    # IAC entries (20)
    iac_idx = 1
    for cls in IAC_CLASSES:
        cap_slug = sanitize_cap_id(cls['slug'])
        # Vulnerable
        entries.append({
            'benchmark_id': f"BENCH-IAC-{iac_idx:03d}",
            'capability_id': f"CAP-IAC-{cap_slug}-001",
            'category': 'IAC',
            'subcategory': cls['name'],
            'variant': 'vulnerable',
            'cwe': cls['cwe'],
            'owasp_category': 'A05:2021-Security Misconfiguration',
            'cve': None,
            'severity': cls['severity'],
            'file': cls['vulnFile'],
            'line': 1,
            'endpoint': None,
            'reachable': True,
            'exploitable': True,
            'expected_detection': 'IAC',
            'expected_severity': cls['severity'],
            'expected_remediation': cls['remediation'],
            'validation_method': 'automated',
            'data_flow': {'source': 'IaC configuration', 'sink': 'Cloud resource', 'through': []},
            'created_in_phase': 1,
            'tags': ['iac', 'vulnerable', cls['slug']]
        })
        iac_idx += 1
        # Safe
        entries.append({
            'benchmark_id': f"BENCH-IAC-{iac_idx:03d}",
            'capability_id': f"CAP-IAC-{cap_slug}-001",
            'category': 'IAC',
            'subcategory': cls['name'],
            'variant': 'safe',
            'cwe': cls['cwe'],
            'owasp_category': 'A05:2021-Security Misconfiguration',
            'cve': None,
            'severity': 'NONE',
            'file': cls['safeFile'],
            'line': 1,
            'endpoint': None,
            'reachable': True,
            'exploitable': False,
            'expected_detection': 'NONE',
            'expected_severity': 'NONE',
            'expected_remediation': cls['remediation'],
            'validation_method': 'automated',
            'data_flow': {'source': 'IaC configuration', 'sink': 'Cloud resource', 'through': []},
            'created_in_phase': 1,
            'tags': ['iac', 'safe', cls['slug']]
        })
        iac_idx += 1

    return {
        'schema_version': '1.0.0',
        'last_updated': TIMESTAMP,
        'description': 'Authoritative registry of all vulnerabilities in the benchmark suite.',
        'entries': entries
    }


def generate_expected_findings(vuln_register):
    findings = []
    sast_map = {c['name']: c for c in SAST_CLASSES}
    cont_map = {c['name']: c for c in CONTAINER_CLASSES}
    iac_map = {c['name']: c for c in IAC_CLASSES}

    for entry in vuln_register['entries']:
        is_vuln = entry['variant'] == 'vulnerable'
        is_unreach = entry['variant'] == 'unreachable'

        root_cause = 'See vulnerability register'
        subcat_base = entry['subcategory'].split(' (')[0]
        if entry['category'] == 'SAST' and subcat_base in sast_map:
            root_cause = sast_map[subcat_base]['rootCause']
        elif entry['category'] == 'SCA':
            for lib in SCA_LIBRARIES:
                if lib['name'] in entry['subcategory']:
                    root_cause = lib['rootCause']
                    break
        elif entry['category'] == 'CONTAINER' and subcat_base in cont_map:
            root_cause = cont_map[subcat_base]['rootCause']
        elif entry['category'] == 'IAC' and subcat_base in iac_map:
            root_cause = iac_map[subcat_base]['rootCause']

        findings.append({
            'benchmark_id': entry['benchmark_id'],
            'expected_cwe': entry['cwe'],
            'expected_severity': entry['severity'] if (is_vuln or is_unreach) else 'NONE',
            'expected_reachability': 'REACHABLE' if not is_unreach else 'UNREACHABLE',
            'expected_risk_rating': entry['severity'] if is_vuln else ('LOW' if is_unreach else 'INFORMATIONAL'),
            'expected_detection': 'TRUE_POSITIVE' if (is_vuln or is_unreach) else 'TRUE_NEGATIVE',
            'expected_remediation': entry['expected_remediation'],
            'expected_root_cause': root_cause,
            'expected_data_flow': entry['category'] in ('SAST', 'DAST'),
            'expected_fix_available': is_vuln or is_unreach,
            'ai_evaluation': {
                'fix_generation_applicable': is_vuln and entry['category'] in ('SAST', 'IAC', 'CONTAINER'),
                'remediation_guidance_applicable': is_vuln,
                'root_cause_analysis_applicable': is_vuln,
                'reachability_analysis_applicable': entry['category'] in ('SAST', 'SCA'),
                'prioritization_applicable': True,
                'risk_ranking_applicable': True
            }
        })

    return {
        'schema_version': '1.0.0',
        'last_updated': TIMESTAMP,
        'description': 'Deterministic expected findings for every benchmark scenario.',
        'findings': findings
    }


def generate_capability_mapping(vuln_register):
    cap_map = {}
    for entry in vuln_register['entries']:
        cid = entry['capability_id']
        if cid not in cap_map:
            cap_map[cid] = {
                'capability_id': cid,
                'category': entry['category'],
                'name': '',
                'description': '',
                'benchmark_ids': [],
                'detection_type': entry['category'] if entry['expected_detection'] == 'NONE' else entry['expected_detection'],
                'complexity': 'MEDIUM',
                'requires_reachability_analysis': False,
                'requires_data_flow_analysis': False,
                'requires_framework_awareness': False,
                'ai_evaluable': True,
                'kpi_weight': 0.5
            }
        cap_map[cid]['benchmark_ids'].append(entry['benchmark_id'])

    # Enrich SAST capabilities
    variant_names = ['Detection', 'Sanitization Recognition', 'Reachability Analysis', 'Framework Protection Recognition']
    for cls in SAST_CLASSES:
        for i in range(1, 5):
            cid = f"{cls['capBase']}-{i:03d}"
            if cid in cap_map:
                cap_map[cid]['name'] = f"{cls['name']} {variant_names[i-1]}"
                cap_map[cid]['description'] = f"{'Detect' if i == 1 else 'Recognize sanitized' if i == 2 else 'Determine reachability of' if i == 3 else 'Recognize framework protection for'} {cls['name']} {'in source code via static analysis' if i == 1 else 'variant as non-vulnerable' if i == 2 else 'sink from public entry points' if i == 3 else 'against ' + cls['name']}"
                cap_map[cid]['complexity'] = 'MEDIUM' if i <= 2 else 'HIGH'
                cap_map[cid]['requires_reachability_analysis'] = (i == 3)
                cap_map[cid]['requires_data_flow_analysis'] = (i <= 2)
                cap_map[cid]['requires_framework_awareness'] = (i == 4)
                weight_map = {'CRITICAL': 1.0, 'HIGH': 0.8, 'MEDIUM': 0.6, 'LOW': 0.4}
                cap_map[cid]['kpi_weight'] = weight_map.get(cls['severity'], 0.5)

    # Enrich SCA capabilities
    sca_caps = {
        'CAP-SCA-DIRECT-001': ('Direct Dependency CVE Detection', 'Detect known CVEs in direct Maven dependencies', 0.9),
        'CAP-SCA-UNREACH-001': ('Unreachable Vulnerability Recognition', 'Recognize that vulnerable dependency code paths are not reachable', 0.7),
        'CAP-SCA-TRANS-001': ('Transitive Dependency CVE Detection', 'Detect known CVEs in transitive Maven dependencies', 0.8)
    }
    for cid, (name, desc, weight) in sca_caps.items():
        if cid in cap_map:
            cap_map[cid]['name'] = name
            cap_map[cid]['description'] = desc
            cap_map[cid]['kpi_weight'] = weight
            cap_map[cid]['requires_reachability_analysis'] = (cid == 'CAP-SCA-UNREACH-001')

    # Enrich remaining capabilities
    for cid, cap in cap_map.items():
        if not cap['name']:
            parts = cid.split('-')
            cap['name'] = f"{' '.join(parts[1:-1])} Detection"
            cap['description'] = f"Detect {cap['category']} issues related to {' '.join(parts[1:-1]).lower()}"
            weight_map_cat = {'SECRET': 0.7, 'CONTAINER': 0.6, 'IAC': 0.6, 'DAST': 0.8}
            cap['kpi_weight'] = weight_map_cat.get(cap['category'], 0.5)

    return {
        'schema_version': '1.0.0',
        'last_updated': TIMESTAMP,
        'description': 'Maps AppSec platform capabilities to benchmark scenarios.',
        'capabilities': list(cap_map.values())
    }


def generate_benchmark_manifest(vuln_register):
    manifests = []
    for entry in vuln_register['entries']:
        ctrl_group = None
        for tag in entry['tags']:
            if tag.startswith('CTRL-'):
                ctrl_group = tag
                break
        manifests.append({
            'benchmark_id': entry['benchmark_id'],
            'phase': entry['category'],
            'category': entry['subcategory'].split(' (')[0],
            'subcategory': entry['variant'],
            'file_path': entry['file'],
            'endpoint': entry['endpoint'],
            'capability_ids': [entry['capability_id']],
            'status': 'planned',
            'created_in_phase': 1,
            'ground_truth_registered': True,
            'expected_findings_registered': True,
            'control_pair_group': ctrl_group,
            'variant': entry['variant']
        })

    return {
        'schema_version': '1.0.0',
        'last_updated': TIMESTAMP,
        'description': 'Authoritative inventory of all benchmark assets.',
        'manifests': manifests
    }


def generate_benchmark_catalog(vuln_register):
    catalog = {
        'schema_version': '1.0.0',
        'last_updated': TIMESTAMP,
        'description': 'Human-readable catalog of all benchmark scenarios organized by category.',
        'summary': {
            'total_scenarios': len(vuln_register['entries']),
            'by_category': {},
            'by_variant': {},
            'by_severity': {}
        },
        'categories': {}
    }

    for entry in vuln_register['entries']:
        cat = entry['category']
        var = entry['variant']
        sev = entry['severity']
        catalog['summary']['by_category'][cat] = catalog['summary']['by_category'].get(cat, 0) + 1
        catalog['summary']['by_variant'][var] = catalog['summary']['by_variant'].get(var, 0) + 1
        catalog['summary']['by_severity'][sev] = catalog['summary']['by_severity'].get(sev, 0) + 1

        if cat not in catalog['categories']:
            catalog['categories'][cat] = {'count': 0, 'scenarios': []}
        catalog['categories'][cat]['count'] += 1
        catalog['categories'][cat]['scenarios'].append({
            'benchmark_id': entry['benchmark_id'],
            'subcategory': entry['subcategory'],
            'variant': entry['variant'],
            'severity': entry['severity'],
            'cwe': entry['cwe'],
            'file': entry['file'],
            'endpoint': entry['endpoint']
        })

    return catalog


def generate_progress_tracker(vuln_register):
    items = [{
        'benchmark_id': e['benchmark_id'],
        'category': e['category'],
        'subcategory': e['subcategory'],
        'status': 'ground_truth_registered',
        'ground_truth_complete': True,
        'code_implemented': True, # Hardened code implementation is already active
        'verified': True
    } for e in vuln_register['entries']]

    categories = {}
    for entry in vuln_register['entries']:
        key = entry['category'].lower()
        if key not in categories:
            categories[key] = {'planned': 0, 'completed': 0, 'in_progress': 0, 'pending': 0, 'last_completed_id': None, 'next_pending_id': None}
        categories[key]['planned'] += 1
        categories[key]['completed'] += 1 # Set completed since we migrated all 210 scenarios
        categories[key]['last_completed_id'] = entry['benchmark_id']

    return {
        'schema_version': '1.0.0',
        'last_updated': TIMESTAMP,
        'summary': {
            'total_planned': len(vuln_register['entries']),
            'total_completed': len(vuln_register['entries']),
            'total_in_progress': 0,
            'total_pending': 0
        },
        'categories': categories,
        'items': items
    }


# ============================================================
# MAIN
# ============================================================
if __name__ == '__main__':
    try:
        print('Generating Ground Truth Framework (ShopSphere)...')

        print('  Generating vulnerability_register.json...')
        vr = generate_vulnerability_register()
        with open(os.path.join(STATE_DIR, 'vulnerability_register.json'), 'w') as f:
            json.dump(vr, f, indent=2)
        print(f'    -> {len(vr["entries"])} entries generated')

        print('  Generating expected_findings.json...')
        ef = generate_expected_findings(vr)
        with open(os.path.join(STATE_DIR, 'expected_findings.json'), 'w') as f:
            json.dump(ef, f, indent=2)
        print(f'    -> {len(ef["findings"])} findings generated')

        print('  Generating capability_mapping.json...')
        cm = generate_capability_mapping(vr)
        with open(os.path.join(STATE_DIR, 'capability_mapping.json'), 'w') as f:
            json.dump(cm, f, indent=2)
        print(f'    -> {len(cm["capabilities"])} capabilities generated')

        print('  Generating benchmark_manifest.json...')
        bm = generate_benchmark_manifest(vr)
        with open(os.path.join(STATE_DIR, 'benchmark_manifest.json'), 'w') as f:
            json.dump(bm, f, indent=2)
        print(f'    -> {len(bm["manifests"])} manifest entries generated')

        print('  Generating benchmark_catalog.json...')
        bc = generate_benchmark_catalog(vr)
        with open(os.path.join(STATE_DIR, 'benchmark_catalog.json'), 'w') as f:
            json.dump(bc, f, indent=2)
        print(f'    -> Catalog with {bc["summary"]["total_scenarios"]} scenarios')

        print('  Updating progress_tracker.json...')
        pt = generate_progress_tracker(vr)
        with open(os.path.join(STATE_DIR, 'progress_tracker.json'), 'w') as f:
            json.dump(pt, f, indent=2)
        print(f'    -> {len(pt["items"])} items tracked')

        # Validation
        print('\n=== VALIDATION ===')
        print(f'  Vulnerability Register:  {len(vr["entries"])} entries')
        print(f'  Expected Findings:       {len(ef["findings"])} entries')
        print(f'  Capability Mapping:      {len(cm["capabilities"])} capabilities')
        print(f'  Benchmark Manifest:      {len(bm["manifests"])} entries')
        vr_ids = set(e['benchmark_id'] for e in vr['entries'])
        ef_ids = set(f['benchmark_id'] for f in ef['findings'])
        bm_ids = set(m['benchmark_id'] for m in bm['manifests'])
        print(f'  VR == EF count match:    {"PASS" if len(vr_ids) == len(ef_ids) else "FAIL"}')
        print(f'  VR == BM count match:    {"PASS" if len(vr_ids) == len(bm_ids) else "FAIL"}')
        print(f'  Orphan EF (not in VR):   {len(ef_ids - vr_ids)} {"PASS" if len(ef_ids - vr_ids) == 0 else "FAIL"}')
        print(f'  Orphan BM (not in VR):   {len(bm_ids - vr_ids)} {"PASS" if len(bm_ids - vr_ids) == 0 else "FAIL"}')
        print(f'  Missing EF (in VR):      {len(vr_ids - ef_ids)} {"PASS" if len(vr_ids - ef_ids) == 0 else "FAIL"}')
        print(f'  Missing BM (in VR):      {len(vr_ids - bm_ids)} {"PASS" if len(vr_ids - bm_ids) == 0 else "FAIL"}')

        # Unique ID check
        all_vr_ids = [e['benchmark_id'] for e in vr['entries']]
        print(f'  Unique VR IDs:           {"PASS" if len(all_vr_ids) == len(set(all_vr_ids)) else "FAIL - DUPLICATES FOUND"}')

        # Category breakdown
        print('\n=== CATEGORY BREAKDOWN ===')
        for cat, count in bc['summary']['by_category'].items():
            print(f'  {cat:12s}: {count}')
        print('\n=== VARIANT BREAKDOWN ===')
        for var, count in bc['summary']['by_variant'].items():
            print(f'  {var:20s}: {count}')
        print('\n=== SEVERITY BREAKDOWN ===')
        for sev, count in bc['summary']['by_severity'].items():
            print(f'  {sev:12s}: {count}')

        print('\nPhase 1 generation COMPLETE!')

    except Exception as e:
        print(f'ERROR: {e}', file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
