"""Seed Hunter's passive fingerprint and memory knowledge base.

The data in this module is intentionally importable by the memory engines.
Running the module populates the SQLite-backed memories through their public
APIs; it never opens or edits the database directly.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

DEFAULT_DATABASE = Path(r"D:\Open-tgtylab\data\targets.db")


def _cms(
    name: str,
    paths: Iterable[str],
    cookie: str,
    meta: str,
    header: str,
    category: str,
) -> dict[str, Any]:
    return {
        "name": name,
        "paths": list(paths),
        "cookies": [cookie],
        "meta": [meta],
        "headers": [header],
        "category": category,
    }


def _edu_system(
    name: str,
    *,
    category: str,
    paths: Iterable[str],
    headers: Iterable[str] = (),
    absent_headers: Iterable[str] = (),
    cookies: Iterable[str] = (),
    body: Iterable[str] = (),
    hosts: Iterable[str] = (),
    login_features: Iterable[str] = (),
    auth: str = "",
    endpoints: Iterable[str] = (),
    minimum_evidence: int = 2,
    allow_weak_cookies: bool = False,
) -> dict[str, Any]:
    return {
        "name": name,
        "category": category,
        "headers": list(headers),
        "absent_headers": list(absent_headers),
        "cookies": list(cookies),
        "body": list(body),
        "paths": list(paths),
        "hosts": list(hosts),
        "login_features": list(login_features),
        "auth": auth,
        "endpoints": list(endpoints),
        "minimum_evidence": int(minimum_evidence),
        "allow_weak_cookies": bool(allow_weak_cookies),
    }


def _framework(
    name: str,
    headers: Iterable[str],
    cookies: Iterable[str],
    paths: Iterable[str],
    category: str,
) -> dict[str, Any]:
    return {
        "name": name,
        "headers": list(headers),
        "cookies": list(cookies),
        "paths": list(paths),
        "category": category,
    }


def _stack(
    stack_pattern: str,
    common_issues: Iterable[str],
    assessment_focus: Iterable[str],
) -> dict[str, Any]:
    return {
        "stack_pattern": stack_pattern,
        "tech_stack_pattern": stack_pattern,
        "common_issues": list(common_issues),
        "assessment_focus": list(assessment_focus),
    }


def _parameter(
    param_pattern: str,
    related_issue_type: str,
    confidence: float,
) -> dict[str, Any]:
    return {
        "param_pattern": param_pattern,
        "related_issue_type": related_issue_type,
        "confidence": float(confidence),
    }


# The CMS list deliberately includes products from portals, education,
# content, commerce, office, community, and developer-collaboration systems.
CMS_SEEDS = [
    _cms("WordPress", ("/wp-admin/", "/wp-content/"), "wordpress_logged_in_", "wordpress", "X-Generator: WordPress", "portal"),
    _cms("Joomla", ("/administrator/", "/media/system/"), "joomla_user_state", "joomla", "X-Content-Encoded-By: Joomla", "portal"),
    _cms("Drupal", ("/core/misc/drupal.js", "/sites/default/"), "SESS", "Drupal", "X-Generator: Drupal", "portal"),
    _cms("TYPO3", ("/typo3/", "/typo3conf/"), "fe_typo_user", "TYPO3", "X-TYPO3-Parsetime", "portal"),
    _cms("Ghost", ("/ghost/", "/assets/ghost/"), "ghost-admin-api-session", "Ghost", "X-Ghost-Version", "content"),
    _cms("Strapi", ("/admin/", "/api/"), "strapi_jwt", "Strapi", "X-Powered-By: Strapi", "content"),
    _cms("Umbraco", ("/umbraco/", "/App_Plugins/"), "UMB_UCONTEXT", "Umbraco", "X-Generator: Umbraco", "portal"),
    _cms("Kentico", ("/cmsdesk/", "/CMSPages/"), "CMSPreferredCulture", "Kentico", "X-Kentico", "portal"),
    _cms("Sitecore", ("/sitecore/", "/layouts/"), "sc_mode", "Sitecore", "X-Sitecore", "portal"),
    _cms("DNN", ("/DesktopModules/", "/Portals/"), "dnn_IsMobile", "DotNetNuke", "X-DNN", "portal"),
    _cms("Concrete CMS", ("/concrete/", "/application/"), "ccm_token", "concrete5", "X-Generator: concrete", "portal"),
    _cms("Craft CMS", ("/admin/", "/cpresources/"), "CraftSessionId", "Craft CMS", "X-Craft-Version", "content"),
    _cms("OctoberCMS", ("/modules/system/", "/storage/framework/"), "october_session", "OctoberCMS", "X-October-Version", "content"),
    _cms("SilverStripe", ("/framework/", "/cms/"), "PastMember", "SilverStripe", "X-Silverstripe", "portal"),
    _cms("Moodle", ("/login/index.php", "/lib/javascript.php"), "MoodleSession", "Moodle", "X-Moodle", "education"),
    _cms("Chamilo", ("/main/", "/plugin/"), "ch_sid", "Chamilo", "X-Chamilo", "education"),
    _cms("Open edX", ("/course/", "/static/edx/"), "sessionid", "edX", "X-Edx", "education"),
    _cms("Canvas LMS", ("/courses/", "/api/v1/"), "_canvas_session", "Canvas LMS", "X-Canvas", "education"),
    _cms("Sakai", ("/portal/", "/direct/"), "JSESSIONID", "Sakai", "X-Sakai", "education"),
    _cms("Totara", ("/totara/", "/theme/"), "TotaraSession", "Totara", "X-Totara", "education"),
    _cms("ILIAS", ("/ilias.php", "/Services/"), "ilClientId", "ILIAS", "X-ILIAS", "education"),
    _cms("Blackboard Learn", ("/webapps/", "/ultra/"), "JSESSIONID", "Blackboard", "X-Blackboard", "education"),
    _cms("MediaWiki", ("/w/load.php", "/wiki/"), "centralauth_User", "MediaWiki", "X-Generator: MediaWiki", "content"),
    _cms("Contentful", ("/spaces/", "/content/v1/"), "contentful_session", "Contentful", "X-Contentful-Version", "content"),
    _cms("Sanity", ("/studio/", "/v2023-05-03/"), "sanityUser", "Sanity", "X-Sanity-Project", "content"),
    _cms("Directus", ("/admin/", "/items/"), "directus_session", "Directus", "X-Directus-Version", "content"),
    _cms("Payload CMS", ("/admin/", "/api/"), "payload-token", "Payload", "X-Powered-By: Payload", "content"),
    _cms("Pimcore", ("/admin/", "/bundles/"), "pimcore_admin_sid", "Pimcore", "X-Pimcore", "content"),
    _cms("Grav", ("/user/", "/system/"), "grav-site", "Grav", "X-Grav", "content"),
    _cms("Kirby", ("/panel/", "/media/"), "kirby_session", "Kirby", "X-Kirby", "content"),
    _cms("Contao", ("/contao/", "/assets/"), "BE_USER_AUTH", "Contao", "X-Contao", "content"),
    _cms("Bolt CMS", ("/bolt/", "/theme/"), "bolt_session", "Bolt", "X-Bolt", "content"),
    _cms("MODX", ("/manager/", "/assets/components/"), "SN4", "MODX", "X-Powered-By: MODX", "content"),
    _cms("ExpressionEngine", ("/admin.php", "/system/"), "exp_tracker", "ExpressionEngine", "X-ExpressionEngine", "content"),
    _cms("Plone", ("/@@search", "/portal_css/"), "__ac", "Plone", "X-Plone", "portal"),
    _cms("Orchard Core", ("/admin/", "/TheAdmin/"), "OrchardCore", "Orchard Core", "X-OrchardCore", "portal"),
    _cms("Textpattern", ("/textpattern/", "/rpc/"), "txp_login", "Textpattern", "X-Textpattern", "content"),
    _cms("Pico CMS", ("/config/", "/themes/"), "pico_session", "Pico CMS", "X-Pico", "content"),
    _cms("ProcessWire", ("/processwire/", "/site/assets/"), "wire_challenge", "ProcessWire", "X-Powered-By: ProcessWire", "content"),
    _cms("Backdrop CMS", ("/core/", "/files/"), "SESS", "Backdrop", "X-Generator: Backdrop", "content"),
    _cms("Microweber", ("/admin/", "/userfiles/"), "mw_session", "Microweber", "X-Microweber", "content"),
    _cms("Liferay", ("/c/portal/", "/o/"), "JSESSIONID", "Liferay", "X-Liferay", "office"),
    _cms("Jekyll", ("/assets/", "/feed.xml"), "jekyll_session", "Jekyll", "X-Jekyll", "content"),
    _cms("Hugo", ("/index.xml", "/css/"), "hugo_session", "Hugo", "X-Hugo", "content"),
    _cms("Webflow", ("/cdn-cgi/", "/css/"), "wf_session", "Webflow", "X-Webflow", "portal"),
    _cms("Wix", ("/_api/wix/", "/wixstatic/"), "wix_session", "Wix", "X-Wix-Request-Id", "portal"),
    _cms("Squarespace", ("/config/", "/api/1/"), "ss_cvr", "Squarespace", "X-Squarespace", "portal"),
    _cms("Shopify", ("/cdn/shop/", "/cart.js"), "_shopify_y", "Shopify", "X-Shopify-Stage", "commerce"),
    _cms("Magento", ("/static/version", "/customer/account"), "PHPSESSID", "Magento", "X-Magento-Cache-Debug", "commerce"),
    _cms("PrestaShop", ("/modules/", "/themes/"), "PrestaShop-", "PrestaShop", "X-Powered-By: PrestaShop", "commerce"),
    _cms("WooCommerce", ("/wp-content/plugins/woocommerce/", "/wc-api/"), "woocommerce_cart_hash", "WooCommerce", "X-WC-Store", "commerce"),
    _cms("OpenCart", ("/catalog/view/", "/index.php?route="), "OCSESSID", "OpenCart", "X-OpenCart", "commerce"),
    _cms("osCommerce", ("/includes/", "/admin/"), "osCsid", "osCommerce", "X-osCommerce", "commerce"),
    _cms("Zen Cart", ("/includes/templates/", "/index.php?main_page="), "zenid", "Zen Cart", "X-Zen-Cart", "commerce"),
    _cms("Shopware", ("/theme/", "/store-api/"), "session-", "Shopware", "X-Shopware-Cache-Id", "commerce"),
    _cms("BigCommerce", ("/stencil-utils/", "/api/storefront/"), "SHOP_SESSION_TOKEN", "BigCommerce", "X-BigCommerce", "commerce"),
    _cms("Saleor", ("/graphql/", "/dashboard/"), "saleorToken", "Saleor", "X-Saleor", "commerce"),
    _cms("Sylius", ("/bundles/", "/admin/"), "PHPSESSID", "Sylius", "X-Sylius", "commerce"),
    _cms("nopCommerce", ("/Admin/", "/Plugins/"), "Nop.customer", "nopCommerce", "X-NopCommerce", "commerce"),
    _cms("Ecwid", ("/assets/ecwid/", "/api/v3/"), "ecwid_session", "Ecwid", "X-Ecwid", "commerce"),
    _cms("Spree Commerce", ("/spree/", "/api/v2/storefront/"), "spree_session", "Spree", "X-Spree", "commerce"),
    _cms("phpBB", ("/styles/", "/ucp.php"), "phpbb3_", "phpBB", "X-phpBB", "community"),
    _cms("vBulletin", ("/forum/", "/includes/"), "bb_sessionhash", "vBulletin", "X-vBulletin", "community"),
    _cms("MyBB", ("/inc/", "/forumdisplay.php"), "mybb[lastvisit]", "MyBB", "X-MyBB", "community"),
    _cms("Discourse", ("/assets/discourse/", "/session/csrf"), "_forum_session", "Discourse", "X-Discourse-Route", "community"),
    _cms("Flarum", ("/forum/", "/api/"), "flarum_session", "Flarum", "X-Flarum", "community"),
    _cms("XenForo", ("/index.php?forums/", "/styles/"), "xf_session", "XenForo", "X-XenForo", "community"),
    _cms("NodeBB", ("/assets/nodebb.min.js", "/api/"), "express.sid", "NodeBB", "X-Powered-By: NodeBB", "community"),
    _cms("Vanilla Forums", ("/dashboard/", "/applications/"), "vanilla_session", "Vanilla Forums", "X-Vanilla", "community"),
    _cms("GitLab", ("/users/sign_in", "/assets/webpack/"), "_gitlab_session", "GitLab", "X-GitLab-Meta", "collaboration"),
    _cms("Gitea", ("/user/login", "/assets/"), "i_like_gitea", "Gitea", "X-Gitea-Version", "collaboration"),
    _cms("Forgejo", ("/user/login", "/assets/"), "i_like_forgejo", "Forgejo", "X-Forgejo-Version", "collaboration"),
    _cms("Bitbucket", ("/plugins/servlet/", "/rest/api/"), "BITBUCKETSESSIONID", "Bitbucket", "X-AUSERNAME", "collaboration"),
    _cms("Phabricator", ("/phabricator/", "/conduit/"), "phsid", "Phabricator", "X-Phabricator", "collaboration"),
    _cms("Redmine", ("/my/page", "/projects/"), "_redmine_session", "Redmine", "X-Redmine", "collaboration"),
    _cms("Jira", ("/secure/", "/rest/api/2/"), "JSESSIONID", "Jira", "X-AREQUESTID", "collaboration"),
    _cms("Jenkins", ("/login", "/static/"), "JSESSIONID", "Jenkins", "X-Jenkins", "collaboration"),
    _cms("SharePoint", ("/sites/", "/_layouts/"), "FedAuth", "SharePoint", "MicrosoftSharePointTeamServices", "office"),
    _cms("Alfresco", ("/share/page/", "/alfresco/"), "alfLogin", "Alfresco", "X-Alfresco", "office"),
    _cms("Nextcloud", ("/index.php/login", "/remote.php/dav/"), "oc_sessionPassphrase", "Nextcloud", "X-Nextcloud-Request-Id", "office"),
    _cms("ownCloud", ("/index.php/login", "/remote.php/webdav/"), "oc_sessionPassphrase", "ownCloud", "X-ownCloud", "office"),
    _cms("Odoo", ("/web/login", "/web/assets/"), "session_id", "Odoo", "X-Odoo", "office"),
    _cms("ERPNext", ("/app/login", "/api/method/"), "sid", "Frappe", "X-Frappe-Site-Name", "office"),
    _cms("ONLYOFFICE", ("/web-apps/", "/coauthoring/"), "asc_auth_key", "ONLYOFFICE", "X-Onlyoffice", "office"),
    _cms("SugarCRM", ("/index.php?module=Users", "/include/"), "PHPSESSID", "SugarCRM", "X-Sugar-Version", "office"),
    _cms("SuiteCRM", ("/index.php?module=Users", "/legacy/"), "PHPSESSID", "SuiteCRM", "X-SuiteCRM", "office"),
]


EDU_SYSTEM_SEEDS = [
    _edu_system(
        "正方教务管理系统",
        category="teaching-management",
        paths=("/jwglxt/", "/xtgl/login_slogin.html"),
        headers=("JSESSIONID",),
        body=("正方教务管理系统",),
        login_features=("登录页标题: 正方教务管理系统",),
        auth="local account or campus SSO",
        endpoints=("/jwglxt/", "/xtgl/login_slogin.html"),
    ),
    _edu_system(
        "强智教务管理系统",
        category="teaching-management",
        paths=("/jsxsd/", "/jsxsdxx/"),
        cookies=("JSESSIONID",),
        body=("强智科技",),
        login_features=("登录页包含: 强智科技",),
        auth="Java session with optional campus SSO",
        endpoints=("/jsxsd/", "/jsxsdxx/"),
        allow_weak_cookies=True,
    ),
    _edu_system(
        "青果教务管理系统",
        category="teaching-management",
        paths=("/kingosoft/",),
        headers=("KINGOSOFT",),
        body=("青果教务管理系统", "kingosoft"),
        login_features=("产品标识: KINGOSOFT",),
        auth="local account or campus SSO",
        endpoints=("/kingosoft/",),
    ),
    _edu_system(
        "金智 CAS",
        category="identity",
        paths=("/lyuapServer/login",),
        absent_headers=("server",),
        body=("统一身份认证平台", 'name="service"'),
        login_features=(
            "CAS service 参数发起 SSO",
            "Server 响应头通常被隐藏",
        ),
        auth="CAS ticket and TGC",
        endpoints=("/lyuapServer/login",),
        minimum_evidence=3,
    ),
    _edu_system(
        "艾卡 CAS",
        category="identity",
        paths=("/authserver/login",),
        headers=("Apereo CAS",),
        cookies=("TGC",),
        body=("authserver",),
        login_features=("Apereo CAS 响应标识",),
        auth="CAS ticket and TGC",
        endpoints=("/authserver/login",),
    ),
    _edu_system(
        "正方统一身份认证",
        category="identity",
        paths=("/zfcas/",),
        headers=("JSESSIONID",),
        body=("正方软件", "zfcas"),
        login_features=("登录页标题包含: 正方软件",),
        auth="CAS/SSO session",
        endpoints=("/zfcas/",),
    ),
    _edu_system(
        "博达 CMS/VSB Portal",
        category="portal",
        paths=("/system/",),
        headers=("X-Protected-By: WebberRASP",),
        body=("Announced by Visual SiteBuilder",),
        login_features=("Visual SiteBuilder footer",),
        auth="Java session with optional campus SSO",
        endpoints=("/system/",),
    ),
    _edu_system(
        "超星智慧门户",
        category="portal",
        paths=(),
        headers=("Location: passport2.chaoxing.com",),
        body=("chaoxing.com",),
        hosts=("lib.*.edu.cn",),
        login_features=("跳转 passport2.chaoxing.com 登录",),
        auth="Chaoxing Passport SSO",
        endpoints=("https://passport2.chaoxing.com/",),
    ),
]


FRAMEWORK_SEEDS = [
    _framework("Spring Boot", ("X-Application-Context",), ("JSESSIONID",), ("/actuator/", "/swagger-ui/"), "java"),
    _framework("Spring MVC", ("X-Spring-MVC",), ("JSESSIONID",), ("/WEB-INF/",), "java"),
    _framework("Struts", ("X-Powered-By: Struts",), ("JSESSIONID",), ("/struts/",), "java"),
    _framework("JSF", ("javax.faces.ViewState",), ("JSESSIONID",), ("/javax.faces.resource/",), "java"),
    _framework("Jakarta EE", ("X-Jakarta-EE",), ("JSESSIONID",), ("/WEB-INF/",), "java"),
    _framework("Tomcat", ("Server: Apache-Coyote",), ("JSESSIONID",), ("/manager/html",), "java"),
    _framework("Jetty", ("Server: Jetty",), ("JSESSIONID",), ("/j_security_check",), "java"),
    _framework("Play Framework", ("X-Play-Framework",), ("PLAY_SESSION",), ("/assets/",), "java"),
    _framework("Grails", ("X-Grails-Version",), ("JSESSIONID",), ("/static/",), "java"),
    _framework("Django", ("X-Django-Version",), ("sessionid", "csrftoken"), ("/static/admin/",), "python"),
    _framework("Flask", ("Server: Werkzeug",), ("session",), ("/static/",), "python"),
    _framework("FastAPI", ("X-FastAPI",), ("session",), ("/docs", "/openapi.json"), "python"),
    _framework("Tornado", ("Server: TornadoServer",), ("_xsrf",), ("/static/",), "python"),
    _framework("Pyramid", ("X-Pyramid",), ("session",), ("/_debug_toolbar/",), "python"),
    _framework("Bottle", ("X-Powered-By: Bottle",), ("beaker.session.id",), ("/static/",), "python"),
    _framework("Sanic", ("X-Sanic",), ("session",), ("/static/",), "python"),
    _framework("Falcon", ("X-Falcon",), ("session",), ("/docs/",), "python"),
    _framework("Laravel", ("X-Laravel",), ("laravel_session",), ("/storage/",), "php"),
    _framework("Symfony", ("X-Symfony-Cache",), ("sf_redirect",), ("/bundles/",), "php"),
    _framework("CodeIgniter", ("X-Powered-By: CodeIgniter",), ("ci_session",), ("/system/",), "php"),
    _framework("Yii", ("X-Yii-Version",), ("_csrf",), ("/assets/",), "php"),
    _framework("CakePHP", ("X-CakePHP",), ("CAKEPHP",), ("/files/",), "php"),
    _framework("Slim", ("X-Powered-By: Slim",), ("slim_session",), ("/vendor/",), "php"),
    _framework("Phalcon", ("X-Phalcon",), ("phalcon_session",), ("/phalcon/",), "php"),
    _framework("Fat-Free", ("X-F3-Version",), ("f3_session",), ("/ui/",), "php"),
    _framework("Express", ("X-Powered-By: Express",), ("connect.sid",), ("/socket.io/",), "node"),
    _framework("NestJS", ("X-Powered-By: NestJS",), ("connect.sid",), ("/swagger/",), "node"),
    _framework("Koa", ("X-Powered-By: koa",), ("koa:sess",), ("/koa/",), "node"),
    _framework("Hapi", ("X-Powered-By: hapi",), ("hapi-session",), ("/documentation/",), "node"),
    _framework("Fastify", ("X-Powered-By: Fastify",), ("fastify-session",), ("/documentation/",), "node"),
    _framework("AdonisJS", ("X-Powered-By: AdonisJS",), ("adonis-session",), ("/adonisjs/",), "node"),
    _framework("Next.js", ("X-Powered-By: Next.js",), ("next-auth.session-token",), ("/_next/static/",), "node"),
    _framework("Nuxt", ("X-Powered-By: Nuxt",), ("nuxt_session",), ("/_nuxt/",), "node"),
    _framework("Remix", ("X-Remix-Route",), ("__session",), ("/build/",), "node"),
    _framework("SvelteKit", ("X-SvelteKit-Page",), ("session",), ("/_app/immutable/",), "node"),
    _framework("Meteor", ("X-Meteor-Route",), ("meteor_session",), ("/packages/",), "node"),
    _framework("Gin", ("X-Powered-By: Gin",), ("gin_session",), ("/debug/pprof/",), "go"),
    _framework("Echo", ("X-Powered-By: Echo",), ("echo_session",), ("/debug/pprof/",), "go"),
    _framework("Fiber", ("X-Powered-By: Fiber",), ("fiber_session",), ("/swagger/",), "go"),
    _framework("Beego", ("X-Powered-By: Beego",), ("beegoSessionID",), ("/static/",), "go"),
    _framework("Buffalo", ("X-Powered-By: Buffalo",), ("buffalo_session",), ("/assets/",), "go"),
    _framework("Chi", ("X-Powered-By: chi",), ("chi_session",), ("/debug/",), "go"),
    _framework("Actix Web", ("X-Powered-By: actix-web",), ("actix_session",), ("/static/",), "rust"),
    _framework("Rocket", ("X-Rocket",), ("rocket_session",), ("/static/",), "rust"),
    _framework("React", ("X-React-Version",), ("react_session",), ("/static/js/",), "frontend"),
    _framework("Vue", ("X-Vue-Version",), ("vue_session",), ("/assets/index-",), "frontend"),
    _framework("Angular", ("X-Angular-Version",), ("XSRF-TOKEN",), ("/main.", "/polyfills."), "frontend"),
    _framework("Webpack", ("X-Webpack-Chunk",), ("webpack_session",), ("/static/js/",), "frontend"),
    _framework("Vite", ("X-Vite-Dev-Server",), ("vite_session",), ("/@vite/client",), "frontend"),
    _framework("Gatsby", ("X-Gatsby",), ("gatsby_session",), ("/webpack-runtime",), "frontend"),
    _framework("Astro", ("X-Astro",), ("astro_session",), ("/_astro/",), "frontend"),
    _framework("Alpine.js", ("X-Alpine-Version",), ("alpine_session",), ("/_alpine/",), "frontend"),
]


STACK_SEEDS = [
    _stack("Apache + PHP + MySQL", ("SQL injection", "file inclusion", "unsafe upload"), ("Test PHP upload handlers.", "Check MySQL FILE privilege.")),
    _stack("Apache + PHP + MariaDB", ("SQL injection", "file inclusion"), ("Review PHP include paths.", "Check MariaDB account privileges.")),
    _stack("Apache + PHP + PostgreSQL", ("SQL injection", "command injection"), ("Review PHP database adapters.", "Check PostgreSQL extension exposure.")),
    _stack("Nginx + PHP + MySQL", ("SQL injection", "path traversal"), ("Inspect FastCGI parameter handling.", "Check MySQL FILE privilege.")),
    _stack("Nginx + Laravel + MySQL", ("SQL injection", "mass assignment"), ("Review Laravel debug and queue endpoints.", "Check database query construction.")),
    _stack("Nginx + Symfony + PostgreSQL", ("SQL injection", "SSTI"), ("Review Symfony profiler exposure.", "Inspect Doctrine query boundaries.")),
    _stack("Nginx + Django + PostgreSQL", ("SQL injection", "CSRF", "IDOR"), ("Review admin and debug settings.", "Inspect ORM filters and object authorization.")),
    _stack("Nginx + Django + MySQL", ("SQL injection", "unsafe deserialization"), ("Review debug pages and signed cookies.", "Inspect ORM raw queries.")),
    _stack("Gunicorn + Django + PostgreSQL", ("SSRF", "IDOR"), ("Review reverse-proxy trust settings.", "Test object-level permissions.")),
    _stack("uWSGI + Django + Redis", ("session tampering", "SSRF"), ("Review Redis exposure.", "Inspect signed session configuration.")),
    _stack("Nginx + Flask + PostgreSQL", ("SSTI", "SQL injection"), ("Review Jinja2 templates.", "Inspect raw SQL and debug routes.")),
    _stack("Uvicorn + FastAPI + PostgreSQL", ("SQL injection", "BOLA"), ("Review OpenAPI exposure.", "Inspect dependency authorization.")),
    _stack("Apache + WordPress + MySQL", ("plugin RCE", "SQL injection", "stored XSS"), ("Enumerate plugin and theme versions.", "Review XML-RPC and upload paths.")),
    _stack("Nginx + Drupal + MySQL", ("access control", "unsafe deserialization"), ("Review module versions.", "Inspect render and cache endpoints.")),
    _stack("Nginx + Joomla + MySQL", ("access control", "SQL injection"), ("Review component routes.", "Inspect administrator exposure.")),
    _stack("Apache + Magento + MySQL", ("template injection", "SQL injection"), ("Review admin APIs and import handlers.", "Check cache and payment integrations.")),
    _stack("Nginx + Magento + Elasticsearch", ("SSRF", "data exposure"), ("Review integration endpoints.", "Inspect Elasticsearch access controls.")),
    _stack("Nginx + PrestaShop + MySQL", ("SQL injection", "file upload"), ("Review module endpoints.", "Check back-office exposure.")),
    _stack("Nginx + WooCommerce + MySQL", ("IDOR", "stored XSS"), ("Review order and coupon authorization.", "Inspect extension callbacks.")),
    _stack("Node.js + Express + MongoDB", ("NoSQL injection", "prototype pollution"), ("Test JSON query operators.", "Trace object merge boundaries.")),
    _stack("Node.js + NestJS + PostgreSQL", ("BOLA", "SQL injection"), ("Review guards and decorators.", "Inspect query builder inputs.")),
    _stack("Node.js + Koa + MongoDB", ("NoSQL injection", "SSRF"), ("Review middleware ordering.", "Test URL-fetching handlers.")),
    _stack("Node.js + Fastify + Redis", ("command injection", "session tampering"), ("Review plugin boundaries.", "Inspect Redis-backed session controls.")),
    _stack("Node.js + Next.js + PostgreSQL", ("SSRF", "XSS", "auth bypass"), ("Review server actions and rewrites.", "Inspect API route authorization.")),
    _stack("Node.js + Nuxt + MongoDB", ("XSS", "NoSQL injection"), ("Review server routes and SSR data.", "Inspect query serialization.")),
    _stack("Node.js + Meteor + MongoDB", ("NoSQL injection", "method authorization"), ("Review DDP methods.", "Inspect publication filters.")),
    _stack("Node.js + Strapi + PostgreSQL", ("BOLA", "SQL injection"), ("Review generated content APIs.", "Inspect role and permission policies.")),
    _stack("Node.js + Ghost + MySQL", ("stored XSS", "auth bypass"), ("Review admin API tokens.", "Inspect theme and asset upload paths.")),
    _stack("Nginx + Node.js + CouchDB", ("NoSQL injection", "data exposure"), ("Review CouchDB view access.", "Inspect proxy route normalization.")),
    _stack("Go + Gin + PostgreSQL", ("SQL injection", "path traversal"), ("Review binding and validation.", "Inspect raw SQL and file handlers.")),
    _stack("Go + Echo + MySQL", ("SQL injection", "SSRF"), ("Review middleware trust headers.", "Inspect database and URL fetch helpers.")),
    _stack("Go + Fiber + Redis", ("command injection", "session tampering"), ("Review Redis command wrappers.", "Inspect debug and metrics routes.")),
    _stack("Go + Beego + MySQL", ("SQL injection", "CSRF"), ("Review ORM filters.", "Inspect default admin modules.")),
    _stack("Caddy + Laravel + PostgreSQL", ("SQL injection", "mass assignment"), ("Review Laravel debug and queue endpoints.", "Inspect PostgreSQL query construction.")),
    _stack("Caddy + PHP + MariaDB", ("file inclusion", "unsafe upload"), ("Review PHP-FPM routing.", "Inspect database account privileges.")),
    _stack("IIS + ASP.NET + SQL Server", ("SQL injection", "view-state tampering"), ("Review upload and serialization handlers.", "Inspect xp_cmdshell and privileged accounts.")),
    _stack("IIS + ASP.NET Core + SQL Server", ("BOLA", "SQL injection"), ("Review middleware and model binding.", "Inspect SQL Server execution privileges.")),
    _stack("IIS + SharePoint + SQL Server", ("access control", "deserialization"), ("Review site collection permissions.", "Inspect exposed service endpoints.")),
    _stack("Tomcat + Spring Boot + MySQL", ("Spring expression injection", "actuator exposure"), ("Review Actuator exposure.", "Inspect SpEL and upload handlers.")),
    _stack("Tomcat + Spring Boot + PostgreSQL", ("SQL injection", "SSRF"), ("Review management endpoints.", "Inspect JDBC and template sinks.")),
    _stack("Tomcat + Struts + Oracle", ("OGNL injection", "SQL injection"), ("Review OGNL evaluation.", "Inspect Oracle query construction.")),
    _stack("Jetty + Spring + PostgreSQL", ("SSRF", "deserialization"), ("Review embedded server routes.", "Inspect Spring message converters.")),
    _stack("Java + JSF + Oracle", ("EL injection", "IDOR"), ("Review expression language inputs.", "Inspect view-state protection.")),
    _stack("Java + Grails + PostgreSQL", ("data binding", "SQL injection"), ("Review command objects.", "Inspect GORM query filters.")),
    _stack("Kestrel + ASP.NET Core + SQL Server", ("BOLA", "request smuggling"), ("Review forwarded headers.", "Inspect SQL Server privileges.")),
    _stack("OpenResty + Lua + Redis", ("command injection", "SSRF"), ("Review Lua route handlers.", "Inspect Redis command construction.")),
    _stack("Nginx + Ruby on Rails + PostgreSQL", ("SQL injection", "mass assignment"), ("Review ActiveRecord scopes.", "Inspect strong parameter boundaries.")),
    _stack("Puma + Rails + PostgreSQL", ("SSRF", "unsafe deserialization"), ("Review background job endpoints.", "Inspect YAML and cookie serialization.")),
    _stack("Elixir + Phoenix + PostgreSQL", ("SQL injection", "CSRF"), ("Review LiveView events.", "Inspect Ecto query fragments.")),
    _stack("Rust + Actix Web + PostgreSQL", ("path traversal", "SQL injection"), ("Review extractor validation.", "Inspect raw SQL and file serving.")),
    _stack("Rust + Rocket + PostgreSQL", ("request smuggling", "IDOR"), ("Review route guards.", "Inspect object-level authorization.")),
    _stack("Python + Tornado + Redis", ("template injection", "SSRF"), ("Review async handlers.", "Inspect Redis-backed sessions.")),
    _stack("Python + Pyramid + PostgreSQL", ("CSRF", "SQL injection"), ("Review route predicates.", "Inspect SQL adapters.")),
    _stack("PHP + Yii + MySQL", ("SQL injection", "unsafe deserialization"), ("Review Yii widgets and controllers.", "Inspect database query builders.")),
    _stack("PHP + CodeIgniter + MySQL", ("SQL injection", "file inclusion"), ("Review query builder inputs.", "Inspect upload and include paths.")),
    _stack("Apache + Concrete CMS + MySQL", ("stored XSS", "access control"), ("Review dashboard permissions.", "Inspect file manager endpoints.")),
    _stack("Nginx + Liferay + PostgreSQL", ("access control", "XXE"), ("Review portlet permissions.", "Inspect document and XML importers.")),
    _stack("Nginx + Odoo + PostgreSQL", ("BOLA", "template injection"), ("Review record rules.", "Inspect QWeb and report rendering.")),
    _stack("Nginx + Nextcloud + MariaDB", ("path traversal", "access control"), ("Review DAV and sharing endpoints.", "Inspect app/plugin versions.")),
    _stack("Nginx + GitLab + PostgreSQL", ("SSRF", "access control"), ("Review import and runner endpoints.", "Inspect project authorization.")),
    _stack("Nginx + Gitea + SQLite", ("path traversal", "access control"), ("Review repository archive routes.", "Inspect organization permissions.")),
    _stack("Nginx + Discourse + PostgreSQL", ("stored XSS", "access control"), ("Review plugin routes.", "Inspect trust-level permissions.")),
    _stack("Nginx + phpBB + MySQL", ("stored XSS", "SQL injection"), ("Review extensions and BBCode.", "Inspect moderator routes.")),
]


EDU_STACK_SEEDS = [
    _stack(
        "正方教务 + Java + Oracle",
        ("SQL 注入", "弱口令", "未授权 API"),
        ("审计选课、成绩和学籍查询参数。", "检查角色边界、批量接口和 Oracle 查询拼接。"),
    ),
    _stack(
        "正方教务 + Java + MySQL",
        ("SQL 注入", "水平越权", "敏感信息泄露"),
        ("对比学生、教师和管理员账号的对象级权限。", "检查导出、查询和移动端 API。"),
    ),
    _stack(
        "正方教务 + Spring MVC + Oracle",
        ("数据绑定越权", "SQL 注入", "CSRF"),
        ("审计控制器参数绑定和服务端字段白名单。", "验证关键写操作的 CSRF 与二次确认。"),
    ),
    _stack(
        "强智教务 + Java + Oracle",
        ("SQL 注入", "弱口令", "会话固定"),
        ("检查登录前后 JSESSIONID 轮换。", "审计课表、成绩和培养方案查询。"),
    ),
    _stack(
        "强智教务 + Java + MySQL",
        ("SQL 注入", "未授权 API", "水平越权"),
        ("枚举前端实际调用的 JSON/JSP 接口。", "用两个测试账号验证对象归属。"),
    ),
    _stack(
        "强智教务 + Tomcat + Oracle",
        ("默认管理面暴露", "目录遍历", "SQL 注入"),
        ("确认 Tomcat 管理端和错误页是否外露。", "检查反向代理与应用路径规范化。"),
    ),
    _stack(
        "青果教务 + Java + Oracle",
        ("SQL 注入", "任意文件下载", "弱口令"),
        ("审计报表、附件和导入导出模块。", "检查 Oracle 账号权限与错误回显。"),
    ),
    _stack(
        "青果教务 + Java + SQL Server",
        ("SQL 注入", "未授权查询", "敏感数据导出"),
        ("检查动态排序和报表查询。", "验证数据库账号是否具备高危扩展权限。"),
    ),
    _stack(
        "青果教务 + Tomcat + Oracle",
        ("路径穿越", "会话管理缺陷", "SQL 注入"),
        ("审计静态资源和下载路径。", "验证退出、并发会话和异常处理。"),
    ),
    _stack(
        "金智 CAS + Java",
        ("service 参数开放重定向", "弱口令"),
        ("验证 service 注册白名单和规范化。", "检查票据一次性、精确 service 绑定和登录限速。"),
    ),
    _stack(
        "金智 CAS + Spring Boot",
        ("管理端点暴露", "认证流程绕过", "敏感配置泄露"),
        ("检查 Actuator 和错误详情。", "追踪验证码、账号和流程事务绑定。"),
    ),
    _stack(
        "金智 CAS + Oracle",
        ("账号枚举", "密码找回缺陷", "SQL 注入"),
        ("统一登录和找回接口的错误与时序。", "审计身份因子与目标账号绑定。"),
    ),
    _stack(
        "艾卡 CAS + Java",
        ("service 参数开放重定向", "票据重放", "弱口令"),
        ("验证 TGT/ST 生命周期和注销失效。", "检查 service、renew 和 gateway 参数边界。"),
    ),
    _stack(
        "艾卡 CAS + Spring MVC",
        ("认证绕过", "CSRF", "会话固定"),
        ("审计 Webflow 状态参数和登录事件。", "确认登录成功后会话轮换。"),
    ),
    _stack(
        "正方统一身份认证 + Java",
        ("service 参数开放重定向", "弱口令", "账号枚举"),
        ("检查注册服务白名单和错误响应一致性。", "验证票据绑定、重放和退出行为。"),
    ),
    _stack(
        "正方统一身份认证 + Oracle",
        ("SQL 注入", "密码找回缺陷", "未授权用户查询"),
        ("审计身份查询和找回流程。", "最小化验证敏感字段与账号范围。"),
    ),
    _stack(
        "博达 CMS/VSB Portal + Java",
        ("未授权 JSP/API", "存储型 XSS", "任意文件上传"),
        ("枚举 /system/ 下公开组件并区分登录页与真实越权。", "追踪富文本到 v-html/innerHTML 的数据流。"),
    ),
    _stack(
        "博达 CMS/VSB Portal + Tomcat",
        ("路径穿越", "错误信息泄露", "会话管理缺陷"),
        ("检查代理重写和大小写编码差异。", "验证后台会话轮换、Cookie 属性和退出失效。"),
    ),
    _stack(
        "博达 CMS/VSB Portal + Oracle",
        ("SQL 注入", "多租户越权", "搜索索引数据泄露"),
        ("检查站群栏目、文章和附件的租户边界。", "审计搜索、报表和发布查询。"),
    ),
    _stack(
        "超星智慧门户",
        ("认证绕过", "API 未授权访问"),
        ("验证门户与 passport2 登录态交换。", "审计公开搜索、用户内容和聚合 API 的授权。"),
    ),
    _stack(
        "超星智慧门户 + Java",
        ("水平越权", "存储型 XSS", "会话管理缺陷"),
        ("用不同测试账号验证对象级权限。", "追踪搜索高亮和富文本进入 HTML sink 的路径。"),
    ),
    _stack(
        "超星智慧门户 + Elasticsearch",
        ("搜索 API 未授权", "索引数据泄露", "存储型 XSS"),
        ("确认搜索后端是否真实使用 Elasticsearch。", "仅在隔离索引中验证写权限与净化链。"),
    ),
]

STACK_SEEDS.extend(EDU_STACK_SEEDS)


PARAMETER_SEEDS = [
    _parameter("tenant_scope", "authorization_bypass", 0.93),
    _parameter("account_scope", "authorization_bypass", 0.90),
    _parameter("resource_key", "idor", 0.88),
    _parameter("owner_ref", "idor", 0.91),
    _parameter("permission", "authorization_bypass", 0.86),
    _parameter("role_name", "authorization_bypass", 0.87),
    _parameter("username", "account_enumeration", 0.82),
    _parameter("email", "account_enumeration", 0.80),
    _parameter("old_password", "password_reset", 0.94),
    _parameter("new_password", "password_reset", 0.94),
    _parameter("otp_code", "authentication_bypass", 0.91),
    _parameter("mfa_code", "authentication_bypass", 0.92),
    _parameter("csrf_token", "csrf", 0.96),
    _parameter("saml_response", "authentication_bypass", 0.90),
    _parameter("jwt_token", "jwt", 0.91),
    _parameter("access_token", "jwt", 0.88),
    _parameter("api_key", "authorization_bypass", 0.86),
    _parameter("client_secret", "secret_exposure", 0.90),
    _parameter("debug_mode", "information_disclosure", 0.87),
    _parameter("verbose_error", "information_disclosure", 0.84),
    _parameter("file_path", "path_traversal", 0.93),
    _parameter("archive_name", "path_traversal", 0.88),
    _parameter("template_name", "ssti", 0.91),
    _parameter("view_name", "ssti", 0.86),
    _parameter("expression", "ssti", 0.89),
    _parameter("command_name", "command_injection", 0.92),
    _parameter("script_body", "xss", 0.85),
    _parameter("html_fragment", "xss", 0.86),
    _parameter("markdown_body", "xss", 0.81),
    _parameter("graphql_query", "graphql_injection", 0.90),
    _parameter("filter_json", "nosql_injection", 0.90),
    _parameter("mongo_query", "nosql_injection", 0.91),
    _parameter("sort_field", "sqli", 0.82),
    _parameter("column_name", "sqli", 0.84),
    _parameter("table_name", "sqli", 0.84),
    _parameter("order_by", "sqli", 0.83),
    _parameter("xml_body", "xxe", 0.88),
    _parameter("entity_name", "xxe", 0.86),
    _parameter("dns_name", "ssrf", 0.85),
    _parameter("proxy_url", "ssrf", 0.94),
    _parameter("webhook_url", "ssrf", 0.93),
    _parameter("include_path", "lfi", 0.92),
]


def validate_seed_data() -> list[str]:
    """Return data-quality errors without touching the SQLite database."""

    errors: list[str] = []
    collections = (
        (
            "cms",
            CMS_SEEDS,
            ("name", "paths", "cookies", "meta", "headers", "category"),
        ),
        (
            "edu",
            EDU_SYSTEM_SEEDS,
            ("name", "category", "minimum_evidence"),
        ),
        (
            "frameworks",
            FRAMEWORK_SEEDS,
            ("name", "headers", "cookies", "paths", "category"),
        ),
        (
            "stack_patterns",
            STACK_SEEDS,
            (
                "stack_pattern",
                "tech_stack_pattern",
                "common_issues",
                "assessment_focus",
            ),
        ),
        ("parameter_patterns", PARAMETER_SEEDS, ("param_pattern", "related_issue_type", "confidence")),
    )
    minimums = {
        "cms": 50,
        "edu": 8,
        "frameworks": 30,
        "stack_patterns": 50,
        "parameter_patterns": 30,
    }
    for category, records, required in collections:
        if len(records) < minimums[category]:
            errors.append(f"{category} has {len(records)} records; expected at least {minimums[category]}")
        names = set()
        for index, record in enumerate(records):
            for key in required:
                if key not in record or record[key] in (None, "", []):
                    errors.append(f"{category}[{index}] is missing {key}")
            identity = record.get(required[0])
            if identity in names:
                errors.append(f"{category} contains duplicate {identity!r}")
            names.add(identity)
        if category == "edu":
            for index, record in enumerate(records):
                feature_count = sum(
                    len(record.get(key, ()))
                    for key in (
                        "headers",
                        "absent_headers",
                        "cookies",
                        "body",
                        "paths",
                        "hosts",
                    )
                )
                if feature_count < 3:
                    errors.append(
                        f"edu[{index}] has {feature_count} fingerprint features; "
                        "expected at least 3"
                    )
                if int(record.get("minimum_evidence") or 0) < 2:
                    errors.append(
                        f"edu[{index}] must require at least 2 evidence items"
                    )
        if category == "stack_patterns":
            for index, record in enumerate(records):
                if record.get("stack_pattern") != record.get(
                    "tech_stack_pattern"
                ):
                    errors.append(
                        f"stack_patterns[{index}] has inconsistent pattern aliases"
                    )
        if category == "parameter_patterns":
            for index, record in enumerate(records):
                confidence = record.get("confidence")
                if not isinstance(confidence, (int, float)) or not 0.0 <= float(confidence) <= 1.0:
                    errors.append(f"parameter_patterns[{index}] has invalid confidence")
    return errors


def _slug(value: str) -> str:
    result = "".join(char.lower() if char.isalnum() else "-" for char in str(value))
    return "-".join(part for part in result.split("-") if part)[:80]


def _seed_target_url(category: str, name: str) -> str:
    return f"https://seed.hunter.local/{category}/{_slug(name)}"


def _seed_target(
    target_memory: Any,
    *,
    category: str,
    name: str,
    values: Mapping[str, Any],
) -> None:
    target_url = _seed_target_url(category, name)
    history = target_memory.query_target(target_url)
    existing = history["target"]
    desired_stack = {
        category: name,
        "seed_category": category,
        "product": name,
    }
    if existing is not None and existing.get("url") == target_url:
        current_fingerprints = history.get("fingerprints", {})
        current_stack = existing.get("technology_stack", {})
        if (
            all(current_fingerprints.get(key) == value for key, value in values.items())
            and all(current_stack.get(key) == value for key, value in desired_stack.items())
        ):
            return
    target_memory.record_target(
        target_url,
        fingerprints=dict(values),
        technology_stack=desired_stack,
    )


def _seed_technique(
    technique_memory: Any,
    *,
    name: str,
    technique_type: str,
    description: str,
    seed_key: str,
    waf_type: str,
    metadata: Mapping[str, Any] | None = None,
) -> None:
    technique_memory.register_technique(name, technique_type, description)
    target_url = _seed_technique_target_url(seed_key)
    existing = technique_memory.attempts(
        technique_name=name,
        target_url=target_url,
        limit=100,
    )
    normalized_waf = str(waf_type or "custom/unknown").strip()
    desired_metadata = {
        "seed": True,
        "seed_key": seed_key,
        "inferred_waf_type": normalized_waf,
        **dict(metadata or {}),
    }
    if any(
        str(item.get("waf_type") or "").casefold()
        == normalized_waf.casefold()
        and all(
            item.get("metadata", {}).get(key) == value
            for key, value in desired_metadata.items()
        )
        for item in existing
    ):
        return
    technique_memory.record_attempt(
        target_url=target_url,
        technique_name=name,
        waf_type=normalized_waf,
        success=True,
        metadata=desired_metadata,
        notes="Baseline knowledge-base seed observation.",
    )


def _seed_technique_target_url(seed_key: str) -> str:
    return f"https://seed.hunter.local/techniques/{_slug(seed_key)}"


def _infer_stack_waf_type(stack_pattern: str) -> str:
    """Infer a deterministic, conservative WAF association for a stack."""

    stack = str(stack_pattern or "").casefold()
    if "apache" in stack:
        return "ModSecurity"
    if "iis" in stack or "kestrel" in stack:
        return "custom/unknown"
    if "nginx" in stack and "node.js" in stack:
        return "custom/unknown"
    if "nginx" in stack:
        php_ecosystem = (
            "php",
            "laravel",
            "symfony",
            "drupal",
            "joomla",
            "magento",
            "prestashop",
            "woocommerce",
            "nextcloud",
            "phpbb",
        )
        if any(signal in stack for signal in php_ecosystem):
            return "Alibaba Cloud WAF"
        return "NAXSI"
    if "openresty" in stack:
        return "Tencent Cloud WAF"
    if any(signal in stack for signal in ("tomcat", "jetty", "java +")):
        return "AWS WAF"
    if any(
        signal in stack
        for signal in ("gunicorn", "uwsgi", "uvicorn", "puma +")
    ):
        return "NAXSI"
    if "caddy" in stack:
        return "Cloudflare"
    if stack.startswith("php +"):
        return "ModSecurity"
    return "custom/unknown"


def populate_memory(
    db_path: str | Path = DEFAULT_DATABASE,
    *,
    reset: bool = False,
) -> dict[str, Any]:
    """Populate both persistent memories using their public APIs."""

    errors = validate_seed_data()
    if errors:
        raise ValueError("; ".join(errors))

    from core.memory import reset_memory
    from core.memory.target_memory import TargetMemory
    from core.memory.technique_memory import TechniqueMemory

    target_memory = TargetMemory(db_path)
    technique_memory = TechniqueMemory(db_path)
    if reset:
        reset_memory(db_path)

    for record in CMS_SEEDS:
        _seed_target(
            target_memory,
            category="cms",
            name=record["name"],
            values={
                "cms": record["name"],
                "paths": record["paths"],
                "cookies": record["cookies"],
                "meta": record["meta"],
                "headers": record["headers"],
                "seed_category": record["category"],
            },
        )
    for record in EDU_SYSTEM_SEEDS:
        _seed_target(
            target_memory,
            category="edu",
            name=record["name"],
            values={
                "edu": record["name"],
                "paths": record["paths"],
                "headers": record["headers"],
                "absent_headers": record["absent_headers"],
                "cookies": record["cookies"],
                "body": record["body"],
                "hosts": record["hosts"],
                "login_features": record["login_features"],
                "auth": record["auth"],
                "endpoints": record["endpoints"],
                "minimum_evidence": record["minimum_evidence"],
                "seed_category": record["category"],
            },
        )
    for record in FRAMEWORK_SEEDS:
        _seed_target(
            target_memory,
            category="framework",
            name=record["name"],
            values={
                "framework": record["name"],
                "paths": record["paths"],
                "cookies": record["cookies"],
                "headers": record["headers"],
                "seed_category": record["category"],
            },
        )
    for record in STACK_SEEDS:
        _seed_technique(
            technique_memory,
            name=record["stack_pattern"],
            technique_type="stack_association",
            description="; ".join(record["common_issues"]),
            seed_key=f"stack-{record['stack_pattern']}",
            waf_type=_infer_stack_waf_type(record["stack_pattern"]),
            metadata={
                "tech_stack_pattern": record["tech_stack_pattern"],
                "common_issues": record["common_issues"],
                "assessment_focus": record["assessment_focus"],
            },
        )
    for record in PARAMETER_SEEDS:
        _seed_technique(
            technique_memory,
            name=f"parameter:{record['param_pattern']}",
            technique_type="parameter_pattern",
            description=f"{record['related_issue_type']} ({record['confidence']:.2f})",
            seed_key=f"parameter-{record['param_pattern']}",
            waf_type="custom/unknown",
        )

    return {
        "counts": {
            "cms": len(CMS_SEEDS),
            "edu": len(EDU_SYSTEM_SEEDS),
            "frameworks": len(FRAMEWORK_SEEDS),
            "stack_patterns": len(STACK_SEEDS),
            "parameter_patterns": len(PARAMETER_SEEDS),
        },
        "target_memory": target_memory.stats(),
        "technique_memory": technique_memory.stats(),
    }


def _missing_seed_records(
    target_memory: Any,
    technique_memory: Any,
) -> tuple[list[str], list[str]]:
    missing_targets: list[str] = []
    for category, records in (
        ("cms", CMS_SEEDS),
        ("edu", EDU_SYSTEM_SEEDS),
        ("framework", FRAMEWORK_SEEDS),
    ):
        for record in records:
            target_url = _seed_target_url(category, record["name"])
            history = target_memory.query_target(target_url)
            target = history["target"]
            expected = {
                category: record["name"],
                "paths": record["paths"],
                "cookies": record["cookies"],
                "headers": record["headers"],
                "seed_category": record["category"],
            }
            if category == "cms":
                expected["meta"] = record["meta"]
            elif category == "edu":
                expected.update(
                    {
                        "absent_headers": record["absent_headers"],
                        "body": record["body"],
                        "hosts": record["hosts"],
                        "login_features": record["login_features"],
                        "auth": record["auth"],
                        "endpoints": record["endpoints"],
                        "minimum_evidence": record["minimum_evidence"],
                    }
                )
            if (
                target is None
                or target.get("url") != target_url
                or any(
                    history.get("fingerprints", {}).get(key) != value
                    for key, value in expected.items()
                )
            ):
                missing_targets.append(target_url)

    missing_techniques: list[str] = []
    for record in STACK_SEEDS:
        name = record["stack_pattern"]
        technique = technique_memory.query_technique(name)
        attempts = technique_memory.attempts(
            technique_name=name,
            target_url=_seed_technique_target_url(f"stack-{name}"),
            limit=100,
        )
        expected_waf = _infer_stack_waf_type(name)
        expected_metadata = {
            "tech_stack_pattern": record["tech_stack_pattern"],
            "common_issues": record["common_issues"],
            "assessment_focus": record["assessment_focus"],
        }
        if (
            technique is None
            or technique["total_attempts"] < 1
            or not any(
                str(item.get("waf_type") or "").casefold()
                == expected_waf.casefold()
                and all(
                    item.get("metadata", {}).get(key) == value
                    for key, value in expected_metadata.items()
                )
                for item in attempts
            )
            or any(item.get("waf_type") == "*" for item in attempts)
        ):
            missing_techniques.append(name)
    for record in PARAMETER_SEEDS:
        name = f"parameter:{record['param_pattern']}"
        technique = technique_memory.query_technique(name)
        attempts = technique_memory.attempts(
            technique_name=name,
            target_url=_seed_technique_target_url(
                f"parameter-{record['param_pattern']}"
            ),
            limit=100,
        )
        if (
            technique is None
            or technique["total_attempts"] < 1
            or not any(
                str(item.get("waf_type") or "").casefold()
                == "custom/unknown"
                for item in attempts
            )
            or any(item.get("waf_type") == "*" for item in attempts)
        ):
            missing_techniques.append(name)
    return missing_targets, missing_techniques


def _check_database(db_path: Path) -> dict[str, Any]:
    """Inspect an existing DB without creating schema or files."""

    if not db_path.exists():
        return {
            "status": "missing",
            "target_memory": None,
            "technique_memory": None,
        }

    from core.memory.target_memory import TargetMemory
    from core.memory.technique_memory import TechniqueMemory

    try:
        target_memory = TargetMemory(
            db_path,
            initialize=False,
            read_only=True,
        )
        technique_memory = TechniqueMemory(
            db_path,
            initialize=False,
            read_only=True,
        )
        target_stats = target_memory.stats()
        technique_stats = technique_memory.stats()
        missing_targets, missing_techniques = _missing_seed_records(
            target_memory,
            technique_memory,
        )
    except (OSError, RuntimeError, ValueError, sqlite3.DatabaseError):
        return {
            "status": "invalid",
            "target_memory": None,
            "technique_memory": None,
        }

    table_total = (
        target_stats["targets"]
        + target_stats["fingerprints"]
        + target_stats["endpoints"]
        + target_stats["vulnerabilities"]
        + target_stats["attack_history"]
        + technique_stats["techniques"]
        + technique_stats["attempts"]
    )

    if table_total == 0:
        status = "empty"
    elif missing_targets or missing_techniques:
        status = "incomplete"
    else:
        status = "ready"
    return {
        "status": status,
        "target_memory": target_stats,
        "technique_memory": technique_stats,
        "missing_targets": missing_targets,
        "missing_techniques": missing_techniques,
    }


def _print_report(
    *,
    action: str,
    db_path: Path,
    counts: Mapping[str, int],
    database: Mapping[str, Any],
) -> None:
    print(f"action: {action}")
    print(f"database: {db_path}")
    print(f"database_status: {database.get('status', 'ready')}")
    for key in (
        "cms",
        "edu",
        "frameworks",
        "stack_patterns",
        "parameter_patterns",
    ):
        print(f"{key}: {int(counts[key])}")
    if database.get("target_memory"):
        print(f"target_memory: {database['target_memory']}")
    if database.get("technique_memory"):
        print(f"technique_memory: {database['technique_memory']}")
    if database.get("missing_targets"):
        print(f"missing_targets: {len(database['missing_targets'])}")
    if database.get("missing_techniques"):
        print(f"missing_techniques: {len(database['missing_techniques'])}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help="check seed integrity and existing database state without writing",
    )
    mode.add_argument(
        "--reset",
        action="store_true",
        help="clear memory through public APIs and refill all seed records",
    )
    parser.add_argument(
        "--database",
        type=Path,
        default=DEFAULT_DATABASE,
        help=f"SQLite database path (default: {DEFAULT_DATABASE})",
    )
    args = parser.parse_args(argv)

    errors = validate_seed_data()
    if errors:
        for error in errors:
            print(f"error: {error}")
        return 1

    database_path = args.database.expanduser().resolve()
    counts = {
        "cms": len(CMS_SEEDS),
        "edu": len(EDU_SYSTEM_SEEDS),
        "frameworks": len(FRAMEWORK_SEEDS),
        "stack_patterns": len(STACK_SEEDS),
        "parameter_patterns": len(PARAMETER_SEEDS),
    }
    if args.check:
        database = _check_database(database_path)
        _print_report(
            action="check",
            db_path=database_path,
            counts=counts,
            database=database,
        )
        return 1 if database.get("status") in {"invalid", "incomplete"} else 0

    result = populate_memory(database_path, reset=args.reset)
    database = {
        "status": "ready",
        "target_memory": result["target_memory"],
        "technique_memory": result["technique_memory"],
    }
    _print_report(
        action="reset-and-fill" if args.reset else "fill",
        db_path=database_path,
        counts=result["counts"],
        database=database,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
