package ee.ria.tara.util

import ee.ria.tara.*
import ee.ria.tara.configuration.ConfigHolder

class ServiceUrls {
    static final LoginService LOGIN_SERVICE = new LoginService(ConfigHolder.loginService)
    static final OidcService OIDC_SERVICE = new OidcService(ConfigHolder.oidcService)
    static final ForeignIdpProvider FOREIGN_IDP_PROVIDER = new ForeignIdpProvider(ConfigHolder.foreignIdp)
    static final ForeignProxyService FOREIGN_PROXY_SERVICE = new ForeignProxyService(ConfigHolder.caProxyService)
    static final TaraAdminService TARA_ADMIN_SERVICE = new TaraAdminService(ConfigHolder.adminService)
    static final InproxyService INPROXY_SERVICE = new InproxyService(ConfigHolder.inproxyService)
    static final DemoClient DEMO_CLIENT = new DemoClient(ConfigHolder.demoClient)
}
