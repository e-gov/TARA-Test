package ee.ria.tara.configuration

import org.aeonbits.owner.Config
import org.aeonbits.owner.ConfigFactory

class ConfigHolder {

    private static final Properties props = ConfigLoader.load()

    private static final LoginServiceConf loginService = readConf(LoginServiceConf, "loginservice")
    private static final OidcServiceConf oidcService = readConf(OidcServiceConf, "oidcservice")
    private static final OidcClientConf oidcClientPublic = readConf(OidcClientConf, "oidcclientpublic")
    private static final OidcClientConf oidcClientPrivate = readConf(OidcClientConf, "oidcclientprivate")
    private static final OidcClientConf oidcClientPost = readConf(OidcClientConf, "oidcclientpost")
    private static final OidcClientConf oidcClientLegal = readConf(OidcClientConf, "oidcclientlegal")
    private static final SpecificProxyServiceConf specificProxyService = readConf(SpecificProxyServiceConf, "specificproxyservice")
    private static final CaProxyServiceConf caProxyService = readConf(CaProxyServiceConf, "ca-proxyservice")
    private static final ForeignIdpConf foreignIdp = readConf(ForeignIdpConf, "idp")
    private static final AdminServiceConf adminService = readConf(AdminServiceConf, "adminservice")
    private static final TestConf testConf = readConf(TestConf, "test")

    private static <T extends Config> T readConf(Class<T> configClass) {
        return ConfigFactory.create(configClass, props)
    }

    private static <T extends Config> T readConf(Class<T> configClass, String scope) {
        Properties scoped = new Properties()
        props.each { key, value ->
            if (key.toString().startsWith(scope + ".")) {
                def shortKey = key.toString().replaceFirst("^${scope}\\.", "")
                scoped.put(shortKey, value)
            }
        }
        return ConfigFactory.create(configClass, scoped)
    }

    static LoginServiceConf getLoginService() { loginService }

    static OidcServiceConf getOidcService() { oidcService }

    static OidcClientConf getOidcClientPublic() { oidcClientPublic }

    static OidcClientConf getOidcClientPrivate() { oidcClientPrivate }

    static OidcClientConf getOidcClientPost() { oidcClientPost }

    static OidcClientConf getOidcClientLegal() { oidcClientLegal }

    static SpecificProxyServiceConf getSpecificProxyService() { specificProxyService }

    static CaProxyServiceConf getCaProxyService() { caProxyService }

    static ForeignIdpConf getForeignIdp() { foreignIdp }

    static AdminServiceConf getAdminService() { adminService }

    static TestConf getTestConf() { testConf }
}
