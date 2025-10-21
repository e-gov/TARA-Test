package ee.ria.tara.configuration

import org.aeonbits.owner.Config
import org.aeonbits.owner.ConfigFactory

class ConfigHolder {

    private static final Properties props = ConfigLoader.load()

    private static final LoginServiceConf loginService = readConf(LoginServiceConf, "loginservice")
    private static final OidcServiceConf oidcService = readConf(OidcServiceConf, "oidcservice")
    private static final CaProxyServiceConf caProxyService = readConf(CaProxyServiceConf, "ca-proxyservice")
    private static final ForeignIdpConf foreignIdp = readConf(ForeignIdpConf, "idp")
    private static final AdminServiceConf adminService = readConf(AdminServiceConf, "adminservice")
    private static final InproxyServiceConf inproxyService = readConf(InproxyServiceConf, "inproxyservice")
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

    static CaProxyServiceConf getCaProxyService() { caProxyService }

    static ForeignIdpConf getForeignIdp() { foreignIdp }

    static AdminServiceConf getAdminService() { adminService }

    static InproxyServiceConf getInproxyService() { inproxyService }

    static TestConf getTestConf() { testConf }
}
