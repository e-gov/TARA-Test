package ee.ria.tara.configuration

import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths

class ConfigLoader {

    private static final Logger log = LoggerFactory.getLogger(ConfigHolder)

    static Properties load() {
        Properties props = new Properties()

        if (!loadFromEnv(props) && !loadFromClasspath(props)) {
            throw new Exception("Configurations not found")
        }
        return props
    }

    private static boolean loadFromEnv(Properties props) {
        URL envFile = ConfigHolder.class.getResource('/.env')
        if (!envFile) {
            log.warn(".env file not found, skipping external configuration")
            return false
        }

        log.debug(".env file found at: $envFile")
        Properties envProps = new Properties()
        envFile.withInputStream { envProps.load(it) }

        String basePath = envProps.getProperty("configuration_base_path")
        String relativePath = envProps.getProperty("configuration_path")

        if (!basePath) {
            log.warn("Missing 'configuration_base_path' in .env file")
            return false
        }
        if (!relativePath) {
            log.warn("Missing 'configuration_path' in .env file")
            return false
        }

        Path configPath = Paths.get(basePath, relativePath, "application.properties")
        log.debug("Resolved config path from .env: $configPath")

        if (!Files.exists(configPath)) {
            log.warn("application.properties not found at: $configPath")
            return false
        }

        configPath.withInputStream { props.load(it) }
        props.putAll(envProps)
        log.info("Loaded configuration from external file: $configPath")
        return true
    }

    private static boolean loadFromClasspath(Properties props) {
        URL fallback = ConfigHolder.class.getResource('/application.properties')
        if (!fallback) {
            log.error("Fallback configuration '/application.properties' not found in classpath")
            return false
        }
        fallback.withInputStream { props.load(it) }
        log.info("Loaded fallback configuration from classpath: /application.properties")
        return true
    }
}
