<img src="doc/img/eu_regional_development_fund_horizontal.jpg" width="350" height="200">

# TARA integration tests

Tests for TARA (both Hydra OIDC and Estonian specific login service component)

## Prerequisites

* Java 21 JDK
* SUT (TARA) - either deployed or running locally (in docker).
* Fetch the tests:
  `git clone https://github.com/e-gov/TARA-Test`

## Configuring the test

Configure the properties file.
application.properties file needs to be either in `src/test/resources` directory
or its location configured with .env file `src/test/resources`.
Example of .env file:

```
configuration_base_path=/home/me/IdeaProjects/tara-configuration
configuration_path=dev-local
```   

The example application.properties file with values is given `../src/test/resource/sample_application.properties`

Description of values:

**oidcservice** - Hydra OIDC service parameters

**loginservice** - Estonian specific login service parameters

**ca-proxyservice** - Foreign country (CA) proxy service configuration for eIDAS authentication tests.

**idp** - Foreign country (CA) identity provider configuration for eIDAS authentication tests.

**adminservice** - Tara admin service configurations.

**test** - Tara test configurations.

| Parameter                            | Default                                                                                                                              | Description                                                   |
|--------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------|
| oidcservice.protocol                 | https                                                                                                                                | Service protocol.                                             |
| oidcservice.host                     | oidc-service                                                                                                                         | Service URL.                                                  |
| oidcservice.port                     | 8443                                                                                                                                 | Service port.                                                 |
| oidcservice.node.protocol            | https                                                                                                                                | OIDC service node protocol.                                   |
| oidcservice.node.host                | oidc-service-backend                                                                                                                 | OIDC service node URL.                                        |
| oidcservice.node.port                | 8444                                                                                                                                 | OIDC service node port.                                       |
| oidcservice.authenticationRequestUrl | /oauth2/auth                                                                                                                         | OIDC flow start endpoint.                                     |
| oidcservice.configurationUrl         | /.well-known/openid-configuration                                                                                                    | OIDC metadata endpoint.                                       |
| oidcservice.jwksUrl                  | /.well-known/jwks.json                                                                                                               | Signing key info endpoint.                                    |
| loginservice.protocol                | https                                                                                                                                | Service protocol.                                             |
| loginservice.host                    | login-service-backend                                                                                                                | Service URL.                                                  |
| loginservice.port                    | 8444                                                                                                                                 | Service port.                                                 |
| loginservice.node.protocol           | https                                                                                                                                | Login service node protocol.                                  |
| loginservice.node.host               | login-service-backend                                                                                                                | Login service node URL.                                       |
| loginservice.node.port               | 8444                                                                                                                                 | Login service node port.                                      |
| loginservice.initUrl                 | /auth/init                                                                                                                           | Authentication start endpoint in login service.               |
| loginservice.midInitUrl              | /auth/mid/init                                                                                                                       | Mobile-ID start endpoint.                                     |
| loginservice.midPollUrl              | /auth/mid/poll                                                                                                                       | Mobile-ID status polling endpoint.                            |
| loginservice.midCancelUrl            | /auth/mid/poll/cancel                                                                                                                | Mobile-ID cancel endpoint.                                    |
| loginservice.webEidInitUrl           | /auth/id/init                                                                                                                        | ID-card start endpoint.                                       |
| loginservice.webEidLoginUrl          | /auth/id/login                                                                                                                       | ID-card authentication endpoint for submitting Web eID token. |
| loginservice.sidInitUrl              | /auth/sid/init                                                                                                                       | Smart-ID start endpoint.                                      |
| loginservice.sidPollUrl              | /auth/sid/poll                                  Foreign country (CA) identity provider configuration for eIDAS authentication tests. | Smart-ID status polling endpoint.                             |
| loginservice.sidCancelUrl            | /auth/sid/poll/cancel                                                                                                                | Smart-ID cancel endpoint.                                     |
| loginservice.authAcceptUrl           | /auth/accept                                                                                                                         | Authentication accept endpoint.                               |
| loginservice.authRejectUrl           | /auth/reject                                                                                                                         | Authentication reject endpoint.                               |
| loginservice.errorUrl                | /oidc-error                                                                                                                          | Error status endpoint.                                        |
| loginservice.eidasInitUrl            | /auth/eidas/init                                                                                                                     | eIDAS authentication start endpoint.                          |
| loginservice.eidasCallbackUrl        | /auth/eidas/callback                                                                                                                 | eIDAS authentication return endpoint.                         |
| loginservice.authLegalInitUrl        | /auth/legalperson/init                                                                                                               | Legal person authentication start endpoint.                   |
| loginservice.authLegalPersonUrl      | /auth/legalperson                                                                                                                    | Legal person selection endpoint.                              |
| loginservice.authLegalConfirmUrl     | /auth/legalperson/confirm                                                                                                            | Legal person confirmation endpoint.                           |
| loginservice.consentUrl              | /auth/consent                                                                                                                        | Authentication consent selection endpoint.                    |
| loginservice.consentConfirmUrl       | /auth/consent/confirm                                                                                                                | Authentication consent confirmation endpoint                  |
| loginservice.id.username             | f5                                                                                                                                   | Basic authentication username, used in ID-Card tests          |
| loginservice.id.password             | changeme                                                                                                                             | Basic authentication password, used in ID-Card tests          |
| ca-proxyservice.protocol             | https                                                                                                                                | Service protocol.                                             |
| ca-proxyservice.host                 | eidas-caproxy                                                                                                                        | Service URL.                                                  |
| ca-proxyservice.port                 | 8080                                                                                                                                 | Service port.                                                 |
| ca-proxyservice.consentUrl           | /SpecificProxyService/AfterCitizenConsentResponse                                                                                    | Authentication consent endpoint.                              |
| idp.protocol                         | https                                                                                                                                | Service protocol.                                             |
| idp.host                             | eidas-caproxy                                                                                                                        | Service URL.                                                  |
| idp.port                             | 8081                                                                                                                                 | Service port.                                                 |
| idp.responseUrl                      | /IdP/Response                                                                                                                        | Authentication response endpoint.                             |
| adminservice.protocol                | https                                                                                                                                | Service protocol.                                             |
| adminservice.host                    | admin-service                                                                                                                        | Service URL.                                                  |
| adminservice.port                    | 8445                                                                                                                                 | Service port.                                                 |
| adminservice.username                |                                                                                                                                      | Admin service username.                                       |
| adminservice.password                |                                                                                                                                      | Admin service password.                                       |
| inproxyservice.protocol              | https                                                                                                                                | Inproxy service protocol.                                     |
| inproxyservice.host                  | inproxy-service                                                                                                                      | Inproxy service URL.                                          |
| inproxyservice.port                  | 8444                                                                                                                                 | Inproxy service port.                                         |
| test.isLocal                         | true                                                                                                                                 | Allows enabling local-only adjustments.                       |
| test.restAssured.consoleLogging      | true                                                                                                                                 | Enables console logging for rest-assured.                     |
| test.adminSetupPath                  | src/test/resources/admin-setup                                                                                                       | Path to test clients configurations.                          |

## Executing tests

* Start tests from IDE
* Start tests from command line:
    * All tests: `mvn clean test`
    * Single specification (test class): `mvn clean test -Dtest=<testClass>`
    * Single test: `mvn clean test -Dtest=<testClass>#<testMethod>`
* Start tests in docker

```bash 
# With console logging
docker compose up
```

```bash
# In the background
docker compose up -d
```

## Test reports

Surefire plugin generates reports in ../target/surefire-reports folder.

For a comprehensive report, Allure is required ([instructions for download](https://allurereport.org/docs/install/)).
To generate the report execute:

```bash
allure serve ./target/allure-results/
```
