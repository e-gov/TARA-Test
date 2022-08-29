<img src="doc/img/eu_regional_development_fund_horizontal.jpg" width="350" height="200">

# TARA2 integration tests

Tests for TARA2 (both Hydra OIDC and Estonian specific login service component)

## Prerequisites

1. SUT (TARA2) must be deployed in the cluster. The deployment can be done in two different setups:

a) General - deployment of TARA2 service as Estonian domestic authentication service.

b) idp - deployment of TARA2 service as identity provider for eIDAS Proxy service.

The configuration changes made in these setups may result test failures if the tests are not kept in sync.
   
2. Fetch the tests:

`git clone https://github.com/e-gov/TARA2-Test`

## Configuring the test

1. Configure the properties file. 
   application.properties file needs to be either in `src/test/resources` directory or its location configured with .env file `src/test/resources`.
   Example of .env file:
   
```
configuration_base_path=/home/me/IdeaProjects/tara-configuration
configuration_path=dev-local
```   

The example application.properties file with values are given ../src/test/resource/sample_application.properties

Description of values:

**oidcservice** - Hydra OIDC service parameters

**loginservice** - Estonian specific login service parameters

**oidcclient** - Tests act like connecting OIDC client. This client must be registered in TARA2 service.

**ca-proxyservice** - Foreign country (CA) proxy service configuration for eIDAS authentication tests.

**idp** - Foreign country (CA) identity provider configuration for eIDAS authentication tests.

**ee-connector** - Estonian connector service configuration for eIDAS authentication tests.

| Parameter                             | Default |  Description |
|---------------------------------------|--------------|------------|
| oidcservice.protocol                  | https | Service protocol. |
| oidcservice.host                      | oidc-service | Service URL. |
| oidcservice.port                      | 8443 | Service port. |
| oidcservice.authenticationRequestUrl  | /oauth2/auth  | OIDC flow start endpoint. |
| oidcservice.configurationUrl          | /.well-known/openid-configuration  | OIDC metadata endpoint. |
| oidcservice.jwksUrl                   | /.well-known/jwks.json  | Signing key info endpoint. |
| loginservice.protocol                 | https | Service protocol. |
| loginservice.host                     | login-service-backend | Service URL. |
| loginservice.port                     | 8444 | Service port. |
| loginservice.node.protocol            | https | Specific service node protocol. |
| loginservice.node.host                | login-service-backend | Specific service node URL. |
| loginservice.node.port                | 8444 | Specific service node port. |
| loginservice.initUrl                  | /auth/init | Authentication start endpoint in login service. |
| loginservice.midInitUrl               | /auth/mid/init | Mobile-ID start endpoint. |
| loginservice.midPollUrl               | /auth/mid/poll | Mobile-ID status polling endpoint. |
| loginservice.midCancelUrl             | /auth/mid/poll/cancel | Mobile-ID cancel endpoint. |
| loginservice.idCardInitUrl            | /auth/id | ID-card authentication endpoint. |
| loginservice.sidInitUrl               | /auth/sid/init | Smart-ID start endpoint. ||
| loginservice.sidPollUrl               | /auth/sid/poll | Smart-ID status polling endpoint. |
| loginservice.sidCancelUrl             | /auth/sid/poll/cancel | Smart-ID cancel endpoint. |
| loginservice.authAcceptUrl            | /auth/accept | Authentication accept endpoint. |
| loginservice.authRejectUrl            | /auth/reject | Authentication reject endpoint.|
| loginservice.errorUrl                 | /oidc-error | Error status endpoint. |
| loginservice.eidasInitUrl             | /auth/eidas/init | eIDAS authentication start endpoint. |
| loginservice.eidasCallbackUrl         | /auth/eidas/callback | eIDAS authentication return endpoint. |
| loginservice.authLegalInitUrl         | /auth/legalperson/init | Legal person authentication start endpoint. |
| loginservice.authLegalPersonUrl       | /auth/legalperson | Legal person selection endpoint. |
| loginservice.authLegalConfirmUrl      | /auth/legalperson/confirm | Legal person confirmation endpoint. |
| loginservice.consentUrl               | /auth/consent | Authentication consent selection endpoint. |
| loginservice.consentConfirmUrl        | /auth/consent/confirm | Authentication consent confirmation endpoint |
| loginservice.heartbeatUrl             | /heartbeat | Service heartbeat endpoint. |
| oidcclientpublic.protocol             | https | Service protocol. |
| oidcclientpublic.host                 | oidc-client-mock | Service URL. |
| oidcclientpublic.port                 | 8451 | Service port. |
| oidcclientpublic.responseUrl          | /oauth/response | Authentication response endpoint. |
| oidcclientpublic.clientId             | dev-mock-oidc-client | Registered client id. |
| oidcclientpublic.secret               | secret | Registered client secret. |
| oidcclientprivate.protocol            | https | Service protocol. |
| oidcclientprivate.host                | oidc-client-mock | Service URL. |
| oidcclientprivate.port                | 8451 | Service port. |
| oidcclientprivate.responseUrl         | /oauth/response | Authentication response endpoint. |
| oidcclientprivate.clientId            | dev-mock-oidc-client | Registered client id. |
| oidcclientprivate.secret              | secret | Registered client secret. |
| ca-proxyservice.protocol              | https | Service protocol. |
| ca-proxyservice.host                  | eidas-caproxy | Service URL. |
| ca-proxyservice.port                  | 8080 | Service port. |
| ca-proxyservice.consentUrl            | /SpecificProxyService/AfterCitizenConsentResponse | Authentication consent endpoint. |
| idp.protocol                          | https | Service protocol. |
| idp.host                              | eidas-caproxy | Service URL. |
| idp.port                              | 8081 | Service port. |
| idp.responseUrl                       | /IdP/Response | Authentication response endpoint. |
| ee-connector.protocol                 | https | Service protocol. |
| ee-connector.host                     | eidas-specificconnector | Service URL. |
| ee-connector.port                     | 8443 | Service port. |
| ee-connector.authenticationRequestUrl | /SpecificConnector/ServiceProvider | Estonian eIDAS conenctor authentication start endpoint. |


## Execute tests and generate report

1. To run the tests:
   
a) for domestic deployment:

`./mvn clean test`

b) for idp specific deployment:

`./mvn clean test -Dtest.deployment.env="idp"`

2. To check the results:

a) Surefire plugin generates reports in ../target/surefire-reports folder.

b) For a comprehensive report, Allure is required ([instructions for download.](https://docs.qameta.io/allure/#_installing_a_commandline)). To generate the report execute:

`allure serve .../tara-test/allure-results/`

## To see Allure report after running tests in IntelliJ 

Configure correct Allure results directory in IntelliJ in order to view Allure report when running tests from IntelliJ

`Run-> Edit configurations-> Templates-> JUnit-> VM Options: -ea -Dallure.results.directory=$ProjectFileDir$/target/allure-results`

And delete all existing run configurations