# Zitadel-with-Opensearch-SSO

## Overview

 The following documentation shows the configurtions needed for OpenSearch Single sign-on (SSO) and connect it to Zitadel. The steps shown are basic configuration needed to connect with Zitadel. The OpenSearch node must be in Production mode, meaning you have created the certificate for "node/s, admin and CA" and ensure HTTPS is
working correct.

## Prerequisite:
* Ubuntu-22.0.4
* Updates/Upgrades Completed
* Network Configured (Static address and DNS)
* Date/Time is set
* Opensearch-2.11.1
* Zitadel-v2.44.2

To use SAML for authentication, configureations are needed in the **authc** section of config/opensearch-security/config.yml. SAML works solely on the HTTP layer, you do not need any authentication_backend and can set it to noop. Place all SAML-specific configuration options in config.yml file in the config section of the SAML HTTP authenticator. Ensure order number is correct. The Security plugin can read IdP metadata either from a URL or a file. In this example Im using URL.

Navigate to config.conf
```
vi /etc/opensearch/opensearch-security/config.yml
```


  ```
  authc:
      saml_auth_domain:
       http_enabled: true
       transport_enabled: true
       order: 1
       http_authenticator:
        type: saml
        challenge: true
        config:
         idp:
          metadata_url: https://global-edjak2.zitadel.cloud/saml/v2/metadata
          entity_id: https://global-edjak2.zitadel.cloud/saml/v2/metadata
         sp:
          entity_id: opensearch
         kibana_url: https://opensearch.hungry-howard.com:5601
         subject_key: Email
         roles_key: Role
         exchange_key: MIIFIjCCAwqgAwIBAgICAY4wDQYJKoZIhvcNAQELBQAwLDEQMAEwNjA2NTAxMVowMjEQMA4GA1UEChMHWklUQURFTDEeM................aRt/rtADhpBbyvmTMkOupCB6.TKLX9RheYBswgWFagbC0.
       authentication_backend:
          type: noop
  ```
  
##  OpenSearch Dashboards configuration


edit  file

```
vi etc/opensearch-dashboards/opensearch-dashboards.yml
```
Most of the SAML-specific configuration is done in the Security plugin, just activate SAML in your opensearch_dashboards.yml by adding the following:


```
opensearch_security.auth.type: "saml"
```

In addition, you must add the OpenSearch Dashboards endpoint for validating the SAML assertions to your allow list:
```
server.xsrf.allowlist: ["/_opendistro/_security/saml/acs"]
```
If you use the logout POST binding, you also need to ad the logout endpoint to your allow list:
```
server.xsrf.allowlist: ["/_opendistro/_security/saml/acs", "/_opendistro/_security/saml/logout"]
```
Execute security script

/usr/share/opensearch/plugins/opensearch-security/tools/securityadmin.sh
```
./securityadmin.sh -f /etc/opensearch/opensearch-security/config.yml  -t authentication  -cd /etc/opensearch/opensearch-security/ -cacert /etc/opensearch/root-ca.pem -cert /etc/opensearch/admin.pem -key /etc/opensearch/admin-key.pem -icl -nhnv
```



