# Zitadel-with-Opensearch-SAML-SSO

## Overview

 The following documentation explains the configurations needed for OpenSearch Single sign-on (SSO) and the connection to Zitadel instance. OpenSearch node must be in Production mode, meaning you have created the certificate for "node/s, admin and CA" and ensure HTTPS is working correct. Take note this is a basic configuration setup to start SSO with Opensearch using Zitadel.

## Prerequisite:
* Ubuntu-22.0.4
* Updates/Upgrades Completed
* Network Configured (Static address and DNS)
* Date/Time is set
* Opensearch-2.11.1
* Zitadel-v2.44.2

To use SAML for authentication, configurations are needed in the **authc** section of this file  /config/opensearch-security/config.yml. SAML works solely on the HTTP layer, you do not need any authentication_backend and can set it to noop. Place all SAML-specific configuration options in config.yml file, under the section of the SAML HTTP authenticator. Ensure the order number is correct. 
In the example below the ORDER is set to 1 and basic_internal_auth_domain is set to "0".


NOTE: The Security plugin can read IdP metadata either from a URL or a file. In this example Im using URL.

Edit the file config.conf.

```
vi /etc/opensearch/opensearch-security/config.yml
```

### Configure section "authc"

Get the exchange_key from Zitadel using th endpoint **/saml/v2/metadata** on the Zitadel instances URL. 
Example:

```
https://zitadel-self-hosting.com/saml/v2/metadata
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
          metadata_url: https://zitadel.self-hosting.com/saml/v2/metadata
          entity_id: https://zitadel.self-hosting/saml/v2/metadata
         sp:
          entity_id: https://opensearch.domain.com:5601
         kibana_url: https://opensearch.domain.com:5601
         subject_key: Email
         roles_key: Role
         exchange_key:AwqgAwIBAgICAY4wDQYJKoZIhvcNANjA2NT1UEChMHWklUQURFTDEeM................aRt/rtADhpBbyvmTMkOupCB6.TKLX9RheYBswgWFagbC0.
       authentication_backend:
          type: noop
  ```
Change the challenge flag in basic_internal_auth_domain  section from true to false.
Example:
```
basic_internal_auth_domain:
        description: "Authenticate via HTTP Basic against internal users database"
        http_enabled: true
        transport_enabled: true
        order: 0
        http_authenticator:
          type: basic
          challenge: false
        authentication_backend:
          type: intern
```

  
##  OpenSearch Dashboards configuration


Edit Opensearch-Dashboard yaml file.

```
vi /etc/opensearch-dashboards/opensearch_dashboards.yml
```

The SAML-specific configuration is done in the Security plugin, just activate SAML in your opensearch_dashboards.yml by adding the following:


```
opensearch_security.auth.type: "saml"
```

Add the OpenSearch Dashboards endpoint for validating the SAML assertions to your allow list.

```
server.xsrf.allowlist: ["/_opendistro/_security/saml/acs"]
```

If you use the logout POST binding, you also need to ad the logout endpoint to your allow list.

```
server.xsrf.allowlist: ["/_opendistro/_security/saml/acs", "/_opendistro/_security/saml/logout"]
```

Execute security script to apply any configurtion made.
Change directory.

```
cd /usr/share/opensearch/plugins/opensearch-security/tools/
```
Configuration files are completed, execute the security script. The command below is uploading the new configurations made  from the file config.yml.

```
./securityadmin.sh -f /etc/opensearch/opensearch-security/config.yml    -cacert /etc/opensearch/root-ca.pem -cert /etc/opensearch/admin.pem -key /etc/opensearch/admin-key.pem -icl -nhnv
```

Restart Opensearch-Dashboard.

```
systemctl restart opensearch-dashboards
```

## Zitadel  Settings

Navigate to Organization --> Projects.

Create a new Project called Opensearch, click continue.

Under **Application** click "New" and select SAML, then name it Opensearch, Save.

![image](https://github.com/HungryHowies/Zitadel-with-Opensearch-SSO/assets/22652276/fafdfc65-7f06-4220-b3d3-085a512990a8)

Under SAML CONFIGURATION, Select Option #3. 

Configure entity ID:

This should match the **config.yml** file on opensearch.

```
https://opensearch.domain.com:5601
```

Configure ACS endpoint URL.

```
https://opensearch.domain.com:5601/_opendistro/_security/saml/acs
```

Results:

```
<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://opensearch.domain.com:5601">
    <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol urn:oasis:names:tc:SAML:1.1:protocol">
	<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"Location="https://opensearch.domain.com:5601/_opendistro/_security/saml/logout/" />
<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:attrnameformat:basic</md:NameIDFormat>
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://opensearch.domain.com:5601/_opendistro/_security/saml/acs" index="0"/>
    </md:SPSSODescriptor>
</md:EntityDescriptor>
```

Click Continue, then create.

Create a new user under the Project called "Opensearch".

![image](https://github.com/HungryHowies/Zitadel-with-Opensearch-SSO/assets/22652276/a0f6128d-0a24-4233-8ed4-7d5cb04ae7bb)


Give the some.user a role called "Project Owner Viewer Global".

## Opensearch Add User to Role

Login to Opensearch with Default Admin credentials. 

Navigate to Security --> Roles.

![image](https://github.com/HungryHowies/Zitadel-with-Opensearch-SSO/assets/22652276/3ca2c47f-8f76-4861-b5e8-2f0c0035a4cb)

 Add the user from Zitadel to a default Role or custom Role. 
 
 **Example:** I added some.user from Zitadel to **all_access**. 

 Choose "all_access", then click the Mapped Users tab.

 Button upper right, click "Manage mapping". Add the user "some.user".
 
 
 ![image](https://github.com/HungryHowies/Zitadel-with-Opensearch-SSO/assets/22652276/e4451297-0316-4a67-bf58-47a750463041)

 Results: 

 ![image](https://github.com/HungryHowies/Zitadel-with-Opensearch-SSO/assets/22652276/f259c1a6-c060-439f-a7a3-4f2fa1b74ce8)



 

 

  
 





 






















