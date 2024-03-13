# Zitadel-with-Opensearch-SAML-SSO

## Overview

 The following documentation explains the configurations needed for OpenSearch Single sign-on (SSO) and the connection to Zitadel instance. OpenSearch node must be in Production mode, meaning you have created the certificate for "node/s, admin and CA" and ensure HTTPS is working correct. Take note this is a basic configuration setup to start SSO with OpenSearch using Zitadel.

## Prerequisite:
* Ubuntu-22.0.4
* Updates/Upgrades Completed
* Network Configured (Static address and DNS)
* Date/Time is set
* Opensearch-2.11.1
* Zitadel-v2.44.2 +

To use SAML for authentication, configurations are needed in the **authc** section of this file  *vi /etc/opensearch/opensearch-security/config.yml*. Setup authentication_backend to noop. Place all SAML-specific configuration options in config.yml file, under the section *saml_auth_domain:*. Ensure the order number is correct. In the example below the saml_auth_domain ORDER is set to 1 and basic_internal_auth_domain is set to "0". The  basic_internal_auth_domain challenge is set from true to false.


NOTE: The Security plugin can read IdP metadata either from a URL or a file. In this example Im using URL.

### Edit config.conf file.

```
vi /etc/opensearch/opensearch-security/config.yml
```

### Configure section "authc"

Get the exchange_key from Zitadel using the endpoint **/saml/v2/metadata** on the Zitadel instances URL. 
I found the correct key in Zitadel's XML is locate here.

```
<DigestMethod xmlns="http://www.w3.org/2000/09/xmldsig#" 
             Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
<DigestValue 
xmlns="http://www.w3.org/2000/09/xmldsig#">8nZHHDNt2HUSETHISONEQPD01eCWS8NfSsmfBwBFQ=</DigestValue>
     </Reference>
</SignedInfo>
```

Zitadels metadata URL location.

```
https://zitadel-self-hosting.com/saml/v2/metadata
```

Add the following SAML settings in the config.yml file under *authc:*
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
         exchange_key: AwqgAwIBAgICAY4wDQYJKoZIhvcNANjA2NT1UEChC0SOMETHING
       authentication_backend:
          type: noop
  ```
### basic_internal_auth_domain Section

Change the challenge flag in basic_internal_auth_domain section from true to false.
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

  
###  OpenSearch Dashboards configuration


Edit Opensearch-Dashboard yaml file.

```
vi /etc/opensearch-dashboards/opensearch_dashboards.yml
```

(Option) Change the name on SSO button.

```
opensearch_security.ui.saml.login.buttonname: Zitadel
```

The SAML-specific configuration is done with the  Security plugin,  activate SAML in your opensearch_dashboards.yml file by adding the following:


```
opensearch_security.auth.type: "saml"
```

Add the OpenSearch Dashboards endpoint for validating the SAML assertions to your allow list.

```
server.xsrf.allowlist: ["/_opendistro/_security/saml/acs", "/_opendistro/_security/saml/logout"]
```

### Execute Security Script 

This will apply any configuration done from the steps above.

Change directory.

```
cd /usr/share/opensearch/plugins/opensearch-security/tools/
```

If the configuration files are completed, execute the security script. The command below will applying the new configurations made from the file config.yml.

```
./securityadmin.sh -h opensearch.domai.com -f /etc/opensearch/opensearch-security/config.yml    -cacert /etc/opensearch/root-ca.pem -cert /etc/opensearch/admin.pem -key /etc/opensearch/admin-key.pem -icl -nhnv
```

Restart Opensearch

```
systemctl restart opensearch
```

Restart OpenSearch-Dashboards

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

NOTE: I did add a section for LOGOUT as shown below.

```
<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"                     
                     entityID="https://opensearch.domain.com:5601">
    <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                Location="https://opensearch.domain.com:5601/_opendistro/_security/saml/logout" />
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                     Location="https://opensearch.domain.com:5601/_opendistro/_security/saml/acs" index="0" />
        
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


 ### Opensearch Logging off with 404

 When logging off,  I recieved a 404 error.

***{"statusCode":404,"error":"Not Found","message":"Not Found"}***
 
Found the solution   [Here](https://forum.opensearch.org/t/saml-issue-on-logout/5617/16?u=gsmitt)

What I did was edit the following file. Line (308,15)

```
vi /usr/share/opensearch-dashboards/plugins/securityDashboards/server/auth/types/saml/routes.js
```
Commented out this line.

```
//  const redirectUrl = authInfo.sso_logout_url || this.coreSetup.http.basePath.serverBasePath || '/';
```

Added this line.

```
const redirectUrl = `${this.coreSetup.http.basePath.serverBasePath}/app/home`;
```

Results:

![image](https://github.com/HungryHowies/Zitadel-with-Opensearch-SSO/assets/22652276/fc0f0851-5ac2-4010-988b-4560ce2c210d)
 

 

  
 





 






















