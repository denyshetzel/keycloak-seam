# keycloak-seam

This project has the objective the integration between Keycloak and Jboss Seam.

web.xml
```xml
<filter>
    <filter-name>Keycloak Filter</filter-name>
    <filter-class>com.yourpackage.SeamKeycloakOIDCFilter</filter-class>
  <init-param>
    <param-name>keycloak.config.skipPattern</param-name>
    <param-value>^/(.js|.css)</param-value>
</init-param>
</filter>
<filter-mapping>
    <filter-name>Keycloak Filter</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
```

component.xml
```xml
<security:identity authenticate-method="#{authenticator.authenticate}"/>
```
