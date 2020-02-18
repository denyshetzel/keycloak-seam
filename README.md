# keycloak-seam

This project is an extension of the KeycloakOIDCFilter with the objective of integration between Keycloak and Jboss Seam

<b>web.xml</b>
```xml
<filter>
    <filter-name>Keycloak Filter</filter-name>
    <filter-class>br.com.sso.SeamKeycloakOIDCFilter</filter-class>
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

<b>component.xml</b>
```xml
<security:identity authenticate-method="#{authenticator.authenticate}"/>
```

```java
@Stateless
@Name("authenticator")
public class AuthenticatorAction {
    ...

    public boolean authenticate() {
        // your login logic
        return true;
    }

    ...
}
```
