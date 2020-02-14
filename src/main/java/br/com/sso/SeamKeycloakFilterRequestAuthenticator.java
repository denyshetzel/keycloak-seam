package br.com.sso;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.jboss.seam.Component;
import org.jboss.seam.security.Identity;
import org.jboss.seam.servlet.ContextualHttpServletRequest;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.adapters.AdapterTokenStore;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.OIDCHttpFacade;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.servlet.FilterRequestAuthenticator;

public class SeamKeycloakFilterRequestAuthenticator extends FilterRequestAuthenticator {
  public SeamKeycloakFilterRequestAuthenticator(KeycloakDeployment deployment, AdapterTokenStore tokenStore, OIDCHttpFacade facade, HttpServletRequest request, int sslRedirectPort) {
    super(deployment, tokenStore, facade, request, sslRedirectPort);
  }
  
  protected void completeBearerAuthentication(KeycloakPrincipal<RefreshableKeycloakSecurityContext> principal, String method) {
    super.completeBearerAuthentication(principal, method);
    login(principal);
  }
  
  protected void completeOAuthAuthentication(KeycloakPrincipal<RefreshableKeycloakSecurityContext> skp) {
    super.completeOAuthAuthentication(skp);
    login(skp);
  }
  
  private void login(final KeycloakPrincipal<RefreshableKeycloakSecurityContext> principal) {
    try {
      new ContextualHttpServletRequest(this.request) {
          public void process() throws Exception {
            Identity identity = (Identity)Component.getInstance(Identity.class);
            identity.getCredentials().setUsername(principal.getName());
            identity.authenticate();
          }
        }.run();
    } catch (ServletException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    } 
  }
}
