package br.com.sso;

import java.io.IOException;
import java.util.List;
import java.util.logging.Logger;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.keycloak.adapters.AuthenticatedActionsHandler;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.PreAuthActionsHandler;
import org.keycloak.adapters.servlet.KeycloakOIDCFilter;
import org.keycloak.adapters.servlet.OIDCFilterSessionStore;
import org.keycloak.adapters.servlet.OIDCServletHttpFacade;
import org.keycloak.adapters.spi.AuthChallenge;
import org.keycloak.adapters.spi.AuthOutcome;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.adapters.spi.UserSessionManagement;

public class SeamKeycloakOIDCFilter extends KeycloakOIDCFilter {
	private static final Logger log = Logger.getLogger(SeamKeycloakOIDCFilter.class.getName());

	public void init(FilterConfig filterConfig) throws ServletException {
		super.init(filterConfig);
	}

	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		processFilter(request, response, chain);
	}

	private void processFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		log.fine("Keycloak OIDC Filter");
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;
		if (shouldSkip(request)) {
			chain.doFilter(req, res);
			return;
		}
		OIDCServletHttpFacade facade = new OIDCServletHttpFacade(request, response);
		KeycloakDeployment deployment = this.deploymentContext.resolveDeployment(facade);
		if (deployment == null || !deployment.isConfigured()) {
			response.sendError(403);
			log.fine("deployment not configured");
			return;
		}
		PreAuthActionsHandler preActions = new PreAuthActionsHandler(new UserSessionManagement() {
			public void logoutAll() {
				if (SeamKeycloakOIDCFilter.this.idMapper != null)
					SeamKeycloakOIDCFilter.this.idMapper.clear();
			}

			public void logoutHttpSessions(List<String> ids) {
				SeamKeycloakOIDCFilter.log.fine("**************** logoutHttpSessions");
				for (String id : ids) {
					SeamKeycloakOIDCFilter.log.finest("removed idMapper: " + id);
					SeamKeycloakOIDCFilter.this.idMapper.removeSession(id);
				}
			}
		}, this.deploymentContext, (HttpFacade) facade);
		if (preActions.handleRequest())
			return;
		this.nodesRegistrationManagement.tryRegister(deployment);
		OIDCFilterSessionStore tokenStore = new OIDCFilterSessionStore(request, facade, 100000, deployment, this.idMapper);
		tokenStore.checkCurrentToken();
		SeamKeycloakFilterRequestAuthenticator authenticator = new SeamKeycloakFilterRequestAuthenticator(deployment, tokenStore, facade, request, 8443);
		//FilterRequestAuthenticator authenticator = new FilterRequestAuthenticator(deployment, tokenStore, facade, request, 8443);
		AuthOutcome outcome = authenticator.authenticate();
		if (outcome == AuthOutcome.AUTHENTICATED) {
			log.fine("AUTHENTICATED");
			if (facade.isEnded())
				return;
			AuthenticatedActionsHandler actions = new AuthenticatedActionsHandler(deployment, facade);
			if (actions.handledRequest())
				return;
			HttpServletRequestWrapper wrapper = tokenStore.buildWrapper();
			chain.doFilter((ServletRequest) wrapper, res);
			return;
		}
		AuthChallenge challenge = authenticator.getChallenge();
		if (challenge != null) {
			log.fine("challenge");
			challenge.challenge((HttpFacade) facade);
			return;
		}
		response.sendError(403);
	}

	private boolean shouldSkip(HttpServletRequest request) {
		if (this.skipPattern == null)
			return false;
		String requestPath = request.getRequestURI().substring(request.getContextPath().length());
		return this.skipPattern.matcher(requestPath).matches();
	}
}
