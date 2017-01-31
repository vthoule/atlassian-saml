package com.bitium.saml.servlet;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URI;
import java.security.Principal;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.SAMLException;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.util.SAMLUtil;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.saml.websso.WebSSOProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;

import com.atlassian.seraph.auth.DefaultAuthenticator;
import com.bitium.saml.SAMLContext;
import com.bitium.saml.SAMLStatusCodesProvider;
import com.bitium.saml.SAMLStatusCodesProvider.StatusCodesExplained;
import com.bitium.saml.config.SAMLConfig;

public abstract class SsoLoginServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;

	public static final String OS_DESTINATION_KEY = "os_destination";
	public static final String SAML_STATUSCODES_EXPLAINED_KEY = "saml_statuscodes_explained";

	protected Log log = LogFactory.getLog(SsoLoginServlet.class);

	protected SAMLConfig saml2Config;

	protected SAMLCredential credential;

	protected SAMLStatusCodesProvider samlStatusCodesProvider;

	@Override
	public void init() throws ServletException {
		super.init();
	}

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

		storeRedirectDestinationInSession(request);

		try {
			SAMLContext context = new SAMLContext(request, saml2Config);
			SAMLMessageContext messageContext = context.createSamlMessageContext(request, response);

			// Generate options for the current SSO request
			WebSSOProfileOptions options = new WebSSOProfileOptions();
			options.setBinding(org.opensaml.common.xml.SAMLConstants.SAML2_REDIRECT_BINDING_URI);
			options.setIncludeScoping(false);

			// Send request
			WebSSOProfile webSSOprofile = new WebSSOProfileImpl(context.getSamlProcessor(), context.getMetadataManager());
			webSSOprofile.sendAuthenticationRequest(messageContext, options);
		} catch (Exception e) {
			redirectToLoginWithSAMLError(response, e, "general");
		}
	}

	private void storeRedirectDestinationInSession(HttpServletRequest request) throws UnsupportedEncodingException {
		String refererURL = request.getHeader("Referer");
		String osDestination = null;
		if (refererURL != null) {
			try {
				URI url = new URI(refererURL);
				String queryString = url.getRawQuery();
				if (queryString != null) {
					String[] params = queryString.split("&");
					for (String param : params) {
						String key = param.substring(0, param.indexOf('='));
						if (key.equals(OS_DESTINATION_KEY)) {
							String val = param.substring(param.indexOf('=') + 1);
							osDestination = java.net.URLDecoder.decode(val, "UTF-8");
						}
					}
				}
			} catch (java.net.URISyntaxException ignored) {
			}
		}

		if (osDestination != null) {
			request.getSession().setAttribute(OS_DESTINATION_KEY, osDestination);
		}
	}

	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException {
		try {
			SAMLContext context = new SAMLContext(request, saml2Config);
			SAMLMessageContext messageContext = context.createSamlMessageContext(request, response);

			// Process response
			context.getSamlProcessor().retrieveMessage(messageContext);

			messageContext.setLocalEntityEndpoint(SAMLUtil.getEndpoint(messageContext.getLocalEntityRoleMetadata().getEndpoints(), messageContext.getInboundSAMLBinding(), new HttpServletRequestAdapter(request)));
			messageContext.getPeerEntityMetadata().setEntityID(saml2Config.getIdpEntityId());

			WebSSOProfileConsumerImpl consumer = new WebSSOProfileConsumerImpl(context.getSamlProcessor(), context.getMetadataManager());
			consumer.setMaxAuthenticationAge(saml2Config.getMaxAuthenticationAge());
			try {
				credential = consumer.processAuthenticationResponse(messageContext);
			} catch (SAMLException se) {
				redirectWithError(messageContext, request, response, se);
				return;
			}

			request.getSession().setAttribute("SAMLCredential", credential);

			String uidAttribute = saml2Config.getUidAttribute();
			String userName = uidAttribute.equals("NameID") ? credential.getNameID().getValue() : credential.getAttributeAsString(uidAttribute);

			authenticateUserAndLogin(request, response, userName);
		} catch (Exception e) {
			redirectToLoginWithSAMLError(response, e, "plugin_exception");
		}
	}

	protected String redirectWithError(SAMLMessageContext messageContext, HttpServletRequest request, HttpServletResponse response, SAMLException se) throws ServletException {
		Response samlResponse = (Response) messageContext.getInboundSAMLMessage();
      // Retrieve statusCodes
		Status status = samlResponse.getStatus();
		StatusCode statusCode = status.getStatusCode();
		
      if (!StatusCode.SUCCESS_URI.equals(statusCode)) {
      	StatusCodesExplained statusCodesExplained = samlStatusCodesProvider.getStatusCodesExplained(status);
      	statusCodesExplained.setMsgCode1stlevel(getText(statusCodesExplained.getKeyOfstatusCode1stLevel(), null));
      	statusCodesExplained.setMsgCode2ndlevel(getText(statusCodesExplained.getKeyOfstatusCode2ndLevel(), null));
      	request.getSession().setAttribute(SAML_STATUSCODES_EXPLAINED_KEY, statusCodesExplained);
      	redirectToLogoutWithSAMLError(response);
      } else {
      	redirectToLoginWithSAMLError(response, se, "plugin_exception");
      }
		return "";
	}
	
	protected void redirectToLogoutWithSAMLError(HttpServletResponse response) throws ServletException {
		try {
			if (saml2Config.hasUrlOnLoginError()) {
				response.sendRedirect(getUrlOnLoginError() + "?samlerror=true");
			} else if (saml2Config.hasLoggedOutPageTemplate()) {
				response.sendRedirect(getLoggedOutUrl() + "?samlerror=true");
			} else {
				response.sendRedirect(getLogoutUrl() + "?samlerror=true");
			}
		} catch (IOException ioException) {
			throw new ServletException();
		}
	}

	protected abstract String getText(String _key, Object _args);
	
	protected abstract void authenticateUserAndLogin(HttpServletRequest request, HttpServletResponse response, String username) throws Exception;

	protected Boolean authoriseUserAndEstablishSession(DefaultAuthenticator authenticator, Object userObject, HttpServletRequest request, HttpServletResponse response) throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
		// Note: Need to use reflection to call the protected DefaultAuthenticator.authoriseUserAndEstablishSession
		Principal principal = (Principal) userObject;

		Method authUserMethod = DefaultAuthenticator.class.getDeclaredMethod("authoriseUserAndEstablishSession", new Class[] { HttpServletRequest.class, HttpServletResponse.class, Principal.class });
		authUserMethod.setAccessible(true);
		return (Boolean) authUserMethod.invoke(authenticator, new Object[] { request, response, principal });
	}

	protected void redirectToSuccessfulAuthLandingPage(HttpServletRequest request, HttpServletResponse response) throws IOException {
		String redirectUrl = saml2Config.getRedirectUrl();
		if (redirectUrl == null || redirectUrl.equals("")) {
			if (request.getSession() != null && request.getSession().getAttribute(OS_DESTINATION_KEY) != null) {
				String os_destination = request.getSession().getAttribute(OS_DESTINATION_KEY).toString();
				redirectUrl = saml2Config.getBaseUrl() + os_destination;
			} else {
				redirectUrl = getDashboardUrl();
			}
		}
		response.sendRedirect(redirectUrl);
	}

	protected void redirectToLoginWithSAMLError(HttpServletResponse response, Exception exception, String string) throws ServletException {
		try {
			if (exception != null) {
				log.error("saml plugin error + " + exception.getMessage());
			}
			response.sendRedirect(getLoginFormUrl() + "?samlerror=" + string);
		} catch (IOException ioException) {
			throw new ServletException();
		}
	}

	protected abstract Object tryCreateOrUpdateUser(String userName) throws Exception;

	protected abstract String getDashboardUrl();

	protected abstract String getLoginFormUrl();

	protected abstract String getLogoutUrl();
	
	protected String getUrlOnLoginError() {
		return saml2Config.getUrlOnLoginError();
	}
	protected abstract String getLoggedOutUrl();

	public void setSaml2Config(SAMLConfig saml2Config) {
		this.saml2Config = saml2Config;
	}
}
