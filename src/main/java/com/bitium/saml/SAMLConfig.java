package com.bitium.saml;

public interface SAMLConfig {

	String getAlias();

	String getBaseUrl();

	String getSpEntityId();

	String getIdpEntityId();

	void setDefaultBaseUrl(String defaultBaseURL);

	String getLoginUrl();

	String getX509Certificate();

	String getLogoutUrl();

}
