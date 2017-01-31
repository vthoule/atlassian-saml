package com.bitium.saml;

import java.util.HashMap;
import java.util.Map;

import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;

/**
 * 
 * @FQCN com.bitium.saml.SAMLStatuses
 * @author vthoule (Alkaes Consulting)
 * @since 1.0.0
 * @version 1.0.0
 * @description
 * Goal of this Class is to provide a more readable error message in case of not Successfull authentication.
 * Explanation of code have been identified fom https://msdn.microsoft.com/en-us/library/hh269642.aspx 
 */
public class SAMLStatusCodesProvider {

	private static SAMLStatusCodesProvider instance;
	
	private Map<String, String> statusCodes1stLevel = new HashMap<String, String>();
	private Map<String, String> statusCodes2ndLevel = new HashMap<String, String>();
	
	public static SAMLStatusCodesProvider getInstance() {
		if (instance == null) {
			instance = new SAMLStatusCodesProvider();
		}
		return instance;
	}
	
	protected SAMLStatusCodesProvider() {
		buildStatusCodeMap();
	}

	public Map<String, String> getStatusCodes1stLevel() {
		return statusCodes1stLevel;
	}
	
	public Map<String, String> getStatusCodes2ndLevel() {
		return statusCodes2ndLevel;
	}

	private void buildStatusCodeMap() {
		statusCodes1stLevel.put(StatusCode.SUCCESS_URI, "SUCCESS_URI");
		statusCodes1stLevel.put(StatusCode.REQUESTER_URI, "REQUESTER_URI");
		statusCodes1stLevel.put(StatusCode.RESPONDER_URI, "RESPONDER_URI");
		statusCodes1stLevel.put(StatusCode.VERSION_MISMATCH_URI, "VERSION_MISMATCH_URI");
		
		statusCodes2ndLevel.put(StatusCode.AUTHN_FAILED_URI, "AUTHN_FAILED_URI");
		statusCodes2ndLevel.put(StatusCode.INVALID_ATTR_NAME_VALUE_URI, "INVALID_ATTR_NAME_VALUE_URI");
		statusCodes2ndLevel.put(StatusCode.INVALID_NAMEID_POLICY_URI, "INVALID_NAMEID_POLICY_URI");
		statusCodes2ndLevel.put(StatusCode.NO_AUTHN_CONTEXT_URI, "NO_AUTHN_CONTEXT_URI");
		statusCodes2ndLevel.put(StatusCode.NO_AVAILABLE_IDP_URI, "NO_AVAILABLE_IDP_URI");
		statusCodes2ndLevel.put(StatusCode.NO_PASSIVE_URI, "NO_PASSIVE_URI");
		statusCodes2ndLevel.put(StatusCode.NO_SUPPORTED_IDP_URI, "NO_SUPPORTED_IDP_URI");
		statusCodes2ndLevel.put(StatusCode.PARTIAL_LOGOUT_URI, "PARTIAL_LOGOUT_URI");
		statusCodes2ndLevel.put(StatusCode.PROXY_COUNT_EXCEEDED_URI, "PROXY_COUNT_EXCEEDED_URI");
		statusCodes2ndLevel.put(StatusCode.REQUEST_DENIED_URI, "REQUEST_DENIED_URI");
		statusCodes2ndLevel.put(StatusCode.REQUEST_UNSUPPORTED_URI, "REQUEST_UNSUPPORTED_URI");
		statusCodes2ndLevel.put(StatusCode.REQUEST_VERSION_DEPRECATED_URI, "REQUEST_VERSION_DEPRECATED_URI");
		statusCodes2ndLevel.put(StatusCode.REQUEST_VERSION_TOO_HIGH_URI, "REQUEST_VERSION_TOO_HIGH_URI");
		statusCodes2ndLevel.put(StatusCode.REQUEST_VERSION_TOO_LOW_URI, "REQUEST_VERSION_TOO_LOW_URI");
		statusCodes2ndLevel.put(StatusCode.RESOURCE_NOT_RECOGNIZED_URI, "RESOURCE_NOT_RECOGNIZED_URI");
		statusCodes2ndLevel.put(StatusCode.TOO_MANY_RESPONSES, "TOO_MANY_RESPONSES");
		statusCodes2ndLevel.put(StatusCode.UNKNOWN_ATTR_PROFILE_URI, "UNKNOWN_ATTR_PROFILE_URI");
		statusCodes2ndLevel.put(StatusCode.UNKNOWN_PRINCIPAL_URI, "UNKNOWN_PRINCIPAL_URI");
		statusCodes2ndLevel.put(StatusCode.UNSUPPORTED_BINDING_URI, "UNSUPPORTED_BINDING_URI");
	}

	public class StatusCodesExplained {
		protected String statusMessageText;

		protected String statusCode1stLevel;
		protected String statusCode2ndLevel;
		
		protected String keyOfstatusCode1stLevel;
		protected String keyOfstatusCode2ndLevel;
		
		protected String msgCode1stlevel;
		protected String msgCode2ndlevel;
		protected String msgError;
		
		public String getMsgError() {
			return msgError;
		}
		public void setMsgError(String msgError) {
			this.msgError = msgError;
		}
		public String getStatusCode1stLevel() {
			return statusCode1stLevel;
		}
		public void setStatusCode1stLevel(String statusCode1stLevel) {
			this.statusCode1stLevel = statusCode1stLevel;
		}
		public String getStatusCode2ndLevel() {
			return statusCode2ndLevel;
		}
		public void setStatusCode2ndLevel(String statusCode2ndLevel) {
			this.statusCode2ndLevel = statusCode2ndLevel;
		}
		public String getStatusMessageText() {
			return statusMessageText;
		}
		public void setStatusMessageText(String statusMessageText) {
			this.statusMessageText = statusMessageText;
		}
		public String getKeyOfstatusCode1stLevel() {
			return keyOfstatusCode1stLevel;
		}
		public void setKeyOfstatusCode1stLevel(String keyOfstatusCode1stLevel) {
			this.keyOfstatusCode1stLevel = keyOfstatusCode1stLevel;
		}
		public String getKeyOfstatusCode2ndLevel() {
			return keyOfstatusCode2ndLevel;
		}
		public void setKeyOfstatusCode2ndLevel(String keyOfstatusCode2ndLevel) {
			this.keyOfstatusCode2ndLevel = keyOfstatusCode2ndLevel;
		}
		public String getMsgCode1stlevel() {
			return msgCode1stlevel;
		}
		public void setMsgCode1stlevel(String msgCode1stlevel) {
			msgCode1stlevel = msgCode1stlevel;
		}
		public String getMsgCode2ndlevel() {
			return msgCode2ndlevel;
		}
		public void setMsgCode2ndlevel(String msgCode2ndlevel) {
			msgCode2ndlevel = msgCode2ndlevel;
		}

	}
	
	public StatusCodesExplained getStatusCodesExplained(final Status status) {
		StatusCode statusCode = status.getStatusCode();
		StatusCodesExplained statusCodesExplained = new StatusCodesExplained();
		StatusMessage statusMessage = status.getStatusMessage();

   	
   	String statusCode1stLevel = statusCode.getValue();
   	String statusCode2ndLevel = (statusCode.getStatusCode() != null) ? statusCode.getStatusCode().getValue() : null;
   	String statusMessageText = (statusMessage != null) ? statusMessage.getMessage() : null;
   	
   	String keyOfstatusCode1stLevel = getStatusCodes1stLevel().get(statusCode1stLevel);
   	String keyOfstatusCode2ndLevel = getStatusCodes1stLevel().get(statusCode2ndLevel);
   	
   	statusCodesExplained.setStatusCode1stLevel(statusCode1stLevel);
   	statusCodesExplained.setStatusCode2ndLevel(statusCode2ndLevel);
   	statusCodesExplained.setStatusMessageText(statusMessageText);
   	
   	statusCodesExplained.setKeyOfstatusCode1stLevel(keyOfstatusCode1stLevel);
   	statusCodesExplained.setKeyOfstatusCode2ndLevel(keyOfstatusCode2ndLevel);
   	
   	return statusCodesExplained;
	}
	
	
}
