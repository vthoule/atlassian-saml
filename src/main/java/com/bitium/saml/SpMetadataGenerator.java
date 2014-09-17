package com.bitium.saml;

import javax.servlet.ServletException;

import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.Configuration;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataMemoryProvider;

public class SpMetadataGenerator {
	public MetadataProvider generate(SAMLConfig configuration) throws ServletException, MetadataProviderException {
		MetadataGenerator generator = new MetadataGenerator();
		generator.setKeyManager(new EmptyKeyManager());
		generator.setSignMetadata(false);
		
        // Defaults
        String alias = configuration.getAlias();
        String baseURL = configuration.getBaseUrl();

        generator.setEntityAlias(alias);
        generator.setEntityBaseURL(baseURL);

        // Use default entityID if not set
        if (generator.getEntityId() == null) {
            generator.setEntityId(configuration.getSpEntityId());
        }
        
        Configuration.getGlobalSecurityConfiguration().getKeyInfoGeneratorManager().getManager("MetadataKeyInfoGenerator");
        
        EntityDescriptor descriptor = generator.generateMetadata();
        ExtendedMetadata extendedMetadata = generator.generateExtendedMetadata();
        extendedMetadata.setRequireLogoutRequestSigned(false);

        MetadataMemoryProvider memoryProvider = new MetadataMemoryProvider(descriptor);
        memoryProvider.initialize();
        MetadataProvider spMetadataProvider = new ExtendedMetadataDelegate(memoryProvider, extendedMetadata);
        
        return spMetadataProvider;
	}
}
