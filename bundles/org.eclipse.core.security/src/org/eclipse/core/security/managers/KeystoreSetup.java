/*******************************************************************************
 * Copyright (c) 2025 Eclipse Platform, Security Group and others.
 *
 * This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 *     Eclipse Platform - initial API and implementation
 *******************************************************************************/
package org.eclipse.core.security.managers;


import java.util.Optional;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;


import org.eclipse.core.security.ActivateSecurity;
import org.eclipse.core.security.SecurityComponentIfc;
import org.eclipse.core.security.incoming.IncomingSystemProperty;
import org.eclipse.core.security.incoming.IncomingSystemPropertyIfc;
import org.eclipse.core.security.incoming.SecurityFileSnapshot;
import org.eclipse.core.security.state.X509SecurityState;
import org.eclipse.core.security.state.X509SecurityStateIfc;
import org.eclipse.core.security.util.PKIProperties;
import org.eclipse.core.security.managers.KeyStoreManager;
import org.eclipse.core.security.managers.ConfigureTrust;

import org.osgi.framework.BundleContext;
//import org.eclipse.ecf.core.security.SSLContextFactory;
//import org.eclipse.ecf.internal.provider.filetransfer.httpclientjava.ECFHttpClientFactory;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.ServiceScope;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.ComponentContext;
import org.osgi.framework.ServiceReference;

/*
 *   This class checks the keystore type that have been input and ensure they match 
 */

//@Component(scope=ServiceScope.SINGLETON, immediate=true, configurationPolicy=ConfigurationPolicy.REQUIRE)
@Component(scope=ServiceScope.SINGLETON)
public class KeystoreSetup {
	boolean isPkcs11Installed = false;
	boolean isKeyStoreLoaded = false;
	@Reference
	//private ComponentContext context;
	private BundleContext context;
	Properties pkiProperties = null;
	SSLContext sslContext = null;
	
	SecurityComponentIfc securityComponentIfc;
	@Reference PKIProperties pKIProperties;
	@Reference KeyStoreManager keyStoreManager;
	@Reference ConfigureTrust configureTrust;
	@Reference X509SecurityStateIfc x509SecurityStateIfc;
	@Reference IncomingSystemPropertyIfc incomingSystemPropertyIfc;
	//@ServiceDependency(required=true)
	//SSLContextFactory sSLContextFactory;
	//@Reference ECFHttpClientFactory eCFHttpClientFactory;
	protected  KeyStore keyStore = null;
	
	private final int DIGITAL_SIGNATURE = 0;
	private final int KEY_CERT_SIGN = 5;
	private final int CRL_SIGN = 6;
	
	
	public KeystoreSetup() {}
	
	@Activate
	//public void activate(ComponentContext componentContext) {
	public void activate(BundleContext context) {
		this.context = context;
	}
	
	public void installKeystore() {
		Optional<KeyStore> keystoreContainer = null;
		try {
			if ( x509SecurityStateIfc == null ) {
				x509SecurityStateIfc = new X509SecurityState();
			}
			if ( keyStoreManager == null ) {
				keyStoreManager = new KeyStoreManager();
			}
			keystoreContainer = Optional.ofNullable(
					keyStoreManager.getKeyStore(System.getProperty("javax.net.ssl.keyStore"), //$NON-NLS-1$
							System.getProperty("javax.net.ssl.keyStorePassword"), //$NON-NLS-1$
							System.getProperty("javax.net.ssl.keyStoreType"))); //$NON-NLS-1$

			if ((keystoreContainer.isEmpty()) || (!(keyStoreManager.isKeyStoreInitialized()))) {
				ActivateSecurity.getInstance().log("Failed to Load a Keystore."); //$NON-NLS-1$
				x509SecurityStateIfc.setPKCS12on(false);
				System.clearProperty("javax.net.ssl.keyStoreType"); //$NON-NLS-1$
				System.clearProperty("javax.net.ssl.keyStore"); //$NON-NLS-1$
				System.clearProperty("javax.net.ssl.keyStoreProvider"); //$NON-NLS-1$
				System.clearProperty("javax.net.ssl.keyStorePassword"); //$NON-NLS-1$
			} else {
				ActivateSecurity.getInstance().log("A Keystore and Password are detected."); //$NON-NLS-1$
				keyStore = keystoreContainer.get();
				setKeyStoreLoaded(true);
			}
		} catch (Exception e) {
			ActivateSecurity.getInstance().log("Exception Loading a Keystore:"+e.getMessage()); //$NON-NLS-1$
		}
	}
	public void setPkiContext() {
		TrustManager[] tm=null;
		KeyManager[] km = null;
		if ( incomingSystemPropertyIfc == null ) {
			incomingSystemPropertyIfc = new IncomingSystemProperty();
		}
		if ( configureTrust == null ) {
			configureTrust = new ConfigureTrust();
		}
		
		if (incomingSystemPropertyIfc.checkTrustStoreType()) {
			if ((incomingSystemPropertyIfc.checkTrustStore())) {
				x509SecurityStateIfc.setTrustOn(true);
				Optional<X509TrustManager> PKIXtrust = configureTrust.setUp();
				if (PKIXtrust.isEmpty()) {
					ActivateSecurity.getInstance().log("Invalid TrustManager Initialization."); //$NON-NLS-1$
					return;
				}
				tm = new TrustManager[] { configureTrust };
				ActivateSecurity.getInstance().log("TrustManager Initialization Done."); //$NON-NLS-1$
			} else {
				ActivateSecurity.getInstance().log("Invalid TrustManager Initialization."); //$NON-NLS-1$
				return;
			}
		}
		
		if (isKeyStoreLoaded) {
			if (keyStoreManager.isKeyStoreInitialized()) {
				try {
					km = new KeyManager[] { keyStoreManager };
				} catch (Exception e) {
					ActivateSecurity.getInstance().log("No such Algorithm Initialization Error."); //$NON-NLS-1$
				} 
			} else {
				ActivateSecurity.getInstance().log("Valid KeyStore not found."); //$NON-NLS-1$
			}
		} 
		activateSecureContext(km,tm);
	}
	public void activateSecureContext( KeyManager[] km, TrustManager[] tm ) {
		try {
			Provider provider = Security.getProvider("SunJSSE");
			SSLContext ctx = SSLContext.getInstance("TLSv1.3", provider);//$NON-NLS-1$
			
			ctx.init(km, tm, null);
			
			SSLContext.setDefault(ctx);
			
			ActivateSecurity.getInstance().log("SSLContext NAME:"+SSLContext.getDefault().getProvider().getName()); //$NON-NLS-1$
			HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
			setSSLContext(ctx);
			pKIProperties = new PKIProperties();
			pKIProperties.load();
			ActivateSecurity.getInstance().setPkiUp(true);
			//ActivateSecurity.getInstance().setSSLContext(ctx);
			//SSLContext.getDefault().getProvider().getName();
			
			setUserEmail();
			ActivateSecurity.getInstance().log("SSLContext has been configured with SSLContext default.PROTO:"+SSLContext.getDefault().getProtocol()); //$NON-NLS-1$
			System.setProperty("javax.net.ssl.keyStoreProvider", "SunJSSE");//$NON-NLS-1$ //$NON-NLS-2$
			//getProviderList();
			
			try {
//				Object providerService = context.getServiceReference(“serviceName”);
//				Class serviceClass = providerService.getClass();
//				Method serviceMethod = serviceClass.getMethod(“methodName”);
//				Object result = serviceMethod.invoke(providerService);
				if ( this.context == null ) {
					ActivateSecurity.getInstance().log("Context null"); //$NON-NLS-1$
				}
				
//				if ( eCFHttpClientFactory == null ) {
//					//FrameworkUtil.getBundle((SSLContextFactory.getClass()).getBundleContext() );
//					
//					eCFHttpClientFactory = new ECFHttpClientFactory();
//					ActivateSecurity.getInstance().log("SSLContext ECF factory null"); //$NON-NLS-1$
//				}
//				eCFHttpClientFactory.newClient();
				ActivateSecurity.getInstance().log("SSLContextFactory has been set."); //$NON-NLS-1$
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
		} catch (KeyManagementException e) {
			ActivateSecurity.getInstance().log("KeystoreSetup - A KeyManagement error occured:"+e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			ActivateSecurity.getInstance().log("KeystoreSetup - No Algorithm for Provider:"+e.getMessage());
		}
	}
	public SSLContext getSSLContext() {
		return sslContext;
	}

	public void setSSLContext(SSLContext context) {
		this.sslContext = context;
	}

	public void setKeyStoreLoaded(boolean isKeyStoreLoaded) {
		//ActivateSecurity.getInstance().setKeyStoreLoaded(isKeyStoreLoaded);
	}
	private void setUserEmail() {
		try {
			Enumeration<String> en = keyStore.aliases();
			while (en.hasMoreElements()) {
				String alias = en.nextElement();
				// System.out.println(" " + alias);
				Certificate cert = keyStore.getCertificate(alias);
				if (cert.getType().equalsIgnoreCase("X.509")) {
					X509Certificate X509 = (X509Certificate) cert;

					//
					// we need to make sure this is a digital certificate instead of a server
					// cert or something
					//
					if (isDigitalSignature(X509.getKeyUsage())) {
						Collection<List<?>> altnames = X509.getSubjectAlternativeNames();
						if (altnames != null) {
							for (List<?> item : altnames) {
								Integer type = (Integer) item.get(0);
								if (type == 1)
									try {
										String userEmail = item.toArray()[1].toString();
										System.setProperty("mail.smtp.user", userEmail);
									} catch (Exception e) {
										e.printStackTrace();
									}
							}
						}

					}

				}
			}
		} catch (Exception err) {

		}
	}

	private boolean isDigitalSignature(boolean[] ba) {
		if (ba != null) {
			return ba[DIGITAL_SIGNATURE] && !ba[KEY_CERT_SIGN] && !ba[CRL_SIGN];
		} else {
			return false;
		}
	}

	public void getProviderList() {
		try {
		      Provider providers[] = Security.getProviders();
		      for(Provider p : providers) {
		    	  ActivateSecurity.getInstance().log(p.getName()+ "|" + p.getInfo());
		       }
		    } catch (Exception e) {
		      System.out.println(e);
		    }
	}
}
