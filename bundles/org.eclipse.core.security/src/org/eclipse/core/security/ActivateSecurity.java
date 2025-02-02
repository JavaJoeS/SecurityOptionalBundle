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
package org.eclipse.core.security;

import org.eclipse.core.runtime.ServiceCaller;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;
import java.util.Properties;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.io.File;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.eclipse.core.pki.AuthenticationBase;
import org.eclipse.core.pki.pkiselection.PKIProperties;
import org.eclipse.core.pki.util.ConfigureTrust;
import org.eclipse.core.pki.util.KeyStoreFormat;
import org.eclipse.core.pki.util.KeyStoreManager;
import org.eclipse.core.pki.util.LogUtil;

import org.eclipse.core.resources.IWorkspaceRoot;
import org.eclipse.core.resources.ResourcesPlugin;
import org.eclipse.core.resources.IResource;
import org.eclipse.core.resources.IMarker;
import org.eclipse.core.runtime.RegistryFactory;
import org.eclipse.core.runtime.spi.RegistryStrategy;
import org.eclipse.core.runtime.IExtensionRegistry;
import org.eclipse.core.runtime.CoreException;
import org.eclipse.core.runtime.ILog;
import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.core.runtime.IAdapterFactory;
import org.eclipse.core.runtime.QualifiedName;
import org.eclipse.core.runtime.Platform;
import org.eclipse.ui.IStartup;
import org.eclipse.ui.IWorkbench;
import org.eclipse.ui.PlatformUI;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;

public class ActivateSecurity implements BundleActivator, IStartup {
	public static final String ID = "org.eclipse.core.pki"; //$NON-NLS-1$
	protected final String pin = "#Gone2Boat@Bay"; //$NON-NLS-1$
	private static ActivateSecurity instance;
	
	
	static boolean isPkcs11Installed = false;
	static boolean isKeyStoreLoaded = false;
	private BundleContext context;
	SSLContext sslContext = null;
	
	private static final ServiceCaller<ILog> logger = new ServiceCaller(PKISetup.class, ILog.class);
	protected static KeyStore keyStore = null;
	PKIProperties pkiInstance = null;
	Properties pkiProperties = null;
	Optional<KeyStore> keystoreContainer = null;
	private static final int DIGITAL_SIGNATURE = 0;
	private static final int KEY_CERT_SIGN = 5;
	private static final int CRL_SIGN = 6;

	
	public ActivateSecurity() {
		super();
		setInstance(this);
	}

	@Override
	public void start(BundleContext context) throws Exception {
		this.context = context;
		Startup();
	}
	@Override 
	public void earlyStartup() {
		// required by implementation
	}

	@Override
	public void stop(BundleContext context) throws Exception {
		context=null;
	}

	public static ActivateSecurity getInstance() {
		return instance;
	}

	public static void setInstance(PKISetup instance) {
		PKISetup.instance = instance;
	}

	public void log(String message) {
		logger.call(logger -> logger.info(message));
	}

	public void Startup() {

		// log("Startup method is now running"); //$NON-NLS-1$

		Optional<String> type = null;
		Optional<String> decryptedPw;

		X509SecurityState.CONTROL.setPKCS11on(false);
		X509SecurityState.CONTROL.setPKCS12on(false);
		/*
		 * First see if parameters were passed into eclipse via the command line -D
		 */
		type = Optional.ofNullable(System.getProperty("javax.net.ssl.keyStoreType")); //$NON-NLS-1$

		if (type.isEmpty()) {
			//
			// Incoming parameter as -DkeystoreType was empty so CHECK in .pki file
			//
			PKIState.CONTROL.setPKCS11on(false);
			PKIState.CONTROL.setPKCS12on(false);
			if (PublicKeySecurity.INSTANCE.isTurnedOn()) {
				PublicKeySecurity.INSTANCE.getPkiPropertyFile(pin);
			}
		}
		// LogUtil.logInfo("PKISetup - now looking at incoming"); //$NON-NLS-1$
		if (IncomingSystemProperty.SETTINGS.checkType()) {
			if (IncomingSystemProperty.SETTINGS.checkKeyStore(pin)) {
				KeystoreSetup setup = KeystoreSetup.getInstance();
				if (PKIState.CONTROL.isPKCS12on()) {
					
					setup.installKeystore();
					
				}
				if (PKIState.CONTROL.isPKCS11on()) {
					String pkcs11Pin = "";
					LogUtil.logInfo("PKISetup - Processing PKCS11"); //$NON-NLS-1$
					decryptedPw = Optional.ofNullable(System.getProperty("javax.net.ssl.keyStorePassword"));
					if (!decryptedPw.isEmpty()) {
						pkcs11Pin = decryptedPw.get();
					}
					keystoreContainer = Optional
							.ofNullable(AuthenticationBase.INSTANCE.initialize(pkcs11Pin.toCharArray()));// $NON-NLS-1$
					if (keystoreContainer.isEmpty()) {
						LogUtil.logError("PKISetup - Failed to Load a Keystore.", null); //$NON-NLS-1$
						PKIState.CONTROL.setPKCS11on(false);
						System.clearProperty("javax.net.ssl.keyStoreType"); //$NON-NLS-1$
						System.clearProperty("javax.net.ssl.keyStore"); //$NON-NLS-1$
						System.clearProperty("javax.net.ssl.keyStoreProvider"); //$NON-NLS-1$
						System.clearProperty("javax.net.ssl.keyStorePassword"); //$NON-NLS-1$
						SecurityFileSnapshot.INSTANCE.restoreProperties();
					} else {
						LogUtil.logError("A Keystore and Password are detected.", null); //$NON-NLS-1$
						keyStore = keystoreContainer.get();
						KeyStoreManager.INSTANCE.setKeyStore(keyStore);
						setKeyStoreLoaded(true);
						setup.setPkiContext();
					}
				}
			}
		}
	}

	public SSLContext getSSLContext() {
		return sslContext;
	}

	public void setSSLContext(SSLContext context) {
		this.sslContext = context;
	}

	private boolean isKeyStoreLoaded() {
		return isKeyStoreLoaded;
	}

	private void setKeyStoreLoaded(boolean isKeyStoreLoaded) {
		PKISetup.isKeyStoreLoaded = isKeyStoreLoaded;
	}

	private static boolean isDigitalSignature(boolean[] ba) {
		if (ba != null) {
			return ba[DIGITAL_SIGNATURE] && !ba[KEY_CERT_SIGN] && !ba[CRL_SIGN];
		} else {
			return false;
		}
	}

	private void setupAdapter() {
	
		IAdapterFactory pr = new IAdapterFactory() {
	        @Override
	        public Class[] getAdapterList() {
	                return new Class[] { SSLContext.class };
	        }
	        
			@Override
			public <T> T getAdapter(Object adaptableObject, Class<T> adapterType) {
					IResource res = (IResource) adaptableObject;
					SSLContext v = null;
					QualifiedName key = new QualifiedName("org.eclipse.core.pki", "context");//$NON-NLS-1$
					try {
						v = (SSLContext) res.getSessionProperty(key);
						if (v == null) {
							v = getSSLContext();
							res.setSessionProperty(key, v);
						}
					} catch (CoreException e) {
						// unable to access session property - ignore
					}
					return (T)v;
			}
		};
		Platform.getAdapterManager().registerAdapters(pr,IResource.class);
	}
}