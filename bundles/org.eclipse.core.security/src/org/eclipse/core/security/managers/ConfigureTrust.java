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


import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Optional;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.eclipse.core.security.ActivateSecurity;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ServiceScope;

@Component(scope=ServiceScope.SINGLETON)
public class ConfigureTrust implements X509TrustManager {
	
	protected X509TrustManager pkixTrustManager = null;
	public ConfigureTrust() {}
	

	public Optional<X509TrustManager> setUp() {
		KeyStore keyStore = null;
		String storeLocation = null;
		String trustType = null;
		String passwd = "changeit"; //$NON-NLS-1$
		try {
			Optional<String> trustStoreFile = Optional.ofNullable(System.getProperty("javax.net.ssl.trustStore")); //$NON-NLS-1$
			if (trustStoreFile.isPresent()) {
				storeLocation = trustStoreFile.get().toString();
			} else {
				storeLocation = System.getProperty("java.home") + //$NON-NLS-1$
						"/lib/security/cacerts" //$NON-NLS-1$
								.replace("/", FileSystems.getDefault().getSeparator()); //$NON-NLS-1$
			}
			InputStream fs = Files.newInputStream(Paths.get(storeLocation));
			
			Optional<String> trustStoreFileType = Optional
					.ofNullable(System.getProperty("javax.net.ssl.trustStoreType")); //$NON-NLS-1$
			if (trustStoreFileType.isPresent()) {
				trustType = trustStoreFileType.get().toString();
			} else {
				trustType = KeyStore.getDefaultType();		
			}
			keyStore = KeyStore.getInstance(trustType);

			//  Set the TrustStore default well known value set and over ride if property present
			Optional<String> trustStorePassword = Optional
					.ofNullable(System.getProperty("javax.net.ssl.trustStorePassword")); //$NON-NLS-1$
			if (trustStorePassword.isPresent()) {
				ActivateSecurity.getInstance().log("ConfigureTrust using Provided Password from property."); //$NON-NLS-1$
				passwd = trustStorePassword.get().toString();
			}

			keyStore.load(fs, passwd.toCharArray());

			TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX"); //$NON-NLS-1$
			tmf.init(keyStore);
			TrustManager tms[] = tmf.getTrustManagers();
			for (TrustManager tm : tms) {
				if (tm instanceof X509TrustManager) {
					pkixTrustManager = (X509TrustManager) tm;
					break;
				}
			}
		} catch (NoSuchAlgorithmException e) {
			ActivateSecurity.getInstance().log("ConfigureTrust - No algorithm found."); //$NON-NLS-1$
		} catch (KeyStoreException e) {
			ActivateSecurity.getInstance().log("ConfigureTrust - Initialize keystore Error. "); //$NON-NLS-1$
		} catch (FileNotFoundException e) {
			ActivateSecurity.getInstance().log("ConfigureTrust - No File Found:"); //$NON-NLS-1$
		} catch (CertificateException e) {
			ActivateSecurity.getInstance().log("ConfigureTrust - Certificate Error"); //$NON-NLS-1$
		} catch (IOException e) {
			ActivateSecurity.getInstance().log("ConfigureTrust - I/O Error, bad password?"); //$NON-NLS-1$
		}
		return Optional.ofNullable(pkixTrustManager);
	}

	@Override
	public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		pkixTrustManager.checkClientTrusted(chain, authType);
	}

	@Override
	public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
		pkixTrustManager.checkServerTrusted(chain, authType);
	}

	@Override
	public X509Certificate[] getAcceptedIssuers() {
		return pkixTrustManager.getAcceptedIssuers();

	}
}
