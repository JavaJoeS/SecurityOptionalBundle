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
package org.eclipse.core.security.incoming;

import java.util.Optional;

import org.eclipse.core.security.ActivateSecurity;
import org.eclipse.core.security.encryption.NormalizeGCM;
import org.eclipse.core.security.state.X509SecurityState;
import org.eclipse.core.security.state.X509SecurityStateIfc;

import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.ServiceScope;

/*
 * This class checks to make sure the correct type is imported
 * 
 */
@Component(scope=ServiceScope.SINGLETON)
public class IncomingSystemProperty implements IncomingSystemPropertyIfc {
	@Reference X509SecurityStateIfc x509SecurityStateIfc;
	@Reference NormalizeGCM normalizeGCM;
	public IncomingSystemProperty() {}
	
	public boolean checkType() {
		Optional<String> type = null;
		if ( x509SecurityStateIfc == null ) {
			x509SecurityStateIfc = new X509SecurityState();
		}
		if ( normalizeGCM == null ) {
			normalizeGCM=new NormalizeGCM();
		}
		
		type = Optional.ofNullable(System.getProperty("javax.net.ssl.keyStoreType")); //$NON-NLS-1$
		try {
			if (!(type.isPresent())) {
				ActivateSecurity.getInstance().log("Continue without javax.net.ssl.keyStoreType.");//$NON-NLS-1$
				x509SecurityStateIfc.setTrustOn(true);
				return true;
			}
			if (type.get().equalsIgnoreCase("PKCS11")) { //$NON-NLS-1$
				x509SecurityStateIfc.setPKCS11on(true);
				return true;
			}
			if (type.get().equalsIgnoreCase("PKCS12")) { //$NON-NLS-1$
				x509SecurityStateIfc.setPKCS12on(true);
				return true;
			}
		} catch (Exception e) {
			ActivateSecurity.getInstance().log("IncomingSystemProperty null STATE");//$NON-NLS-1$
		}
		return false;
	}

	public boolean checkKeyStore(String pin) {
		byte[] salt = new byte[16];
		Optional<String> keyStore = null;
		Optional<String> keyStorePassword = null;
		Optional<String> PasswordEncrypted = null;
		Optional<String> PasswordDecrypted = null;
		
		if ( x509SecurityStateIfc == null ) {
			x509SecurityStateIfc = new X509SecurityState();
		}
		if ( normalizeGCM == null ) {
			normalizeGCM=new NormalizeGCM();
		}
		
		keyStore = Optional.ofNullable(System.getProperty("javax.net.ssl.keyStore")); //$NON-NLS-1$
		if (!(keyStore.isPresent())) {
			x509SecurityStateIfc.setPKCS11on(false);
			x509SecurityStateIfc.setPKCS12on(false);
		}
		keyStorePassword = Optional.ofNullable(System.getProperty("javax.net.ssl.keyStorePassword")); //$NON-NLS-1$
		if (keyStorePassword.isPresent()) {
			PasswordDecrypted = Optional.ofNullable(System.getProperty("javax.net.ssl.decryptedPassword")); //$NON-NLS-1$
			PasswordEncrypted = Optional.ofNullable(System.getProperty("javax.net.ssl.encryptedPassword")); //$NON-NLS-1$
			if ((PasswordEncrypted.isPresent()) || ((PasswordDecrypted.isPresent()))) {
				if (PasswordEncrypted.get().toString().equalsIgnoreCase("true")) { //$NON-NLS-1$
					salt = new String(System.getProperty("user.name") + pin).getBytes(); //$NON-NLS-1$
					String passwd = normalizeGCM.decrypt(keyStorePassword.get().toString(), pin,
							new String(salt));
					System.setProperty("javax.net.ssl.keyStorePassword", passwd); //$NON-NLS-1$
				}
			}
		}
		return true;
	}

	public boolean checkTrustStoreType() {
		Optional<String> type = null;
		
		if ( x509SecurityStateIfc == null ) {
			x509SecurityStateIfc = new X509SecurityState();
		}
		
		type = Optional.ofNullable(System.getProperty("javax.net.ssl.trustStoreType")); //$NON-NLS-1$
		if (!(type.isPresent())) {
			ActivateSecurity.getInstance().log("No incoming javax.net.ssl.trustStoreType."); //$NON-NLS-1$
			x509SecurityStateIfc.setTrustOn(false);
			return false;
		}
		x509SecurityStateIfc.setTrustOn(true);
		return true;

	}

	public boolean checkTrustStore() {
		Optional<String> trustStore = null;
		Optional<String> trustStorePassword = null;
		trustStore = Optional.ofNullable(System.getProperty("javax.net.ssl.trustStore")); //$NON-NLS-1$
		if (!(trustStore.isPresent())) {
			ActivateSecurity.getInstance().log("No truststore is set, javax.net.ssl.trustStore."); //$NON-NLS-1$
			return false;
		}
		trustStorePassword = Optional.ofNullable(System.getProperty("javax.net.ssl.trustStorePassword")); //$NON-NLS-1$
		if (!(trustStorePassword.isPresent())) {
			ActivateSecurity.getInstance().log("A truststore Password is required, javax.net.ssl.trustStorePassword."); //$NON-NLS-1$
			return false;
		}
		return true;
	}
}
