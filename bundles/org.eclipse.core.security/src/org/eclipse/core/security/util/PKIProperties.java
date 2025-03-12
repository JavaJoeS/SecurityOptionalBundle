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
package org.eclipse.core.security.util;

import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.util.Optional;

import org.osgi.service.component.annotations.ServiceScope;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.ComponentContext;

@Component(scope=ServiceScope.SINGLETON)
public class PKIProperties extends Authenticator {

	private String keyStore = ""; //$NON-NLS-1$
	private String keyStoreType = ""; //$NON-NLS-1$
	private String keyStoreProvider = ""; //$NON-NLS-1$
	private String username = null;
	private transient String keyStorePassword = ""; //$NON-NLS-1$
	private static PKI lastPKI=null;
	

	public PKIProperties() {}
	
	@Activate
	void activate(ComponentContext componentContext) {
		
	}
	
	@Override
	public PasswordAuthentication getPasswordAuthentication() {
		PasswordAuthentication auth = null;

		try {
			auth = new PasswordAuthentication(this.getUsername(), this.getKeyStorePassword().toCharArray() );
		} catch (Exception e) {
			e.printStackTrace();
		}

		return auth;
	}
	public String getKeyStore() {
		return keyStore;
	}
	public void setKeyStore(String keyStore) {
		this.keyStore = keyStore;
	}
	public String getKeyStoreType() {
		return keyStoreType;
	}
	public void setKeyStoreType(String keyStoreType) {
		this.keyStoreType = keyStoreType;
	}
	public String getKeyStoreProvider() {
		return keyStoreProvider;
	}
	public void setKeyStoreProvider(String keyStoreProvider) {
		this.keyStoreProvider = keyStoreProvider;
	}
	public String getKeyStorePassword() {
		return keyStorePassword;
	}
	public void setKeyStorePassword(String keyStorePassword) {
		this.keyStorePassword = keyStorePassword;
	}
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public void restore() {
		try {
			if (( this.getKeyStore() != null ) &&
				( this.getKeyStoreType() != null ) &&
				( this.getKeyStoreProvider() != null) &&
				( this.getKeyStorePassword() != null) ) {

				if ( !(this.getKeyStore().isEmpty()) ) {
					System.setProperty("javax.net.ssl.keyStore", this.getKeyStore()); //$NON-NLS-1$
				}

				if ( !(this.getKeyStoreType().isEmpty()) ) {
					System.setProperty("javax.net.ssl.keyStoreType", this.getKeyStoreType()); //$NON-NLS-1$
				}

				if ( !(this.getKeyStoreProvider().isEmpty() )) {
					System.setProperty("javax.net.ssl.keyStoreProvider", this.getKeyStoreProvider()); //$NON-NLS-1$
				}

				if ( !(this.getKeyStorePassword().isEmpty() )) {
					if ( lastPKI != null ) {
						if ( lastPKI.getKeyStorePassword().isEmpty() ) {
							System.clearProperty("javax.net.ssl.keyStorePassword"); //$NON-NLS-1$
						}
					} else {
						System.setProperty("javax.net.ssl.keyStorePassword", getKeyStorePassword()); //$NON-NLS-1$
					}
				}
			} else {
				clear();
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	public void load() {
		Optional<String> keyStoreType = null;
		Optional<String> keyStore = null;
		Optional<String> keyStorePassword = null;
		Optional<String> keyStoreProvider = null;
		keyStore = Optional.ofNullable(System.getProperty("javax.net.ssl.keyStore")); //$NON-NLS-1$
		if (keyStore.isEmpty()) {
			this.setKeyStore(""); //$NON-NLS-1$
		} else {
			this.setKeyStore(keyStore.get().toString());
		}

		keyStoreType = Optional.ofNullable(System.getProperty("javax.net.ssl.keyStoreType")); //$NON-NLS-1$
		if (keyStoreType.isEmpty()) {
			this.setKeyStoreType(""); //$NON-NLS-1$
		} else {
			this.setKeyStoreType(keyStoreType.get().toString());
		}
		keyStoreProvider = Optional.ofNullable(System.getProperty("javax.net.ssl.keyStoreProvider")); //$NON-NLS-1$
		if (keyStoreProvider.isEmpty()) {
			this.setKeyStoreProvider(""); //$NON-NLS-1$
		} else {
			this.setKeyStoreProvider(keyStoreType.get().toString());
			if (this.getKeyStoreType().equalsIgnoreCase("pkcs12")) {//$NON-NLS-1$
				System.clearProperty("javax.net.ssl.keyStoreProvider"); //$NON-NLS-1$
				this.setKeyStoreProvider(""); //$NON-NLS-1$
			}
		}


		keyStorePassword = Optional.ofNullable(System.getProperty("javax.net.ssl.keyStorePassword")); //$NON-NLS-1$
		if (keyStoreType.isEmpty()) {
			this.setKeyStorePassword(""); //$NON-NLS-1$
		} else {
			this.setKeyStorePassword(keyStorePassword.get().toString());
		}

		this.setUsername(System.getProperty("user.name")); //$NON-NLS-1$
	}
	public void setLastPkiValue( PKI pki ) {
		lastPKI = pki;
	}
	public void clear() {
		System.clearProperty("javax.net.ssl.keyStoreProvider"); //$NON-NLS-1$
		System.clearProperty("javax.net.ssl.keyStore"); //$NON-NLS-1$
		System.clearProperty("javax.net.ssl.keyStoreProvider"); //$NON-NLS-1$
		System.clearProperty("javax.net.ssl.keyStorePassword"); //$NON-NLS-1$
	}
	public void dump() {
		StringBuffer sb = new StringBuffer();
		sb.append("javax.net.ssl.keyStore="); //$NON-NLS-1$
		sb.append(this.getKeyStore());
		sb.append("\n"); //$NON-NLS-1$
		sb.append("javax.net.ssl.keyStoreType="); //$NON-NLS-1$
		sb.append(this.getKeyStoreType());
		sb.append("\n"); //$NON-NLS-1$
		sb.append("javax.net.ssl.keyStoreProvider="); //$NON-NLS-1$
		sb.append(this.getKeyStoreProvider());
		sb.append("\n"); //$NON-NLS-1$
	}
}
