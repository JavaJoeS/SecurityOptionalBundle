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

import java.security.KeyStore;
import java.util.Optional;
import java.util.concurrent.Flow.Subscriber;
import java.util.concurrent.Flow.Subscription;

import org.eclipse.core.security.ActivateSecurity;
import org.eclipse.core.security.managers.AuthenticationBase;
import org.eclipse.core.security.managers.KeyStoreManager;
import org.eclipse.core.security.managers.KeystoreSetup;
import org.eclipse.core.security.state.X509SecurityState;
import org.eclipse.core.security.state.X509SecurityStateIfc;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.ServiceScope;


/*
 *  Class to use for Publish paradigm in Pub/Sub 
 */
@Component(scope=ServiceScope.SINGLETON)
public class IncomingSubscriber implements  IncomingSubscriberIfc {
	
	SecurityFileSnapshot securityFileSnapshot;
	@Reference AuthenticationBase authenticationBase;
	@Reference KeystoreSetup keystoreSetup;
	@Reference KeyStoreManager keyStoreManager;
	@Reference X509SecurityStateIfc x509SecurityStateIfc;
	@Reference IncomingSystemPropertyIfc incomingSystemPropertyIfc;
	IncomingSystemProperty incomingProperty;
	protected final String pin = "#Gone2Boat@Bay"; //$NON-NLS-1$
	Optional<KeyStore> keystoreContainer = null;//$NON-NLS-1$
	protected static KeyStore keyStore = null;//$NON-NLS-1$
	public IncomingSubscriber() {}
	
	@Override
	public void onSubscribe(Subscription subscription) {	
	}
	@Override
	public void onNext(Object item) {
		publishedIncoming();
	}
	public void publishedIncoming() {
		Optional<String> keystoreTypeContainer = null;
		Optional<String> decryptedPw;
		if ( incomingSystemPropertyIfc == null ) {
			incomingSystemPropertyIfc = new IncomingSystemProperty();
		}
		if (x509SecurityStateIfc == null ) {
			x509SecurityStateIfc = new X509SecurityState();
		}
		if (keystoreSetup == null ) {
			keystoreSetup= new KeystoreSetup();
		}	
		
		try {
			if (incomingSystemPropertyIfc.checkType()) {
				if (incomingSystemPropertyIfc.checkKeyStore(pin)) {
					
					if (x509SecurityStateIfc.isTrustOn()) {
						keystoreSetup.installKeystore();
						keystoreSetup.setPkiContext();
					} 
					if (x509SecurityStateIfc.isPKCS12on()) {
						keystoreSetup.installKeystore();
						keystoreSetup.setPkiContext();
					} 
					if (x509SecurityStateIfc.isPKCS11on()) {
						String pkcs11Pin = "";//$NON-NLS-1$
						
						decryptedPw = Optional.ofNullable(System.getProperty("javax.net.ssl.keyStorePassword"));
						if (!decryptedPw.isEmpty()) {
							pkcs11Pin = decryptedPw.get();
						}
						keystoreContainer = Optional
								.ofNullable(authenticationBase.initialize(pkcs11Pin.toCharArray()));// $NON-NLS-1$
						if (keystoreContainer.isEmpty()) {
							ActivateSecurity.getInstance().log("Failed to Load a Keystore."); //$NON-NLS-1$
							x509SecurityStateIfc.setPKCS11on(false);
							System.clearProperty("javax.net.ssl.keyStoreType"); //$NON-NLS-1$
							System.clearProperty("javax.net.ssl.keyStore"); //$NON-NLS-1$
							System.clearProperty("javax.net.ssl.keyStoreProvider"); //$NON-NLS-1$
							System.clearProperty("javax.net.ssl.keyStorePassword"); //$NON-NLS-1$
							securityFileSnapshot.restoreProperties();
						} else {
							ActivateSecurity.getInstance().log("A Keystore and Password are detected."); //$NON-NLS-1$
							keyStore = keystoreContainer.get();
							keyStoreManager.setKeyStore(keyStore);
							//ActivateSecurity.getInstance().setKeyStoreLoaded(true);
							keystoreSetup.setPkiContext();
						}
					}
				}
			}
		} catch (Exception e) {
			ActivateSecurity.getInstance().log("Invalid properties have been set:"+e.getMessage());
		}
	}
	@Override
	public void onError(Throwable throwable) {		
	}
	@Override
	public void onComplete() {	
	}
}
