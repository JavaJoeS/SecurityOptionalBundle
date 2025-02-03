/*******************************************************************************
 * Copyright (c) 2023 Eclipse Platform, Security Group and others.
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

import org.eclipse.core.security.ActivateSecurity;
import org.eclipse.core.security.managers.AuthenticationBase;
import org.eclipse.core.security.managers.KeyStoreManager;
import org.eclipse.core.security.managers.KeystoreSetup;
import org.eclipse.core.security.state.X509SecurityState;

public class InBoundController {
	private static InBoundController INSTANCE;
	protected final String pin = "#Gone2Boat@Bay"; //$NON-NLS-1$
	Optional<KeyStore> keystoreContainer = null;//$NON-NLS-1$
	protected static KeyStore keyStore = null;//$NON-NLS-1$
	private InBoundController() {
	}

	public static InBoundController getInstance() {
		if (INSTANCE == null) {
			INSTANCE = new InBoundController();
		}
		return INSTANCE;
	}

	public void controller() {
		Optional<String> keystoreTypeContainer = null;
		Optional<String> decryptedPw;
		/*
		 * First see if parameters were passed into eclipse via the command line -D
		 */
		keystoreTypeContainer = Optional.ofNullable(System.getProperty("javax.net.ssl.keyStoreType")); //$NON-NLS-1$

		if (keystoreTypeContainer.isEmpty()) {
			//
			// Incoming parameter as -DkeystoreType was empty so CHECK in .pki file
			//
			
			if (PublicKeySecurity.getInstance().isTurnedOn()) {
				PublicKeySecurity.getInstance().getPkiPropertyFile(pin);
			}
		}
		if (IncomingSystemProperty.getInstance().checkType()) {
			if (IncomingSystemProperty.getInstance().checkKeyStore(pin)) {
				KeystoreSetup setup = KeystoreSetup.getInstance();
				if (X509SecurityState.getInstance().isPKCS12on()) {

					setup.installKeystore();

				}
				if (X509SecurityState.getInstance().isPKCS11on()) {
					String pkcs11Pin = "";//$NON-NLS-1$
					ActivateSecurity.getInstance().log("Processing PKCS11 setup.");//$NON-NLS-1$
					
					decryptedPw = Optional.ofNullable(System.getProperty("javax.net.ssl.keyStorePassword"));
					if (!decryptedPw.isEmpty()) {
						pkcs11Pin = decryptedPw.get();
					}
					keystoreContainer = Optional
							.ofNullable(AuthenticationBase.getInstance().initialize(pkcs11Pin.toCharArray()));// $NON-NLS-1$
					if (keystoreContainer.isEmpty()) {
						ActivateSecurity.getInstance().log("Failed to Load a Keystore."); //$NON-NLS-1$
						X509SecurityState.getInstance().setPKCS11on(false);
						System.clearProperty("javax.net.ssl.keyStoreType"); //$NON-NLS-1$
						System.clearProperty("javax.net.ssl.keyStore"); //$NON-NLS-1$
						System.clearProperty("javax.net.ssl.keyStoreProvider"); //$NON-NLS-1$
						System.clearProperty("javax.net.ssl.keyStorePassword"); //$NON-NLS-1$
						SecurityFileSnapshot.getInstance().restoreProperties();
					} else {
						ActivateSecurity.getInstance().log("A Keystore and Password are detected."); //$NON-NLS-1$
						keyStore = keystoreContainer.get();
						KeyStoreManager.getInstance().setKeyStore(keyStore);
						ActivateSecurity.getInstance().setKeyStoreLoaded(true);
						setup.setPkiContext();
					}
				}
			}
		}
	}
}
