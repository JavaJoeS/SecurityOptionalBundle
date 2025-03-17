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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.core.security.ActivateSecurity;
import org.eclipse.core.security.state.X509SecurityStateIfc;

import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.Activate;

import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.ServiceScope;
import org.osgi.service.component.ComponentContext;
import org.osgi.framework.ServiceReference;

/*
 *  This Singleton is the Controller for the Client or Server Authentication process,
 *  exits when no configuration exists.
 */

@Component(scope=ServiceScope.SINGLETON)
public class InBoundController {
	private static AtomicInteger instanceCounter = new AtomicInteger();
	private static AtomicBoolean activated = new AtomicBoolean();
	private int instanceNo=0;
	protected final String pin = "#Gone2Boat@Bay"; //$NON-NLS-1$
	Optional<KeyStore>keystoreContainer = null;
	@Reference X509SecurityStateIfc x509SecurityStateIfc;
	@Reference IncomingSystemPropertyIfc incomingProperty;
	
	
	protected static KeyStore keyStore = null;//$NON-NLS-1$
	BundleContext bundleContext=null;
	
	public InBoundController() {
		ActivateSecurity.getInstance().log("InBoundController CONTRUCTOR:"); //$NON-NLS-1$
		instanceNo = instanceCounter.incrementAndGet();
	}
	
	@Activate
	void activate(ComponentContext ctx) {
		try {
			ActivateSecurity.getInstance().log("InBoundController Activate is:."+activated); //$NON-NLS-1$
			if ( activated.get() ) {
				return;
			} else {
				activated.set(true);
			}
			
			ActivateSecurity.getInstance().log("InBoundController Activate INSTANCE:."+instanceNo); //$NON-NLS-1$
			
			if ( x509SecurityStateIfc != null ) {
				x509SecurityStateIfc.setPKCS11on(false);
				x509SecurityStateIfc.setPKCS12on(false);
				x509SecurityStateIfc.setTrustOn(false);
				controller();
			}
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void controller() {
		Optional<String> keystoreTypeContainer = null;
		Optional<String> decryptedPw;
		
		//ActivateSecurity.getInstance().log("InBoundController controller."); //$NON-NLS-1$
		
		
		/*
		 * First see if parameters were passed into eclipse via the command line -D
		 */
		keystoreTypeContainer = Optional.ofNullable(System.getProperty("javax.net.ssl.keyStoreType")); //$NON-NLS-1$

		Optional<String> testKeyContainer = Optional.ofNullable(
				System.getProperty("core.key"));
		if (!(testKeyContainer.isEmpty() ))  {
			String testKey = testKeyContainer.get().toString().trim();
			if (testKey.equalsIgnoreCase("eclipse.core.pki.testing")) {
				return;
			}
		}
		if (keystoreTypeContainer.isEmpty()) {
			ActivateSecurity.getInstance().log("InBoundController controller NO KEYSTORE TYPE."); //$NON-NLS-1$
			//
			// Incoming parameter as -DkeystoreType was empty so CHECK in .pki file
			//
			//if (publicKeySecurity.getInstance().isTurnedOn()) {
			if (true) {
				//publicKeySecurity.getInstance().getPkiPropertyFile(pin);
			}
		}
	}
}
