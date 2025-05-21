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
import org.eclipse.core.security.incoming.SecurityFileSnapshot;

import java.util.Optional;

import org.eclipse.core.runtime.ILog;


import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.util.tracker.ServiceTracker;

/*
 *  Activator for Security bundle to support optional PKI configuration
 */

public class ActivateSecurity implements BundleActivator {
	public static final String ID = "org.eclipse.core.security"; //$NON-NLS-1$
	private static ActivateSecurity instance;
	private BundleContext context;
	ServiceRegistration <SecurityComponentIfc>securityService;
	ServiceTracker tracker;
	public boolean isPkiUp=false;
	
	
	private static final ServiceCaller<ILog> logger = new ServiceCaller(ActivateSecurity.class, ILog.class);
	
	public ActivateSecurity() {
		super();
		setInstance(this);
	}
	
	@Override
	public void start(BundleContext context) throws Exception {
		this.context=context;
		Optional<String> stateOp = Optional.ofNullable(System.getProperty("core.state"));
		if (!(stateOp.isPresent())) {
			System.setProperty("core.state", "tracking");//$NON-NLS-1$ //$NON-NLS-2$
			securityService = context.registerService(SecurityComponentIfc.class, new SecurityFileSnapshot(), null );
			tracker = new ServiceTracker(context, SecurityComponentIfc.class.getName(), null);
			tracker.open();
			SecurityComponentIfc securityComponentIfc = (SecurityComponentIfc) tracker.getService();
			securityComponentIfc.startup();
		}
	}
	@Override
	public void stop(BundleContext context) throws Exception {
		context=null;
		if (tracker != null ) {
			tracker.close();
			tracker=null;
		}
	}

	public static ActivateSecurity getInstance() {
		return instance;
	}

	public static void setInstance(ActivateSecurity instance) {
		ActivateSecurity.instance = instance;
	}

	public void log(String message) {
		logger.call(logger -> logger.info(message));
	}

	public BundleContext getContext() {
		return context;
	}

	public boolean isPkiUp() {
		return isPkiUp;
	}

	public void setPkiUp(boolean isPkiUp) {
		this.isPkiUp = isPkiUp;
	}
	
}