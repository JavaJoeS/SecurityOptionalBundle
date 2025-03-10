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
package org.eclipse.core.security.state;

import org.osgi.service.component.annotations.Component;
import org.eclipse.core.security.ActivateSecurity;
import org.osgi.service.component.annotations.ServiceScope;

/*
 * This component keeps the state of PKCS
 */

@Component(scope=ServiceScope.SINGLETON, service=X509SecurityStateIfc.class)
public class X509SecurityState implements X509SecurityStateIfc {
	
	private static boolean isPKCS11on=false;
	private static boolean isPKCS12on=false;
	private static boolean isTrustOn=false;
	public X509SecurityState() {
		ActivateSecurity.getInstance().log("X509SecurityState CONSTRUCTOR"); //$NON-NLS-1$
	}
	
	public boolean isPKCS11on() {
		return isPKCS11on;
	}
	public void setPKCS11on(boolean state) {
		ActivateSecurity.getInstance().log("X509SecurityState setPKCS11on:"+state); //$NON-NLS-1$
		this.isPKCS11on = state;
	}
	public boolean isPKCS12on() {
		ActivateSecurity.getInstance().log("X509SecurityState isPKCS12on:"+isPKCS12on); //$NON-NLS-1$
		return isPKCS12on;
	}
	public void setPKCS12on(boolean state) {
		ActivateSecurity.getInstance().log("X509SecurityState setPKCS12on:"+state); //$NON-NLS-1$
		this.isPKCS12on = state;
	}
	public boolean isTrustOn() {
		return isTrustOn;
	}
	public void setTrustOn(boolean state) {
		this.isTrustOn = state;
	}
}
