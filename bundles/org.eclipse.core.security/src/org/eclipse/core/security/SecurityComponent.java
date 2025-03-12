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


import java.util.Optional;

import org.eclipse.core.security.incoming.SecurityFileSnapshot;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ServiceScope;
/*
 *  This component controls life cycle of enablement of pki
 */

@Component(scope=ServiceScope.BUNDLE)
public class SecurityComponent {
	
    boolean isEnabled = false;
    boolean isRunning = false;
	private static SecurityComponentIfc securityComponentIfc;
	
	@Reference(cardinality = ReferenceCardinality.MANDATORY)
	public void bindSecurityService(SecurityComponentIfc securityComponentIfc) {
		
		ActivateSecurity.getInstance().log("SecurityComponent bindSecurityService.");
		securityComponentIfc=securityComponentIfc;
		Optional stateContainer = Optional.ofNullable(System.getProperty("core.state"));
		if ( stateContainer.isEmpty()) {
			System.setProperty("core.state", "running");
		} else {		
			ActivateSecurity.getInstance().log("SecurityComponent bindSecurityService. STATE:"+stateContainer.get());
		}
	}
	void unbindSecurityService(SecurityComponentIfc securityComponentIfc) {
		securityComponentIfc=null;
	}

	public static SecurityComponentIfc getSecurityComponentIfc() {
		return securityComponentIfc;
	}
	
	@Activate
	void checkstatusIsActive() {
		isEnabled=true;
	}
}
