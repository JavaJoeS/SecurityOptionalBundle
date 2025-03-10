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


import org.apache.felix.service.command.Descriptor;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.framework.ServiceReference;

@Component(immediate=true,
		  property= {
	    		 "osgi.command.scope=security",
	    	     "osgi.command.function=letsGo"
	      },
	      service=CommandSecurity.class)
public class CommandSecurity {
	
    private SecurityComponentIfc securityComponentIfc;
	private ComponentContext context;
	private ServiceReference<SecurityComponentIfc> sr;
	
	@Reference
	void setStartup(SecurityComponentIfc securityComponentIfc) {
		ActivateSecurity.getInstance().log("CommandSecurity startup."); //$NON-NLS-1$
	    this.securityComponentIfc = securityComponentIfc;
	}
	@Activate
	void activate(ComponentContext context) {
		ActivateSecurity.getInstance().log("CommandSecurity ACTIVATE."); //$NON-NLS-1$
		this.context=context;
		
	}
	@Reference(name="securityComponentIfc")
	void setReference(ServiceReference<SecurityComponentIfc> sr) {
		ActivateSecurity.getInstance().log("CommandSecurity ServiceReference."); //$NON-NLS-1$
	    this.sr = sr;
	}
	@Descriptor("startup instance")
	public void letsGo() {
		ActivateSecurity.getInstance().log("CommandSecurity letsGo."); //$NON-NLS-1$
		securityComponentIfc = (SecurityComponentIfc) this.context.locateService("securityComponentIfc", sr);
		if (securityComponentIfc != null ) {
			boolean result = securityComponentIfc.isRunning(); 
			ActivateSecurity.getInstance().log("CommandSecurity letsGo  RUNNING:"+result); //$NON-NLS-1$
			
		}
	}
	public void Run() {
		ActivateSecurity.getInstance().log("CommandSecurity Run."); //$NON-NLS-1$
		if (securityComponentIfc != null ) {
			securityComponentIfc.startup(); 
			ActivateSecurity.getInstance().log("CommandSecurity Run:"); //$NON-NLS-1$
			
		}
	}
	
}
