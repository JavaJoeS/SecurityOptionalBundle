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

/*
 * This interface keeps the state of PKCS
 */

public interface X509SecurityStateIfc {
		
	public boolean isPKCS11on();	
	public void setPKCS11on(boolean state);
	public boolean isPKCS12on();
	public void setPKCS12on(boolean state);
	public boolean isTrustOn();
	public void setTrustOn(boolean state);
}
