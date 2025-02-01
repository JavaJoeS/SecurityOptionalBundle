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

package org.eclipse.core.pki.auth;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Serializable;

public enum PokeInConsole implements Serializable {
	PASSWD;
	protected static final String ENTER="Enter password:";//$NON-NLS-1$
	public void get() {
		try {
			Console console = System.console();
			if (console == null) {
				
	    
	            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
	            System.out.print(ENTER);
	            String name=new String();
				try {
					//System.out.println((char)27 + "[37mWHITE");
					//System.out.println((char)27 + "[37m");
					System.out.println((char)27 + "[8m");//$NON-NLS-1$
					name = reader.readLine();
					System.out.flush();
					//System.out.println((char)27 + "[30mBLACK");
					System.out.println((char)27 + "[0m");//$NON-NLS-1$
					System.out.println((char)27 + "[30m");//$NON-NLS-1$
				} catch (IOException e) {
					e.printStackTrace();
				}
	            
	            System.setProperty("javax.net.ssl.keyStorePassword", name);//$NON-NLS-1$
	        } else {
	        	char[] ch = console.readPassword( ENTER );
	        	String pw = new String(ch);
	        	System.setProperty("javax.net.ssl.keyStorePassword", pw);//$NON-NLS-1$
	        }
		    
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
	}
}
