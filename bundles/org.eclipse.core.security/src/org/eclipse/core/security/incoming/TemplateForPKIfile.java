/*******************************************************************************
 * Copyright (c) 2025 IBM Corporation and others.
 *
 * This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 * IBM Corporation - initial API and implementation
 *******************************************************************************/
package org.eclipse.core.security.incoming;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

import org.osgi.service.component.annotations.ServiceScope;
import org.eclipse.core.security.ActivateSecurity;
import org.osgi.service.component.annotations.Component;

@Component(scope=ServiceScope.SINGLETON)
public class TemplateForPKIfile {
	
	public final String hashTag = "############################################################"; //$NON-NLS-1$
	public final String shortHashTag = "################"; //$NON-NLS-1$
	public static final String DotEclipse = ".eclipse";//$NON-NLS-1$
	public final String USER_HOME = System.getProperty("user.home"); //$NON-NLS-1$
	Path userM2Home = null;
	public TemplateForPKIfile() {}
	
	public void setup() {
		try {
			Path path = Paths.get(USER_HOME+
					FileSystems.getDefault().getSeparator()+DotEclipse+
					FileSystems.getDefault().getSeparator()+
					"pki.template");
			if (!(Files.exists(path))) {
				createTemplate(path);
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	public void createTemplate(Path path) {
		String editTag = "Edit this File, Save as .pki"; //$NON-NLS-1$
		try {
			Files.createFile(path);
			Files.write(path, (hashTag + System.lineSeparator()).getBytes(), StandardOpenOption.APPEND);
			Files.write(path, (hashTag + System.lineSeparator()).getBytes(), StandardOpenOption.APPEND);
			Files.write(path, shortHashTag.getBytes(), StandardOpenOption.APPEND);
			Files.write(path, editTag.getBytes(), StandardOpenOption.APPEND);
			Files.write(path, (shortHashTag + System.lineSeparator()).getBytes(), StandardOpenOption.APPEND);
			Files.write(path, (hashTag + System.lineSeparator()).getBytes(), StandardOpenOption.APPEND);
			Files.write(path, (hashTag + System.lineSeparator()).getBytes(), StandardOpenOption.APPEND);
			Files.write(path, ((buildBuffer()) + System.lineSeparator()).getBytes(), StandardOpenOption.APPEND);
			ActivateSecurity.getInstance().log("A pki.template file has been created in your home/.eclipse dir.");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public String buildBuffer() {
		StringBuilder b = new StringBuilder();
		b.append("javax.net.ssl.keyStore="); //$NON-NLS-1$
		b.append("[Fully quallified name of your Keystore File]"); //$NON-NLS-1$
		b.append(System.lineSeparator());
		b.append("javax.net.ssl.keyStorePassword="); //$NON-NLS-1$
		b.append("[Eclipse will encrypt this entry]"); //$NON-NLS-1$
		b.append(System.lineSeparator());
		b.append("javax.net.ssl.keyStoreType="); //$NON-NLS-1$
		b.append("[types allowed; PCKS11, PKCS12]"); //$NON-NLS-1$
		b.append(System.lineSeparator());
		b.append(System.lineSeparator());
		b.append("javax.net.ssl.trustStore="); //$NON-NLS-1$
		b.append("[Fully quallified name of your Truststore File]"); //$NON-NLS-1$
		b.append(System.lineSeparator());
		b.append("javax.net.ssl.trustStorePassword="); //$NON-NLS-1$
		b.append("[Your truststore passwd, usually changeit, unless customized]"); //$NON-NLS-1$
		b.append(System.lineSeparator());
		b.append("javax.net.ssl.trustStoreType="); //$NON-NLS-1$
		b.append("[types allowed; JKS]"); //$NON-NLS-1$
		b.append(System.lineSeparator());
		b.append(hashTag);
		b.append(System.lineSeparator());
		return b.toString();
	}

	public static void main(String[] args) {
		TemplateForPKIfile tmpl = new TemplateForPKIfile();
		tmpl.setup();
	}
}