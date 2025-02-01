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
package org.eclipse.core.pki;

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;



public enum SecurePKIVersionInfo {
	INSTANCE;

	public static String getVersion() {
		String version = null;
		Path path = null;

		try {

			/*
			 * See if this is a valid path check to see if its eclipse testing
			 */
			path = Paths.get("PKI.jar"); //$NON-NLS-1$

			if (path != null) {
				try {
					Manifest manifest = new JarFile(path.toAbsolutePath().toString()).getManifest();
					Attributes attributes = manifest.getMainAttributes();
					version = attributes.getValue("Build-Label"); //$NON-NLS-1$
				} catch (Exception e) {
					version = null;
				}
			}

			if (version == null) {
				version = "isEmbeded?"; //$NON-NLS-1$
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
		return version;
	}
}
