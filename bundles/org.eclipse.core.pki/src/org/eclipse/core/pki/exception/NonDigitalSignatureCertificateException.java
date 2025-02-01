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
package org.eclipse.core.pki.exception;

import java.security.cert.CertificateException;

public class NonDigitalSignatureCertificateException extends
        CertificateException {

    private static final long serialVersionUID = 8626994851137646007L;

    public NonDigitalSignatureCertificateException() {
    }

    public NonDigitalSignatureCertificateException( String arg0 ) {
        super( arg0 );
    }

    public NonDigitalSignatureCertificateException( Throwable arg0 ) {
        super( arg0 );
    }

    public NonDigitalSignatureCertificateException( String arg0, Throwable arg1 ) {
        super( arg0, arg1 );
    }

}
