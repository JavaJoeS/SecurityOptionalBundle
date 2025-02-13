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
package org.eclipse.core.tests.security;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.mockito.Mock;
import org.mockito.Mockito;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;


import org.eclipse.core.security.ActivateSecurity;
import java.util.NoSuchElementException;

class ActivateSecurityTest {

	@Mock
	static ActivateSecurity activateSecurityMock = null;
	
	@BeforeAll
	static void setUpBeforeClass() throws Exception {
		activateSecurityMock = mock(ActivateSecurity.class);
		/*
		 * assertThrows(Exception.class, ()->{
		 * System.out.println("HERE IS WHERE IT IS"); //activateSecurityMock =
		 * ActivateSecurity.getInstance(); });
		 */
	}

	@AfterAll
	static void tearDownAfterClass() throws Exception {
	}

	@BeforeEach
	void setUp() throws Exception {
	}

	@AfterEach
	void tearDown() throws Exception {
	}

	@Test
	void testGetInstance() {
		activateSecurityMock.getInstance();
	}
	@Test
	void testLog() {
		activateSecurityMock.getInstance().log("In Test Mode.");
	}
	@Test
	void testActivateSubscriber() {
		activateSecurityMock.getInstance().activateSubscriber();
	}

}
