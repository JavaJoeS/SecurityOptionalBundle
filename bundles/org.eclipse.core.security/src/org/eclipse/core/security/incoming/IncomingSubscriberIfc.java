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
package org.eclipse.core.security.incoming;


import java.util.concurrent.Flow.Subscriber;
import java.util.concurrent.Flow.Subscription;

/*
 *  interface to use for Publish paradigm in Pub/Sub 
 */

public interface IncomingSubscriberIfc extends Subscriber {
	
	public void onSubscribe(Subscription subscription);
	public void onNext(Object item);
	public void publishedIncoming();
	public void onError(Throwable throwable);
	public void onComplete();
}
