package org.eclipse.core.tests.security;


import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
/**
 * The activator class controls the plug-in life cycle
 */

public class Activator implements BundleActivator {

	// The plug-in ID
	public static final String PLUGIN_ID = "org.eclipse.core.tests.security";

	// The shared instance
	private static Activator plugin;

	private static BundleContext context;

	public static BundleContext getContext() {
		return context;
	}

	/**
	 * The constructor
	 */
	public Activator() {
	}

	@Override
	public void start(BundleContext context) throws Exception {
		Activator.context = context;
		System.setProperty("core.key", "eclipse.core.pki.testing");
	}

	@Override
	public void stop(BundleContext context) throws Exception {

	}
	public static Activator getDefault() {
		return plugin;
	}

}

