package org.eclipse.core.security;

import java.util.Properties;

public interface SecurityComponentIfc {
	
	public void setValidConnection(boolean b);
	public boolean getValidConnection();
	public void startup();
	public boolean image();
	public boolean createPKI();
	public Properties load(String password, String salt);
}
