package com.google.android.gms.nearby.connection;
public abstract class ConnectionLifecycleCallback {
  public abstract void onConnectionInitiated(String endpointId, ConnectionInfo info);
  public abstract void onConnectionResult(String endpointId, ConnectionResolution result);
  public abstract void onDisconnected(String endpointId);
}
