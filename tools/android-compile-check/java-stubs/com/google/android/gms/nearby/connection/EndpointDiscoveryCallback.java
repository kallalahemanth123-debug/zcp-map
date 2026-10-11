package com.google.android.gms.nearby.connection;
public abstract class EndpointDiscoveryCallback { public abstract void onEndpointFound(String endpointId, DiscoveredEndpointInfo info); public abstract void onEndpointLost(String endpointId); }
