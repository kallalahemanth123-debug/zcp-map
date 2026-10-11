package com.google.android.gms.nearby.connection;
import com.google.android.gms.tasks.Task;
public interface ConnectionsClient {
  Task<Void> startAdvertising(String name, String serviceId, ConnectionLifecycleCallback cb, AdvertisingOptions o);
  Task<Void> startDiscovery(String serviceId, EndpointDiscoveryCallback cb, DiscoveryOptions o);
  Task<Void> requestConnection(String name, String endpointId, ConnectionLifecycleCallback cb);
  Task<Void> acceptConnection(String endpointId, PayloadCallback cb);
  Task<Void> rejectConnection(String endpointId);
  Task<Void> sendPayload(String endpointId, Payload p);
  Task<Void> cancelPayload(long payloadId);
  void disconnectFromEndpoint(String endpointId);
  void stopAdvertising(); void stopDiscovery(); void stopAllEndpoints();
}
