package com.google.android.gms.nearby.connection;
public abstract class PayloadCallback { public abstract void onPayloadReceived(String endpointId, Payload p); public abstract void onPayloadTransferUpdate(String endpointId, PayloadTransferUpdate u); }
