package com.google.android.gms.nearby.connection;
public class Payload {
  public @interface Type { int BYTES = 1; int FILE = 2; int STREAM = 3; }
  public static Payload fromBytes(byte[] bytes) { return null; }
  public long getId() { return 0; }
  @Type public int getType() { return 0; }
  @androidx.annotation.Nullable public byte[] asBytes() { return null; }
}
