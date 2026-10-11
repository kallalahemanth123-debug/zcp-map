package com.google.android.gms.tasks;
public abstract class Task<TResult> { public abstract boolean isComplete(); public abstract TResult getResult(); }
