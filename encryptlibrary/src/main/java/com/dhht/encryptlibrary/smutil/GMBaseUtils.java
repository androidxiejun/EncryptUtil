package com.dhht.encryptlibrary.smutil;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class GMBaseUtils {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
}
