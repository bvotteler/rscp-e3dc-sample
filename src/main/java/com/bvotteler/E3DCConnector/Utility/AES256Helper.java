package com.bvotteler.E3DCConnector.Utility;

public interface AES256Helper {
    void init(byte[] key, byte[] ivEnc, byte[] ivDec);

    byte[] encrypt(byte[] message);

    byte[] decrypt(byte[] encryptedMessage);
}