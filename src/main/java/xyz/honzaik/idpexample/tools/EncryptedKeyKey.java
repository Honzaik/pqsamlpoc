package xyz.honzaik.idpexample.tools;

import java.security.Key;

public class EncryptedKeyKey implements Key
{

    private byte[] data;
    public EncryptedKeyKey(byte[] data) {
        this.data = data;
    }

    @Override
    public String getAlgorithm()
    {
        return "EncryptedKey";
    }

    @Override
    public String getFormat()
    {
        return null;
    }

    @Override
    public byte[] getEncoded()
    {
        return this.data.clone();
    }
}
