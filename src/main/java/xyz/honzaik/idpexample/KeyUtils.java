package xyz.honzaik.idpexample;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.opensaml.xmlsec.signature.impl.X509CertificateBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HexFormat;

/**
 * A helper class for manipulating with keystore and certificates.
 */
public class KeyUtils
{

    private static final Logger LOG = LoggerFactory.getLogger(KeyUtils.class);
    private static final String KEYSTORE_TYPE = "pkcs12";
    private static final String KEYSTORE_PROVIDER = "BC"; //We want a BouncyCastle provider because it supports PQ algorithms.

    /**
     * Creates a keystore at the specified location protected with a password.
     *
     * @param filePath  Path to the keystore file.
     * @param password  Keystore password
     * @param overwrite Overwrite the file if it exists.
     */
    public static void createKeyStore(String filePath, String password, boolean overwrite)
    {
        File file = new File(filePath);
        if (file.exists() && !overwrite)
        {
            throw new RuntimeException("file already exists." + filePath);
        }
        try
        {
            file.getParentFile().mkdirs();
            file.createNewFile();
            LOG.info(file.getAbsolutePath());
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE, KEYSTORE_PROVIDER);
            keyStore.load(null, null);
            keyStore.store(new FileOutputStream(file), password.toCharArray());
        }
        catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException |
               NoSuchProviderException e)
        {
            throw new RuntimeException(e);
        }
    }

    /**
     * Loads a keystore from a file and returns the KeyStore object.
     *
     * @param filePath Keystore file path.
     * @param password Keystore password.
     * @return
     */
    public static KeyStore loadKeyStore(String filePath, String password)
    {
        File file = new File(filePath);
        KeyStore keyStore = null;
        try
        {
            keyStore = KeyStore.getInstance(KEYSTORE_TYPE, KEYSTORE_PROVIDER);
        }
        catch (KeyStoreException e)
        {
            throw new RuntimeException(e);
        }
        catch (NoSuchProviderException e)
        {
            throw new RuntimeException(e);
        }

        if (!file.exists())
        {
            throw new RuntimeException("file does not exist." + filePath);
        }
        try
        {
            keyStore.load(new FileInputStream(file), password.toCharArray());
        }
        catch (CertificateException e)
        {
            throw new RuntimeException(e);
        }
        catch (IOException e)
        {
            throw new RuntimeException(e);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new RuntimeException(e);
        }
        return keyStore;
    }

    /**
     * Save a KeyStore object to a file.
     *
     * @param keyStore
     * @param filePath
     * @param password
     */
    public static void saveKeyStore(KeyStore keyStore, String filePath, String password)
    {
        try
        {
            FileOutputStream fos = new FileOutputStream(filePath);
            keyStore.store(fos, password.toCharArray());
        }
        catch (FileNotFoundException e)
        {
            throw new RuntimeException(e);
        }
        catch (CertificateException e)
        {
            throw new RuntimeException(e);
        }
        catch (KeyStoreException e)
        {
            throw new RuntimeException(e);
        }
        catch (IOException e)
        {
            throw new RuntimeException(e);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new RuntimeException(e);
        }
    }

    /**
     * Calculates a SHA-256 digest of a X509 serialized certificate.
     *
     * @param cert
     * @return Hex encoded digest
     */
    public static String getCertificateFingerprintHexString(X509Certificate cert)
    {
        String result = null;
        try
        {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            HexFormat hf = HexFormat.of();
            result = hf.formatHex(digest.digest(cert.getEncoded()));
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new RuntimeException(e);
        }
        catch (CertificateEncodingException e)
        {
            throw new RuntimeException(e);
        }
        return result;
    }

    /**
     * Stores a private key and its corresponding certificate in a keystore.
     *
     * @param keyStore
     * @param alias    Alias used to save the certificate.
     * @param key
     * @param cert
     * @throws KeyStoreException
     */
    public static void storeKeyAndCert(KeyStore keyStore, String alias, PrivateKey key, Certificate cert)
            throws KeyStoreException
    {
        Certificate[] chain = {cert};
        String certFingerprint = KeyUtils.getCertificateFingerprintHexString((X509Certificate) chain[0]);
        LOG.info(chain[0].getPublicKey().getAlgorithm() + " " + certFingerprint);
        keyStore.setCertificateEntry(alias, cert);
        keyStore.setKeyEntry("key-" + certFingerprint, key, null, chain);
    }

    /**
     * Retrieves a private key from a keystore corresponding to the provided certificate.
     * Private keys are stored under the alias "key-<certFingerprint>" where <certFingerprint> is the output of
     * KeyUtils.getCertificateFingerprintHexString()
     *
     * @param keyStore
     * @param cert
     * @return
     * @throws UnrecoverableKeyException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     */
    public static PrivateKey getKeyCorrespondingToCertificate(KeyStore keyStore, X509Certificate cert)
            throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException
    {
        String certFingerprint = KeyUtils.getCertificateFingerprintHexString(cert);
        PrivateKey key = (PrivateKey) keyStore.getKey("key-" + certFingerprint, null);
        return key;
    }

}
