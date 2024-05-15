package xyz.honzaik.idpexample;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import net.shibboleth.utilities.java.support.xml.XMLParserException;

import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.saml.security.impl.SAMLExtraSignatureProfileValidator;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.encryption.EncryptedKey;
import org.opensaml.xmlsec.encryption.support.*;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import xyz.honzaik.idpexample.tools.EncryptedKeyKey;

import javax.xml.namespace.QName;
import java.io.ByteArrayInputStream;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * A helper class containing various static functions used for manipulating and processing SAML objects
 */
public class SAMLUtil
{

    private static final Logger LOG = LoggerFactory.getLogger(SAMLUtil.class);

    /**
     * Builds an instance of a SAML object from a class.
     *
     * @param clazz Template class
     * @param <T>
     * @return
     */
    public static <T> T buildSAMLObject(final Class<T> clazz)
    {
        T obj = null;
        QName name = null;
        try
        {
            name = (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
        }
        catch (IllegalAccessException e)
        {
            throw new RuntimeException(e);
        }
        catch (NoSuchFieldException e)
        {
            throw new RuntimeException(e);
        }

        System.out.println(XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilders().size());

        obj = (T) XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(name).buildObject(name);

        return obj;
    }

    public static String getSAMLObjectString(final XMLObject obj)
    {
        Element el = obj.getDOM();
        //if (obj instanceof SignableSAMLObject && ((SignableSAMLObject) obj).isSigned() && obj.getDOM() != null) {
        if (obj.getDOM() != null)
        {
            el = obj.getDOM();
        }
        else
        {
            try
            {
                Marshaller out = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(obj);
                out.marshall(obj);
                el = obj.getDOM();

            }
            catch (MarshallingException e)
            {
                LOG.error(e.getMessage(), e);
            }
        }
        return SerializeSupport.prettyPrintXML(el);
    }

    /**
     * Pretty-prints a SAML object into the console. Beware this might cause issues because it marshals the object.
     *
     * @param obj
     */
    public static void logSAMLObject(final XMLObject obj)
    {
        LOG.info(getSAMLObjectString(obj));
    }

    /**
     * This function initializes the OpenSAML library.
     */
    public static void initOpenSAML()
    {
        XMLObjectProviderRegistry registry = new XMLObjectProviderRegistry();
        ConfigurationService.register(XMLObjectProviderRegistry.class, registry);
        registry.setParserPool(SAMLUtil.getParserPool());
        LOG.info("init saml");
        try
        {
            InitializationService.initialize();
            LOG.info("initialized opensaml");
        }
        catch (InitializationException e)
        {
            LOG.info("failed to init opensaml");
            throw new RuntimeException(e);
        }
    }

    /**
     * Another OpenSAML initialization function.
     *
     * @return
     */
    private static ParserPool getParserPool()
    {
        BasicParserPool parserPool = new BasicParserPool();
        parserPool.setMaxPoolSize(100);
        parserPool.setCoalescing(true);
        parserPool.setIgnoreComments(true);
        parserPool.setIgnoreElementContentWhitespace(true);
        parserPool.setNamespaceAware(true);
        parserPool.setExpandEntityReferences(false);
        parserPool.setXincludeAware(false);

        final Map<String, Boolean> features = new HashMap<String, Boolean>();
        features.put("http://xml.org/sax/features/external-general-entities", Boolean.FALSE);
        features.put("http://xml.org/sax/features/external-parameter-entities", Boolean.FALSE);
        features.put("http://apache.org/xml/features/disallow-doctype-decl", Boolean.TRUE);
        features.put("http://apache.org/xml/features/validation/schema/normalized-value", Boolean.FALSE);
        features.put("http://javax.xml.XMLConstants/feature/secure-processing", Boolean.TRUE);

        parserPool.setBuilderFeatures(features);
        parserPool.setBuilderAttributes(new HashMap<String, Object>());

        try
        {
            parserPool.initialize();
        }
        catch (ComponentInitializationException e)
        {
            LOG.error(e.getMessage(), e);
        }
        return parserPool;
    }

    /**
     * Verifies the standard signature of a SAML object. The method assumes the public key used for signature verification is
     * in a X509 certificate inside <KeyInfo>.
     *
     * @param object SAML object that is going to be verified
     * @throws SignatureException in case anything is wrong with the signature
     */
    public static void verifySAMLSignature(SignableSAMLObject object) throws SignatureException
    {
        Signature signature = object.getSignature();

        if (signature == null)
        {
            throw new SignatureException("Signature element is null.");
        }

        //Verifies if the signature satisfies the SAML standard. E.g. is enveloped and no other transforms are used.
        SAMLSignatureProfileValidator validator = new SAMLSignatureProfileValidator();
        validator.validate(signature);

        //Retrieves the public key from the KeyInfo and verifies the actual XML signature.
        Credential credential = new BasicX509Credential(SAMLUtil.extractCertificateFromSignature(signature));
        SignatureValidator.validate(signature, credential);
    }

    /**
     * Verifies the extra signature of a SAML object. The method assumes the public key used for signature verification is
     * in a X509 certificate inside <KeyInfo>.
     * The extra signature is an immediate child of <Extensions> and contains an extra XPath transformation to remove
     * the classical signature before hashing.
     * This function also needs to use a modified SAML verifier to allow the transformation to be present.
     *
     * @param object SAML object that is going to be verified. The function is only implemented for SAML objects which
     *               implement the StatusResponseType or RequestAbstractType interfaces. This is because we need a SAML
     *               object which contains <Extensions>.
     * @throws SignatureException in case anything is wrong with the signature
     */
    public static void verifyExtraSAMLSignature(SignableSAMLObject object) throws SignatureException
    {
        Extensions extensions = null;

        //Check if the object has Extensions
        if (object instanceof StatusResponseType)
        {
            extensions = ((StatusResponseType) object).getExtensions();
        }
        else if (object instanceof RequestAbstractType)
        {
            extensions = ((RequestAbstractType) object).getExtensions();
        }
        else
        {
            throw new SignatureException("Object is not an instance of StatusResponseType or RequestAbstractType.");
        }

        //SAML object supports extensions but the Extensions element is empty. Nothing to verify.
        if (extensions == null)
        {
            throw new SignatureException("Extensions is null. No signature found.");
        }

        //Select the first (and should be the only) <Signature> inside <Extensions>
        List<XMLObject> signaturesInExtensions = extensions.getUnknownXMLObjects(Signature.DEFAULT_ELEMENT_NAME);
        if (signaturesInExtensions.isEmpty())
        {
            throw new SignatureException("No signature inside Extensions.");
        }
        if (signaturesInExtensions.size() > 1)
        {
            throw new SignatureException("More than 1 signature inside Extensions.");
        }

        Signature extraSignature = (Signature) signaturesInExtensions.get(0);

        if (extraSignature == null)
        {
            throw new SignatureException("Signature element is null.");
        }

        /* Verifies if the Signature element is conformant with SAML standards with exception that it is not a direct
         child of the root but it is a child of Extensions. Also, it allows the additional XPath transform.
         */

        SAMLExtraSignatureProfileValidator validator = new SAMLExtraSignatureProfileValidator();
        validator.validate(extraSignature);

        //Retrieves the public key from the KeyInfo and verifies the actual XML signature.
        Credential credential = new BasicX509Credential(SAMLUtil.extractCertificateFromSignature(extraSignature));
        SignatureValidator.validate(extraSignature, credential);
    }

    /**
     * Creates a X509Certificate object from a base64 encoded string.
     *
     * @param certString String of a base64 encoded X509 certificate.
     * @return
     * @throws RuntimeException
     */
    private static X509Certificate createCertificateFromString(String certString) throws RuntimeException
    {
        X509Certificate cert = null;
        CertificateFactory factory = null;
        try
        {
            factory = CertificateFactory.getInstance("X.509", "BC");
            cert = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(Base64.getMimeDecoder().decode(certString)));
        }
        catch (CertificateException e)
        {
            throw new RuntimeException(e);
        }
        catch (NoSuchProviderException e)
        {
            throw new RuntimeException(e);
        }

        return cert;
    }

    /**
     * Retrieves a X509 certificate from a <KeyInfo> element.
     *
     * @param keyInfo
     * @return
     */
    private static X509Certificate getCertificateFromKeyInfo(KeyInfo keyInfo)
    {
        String certString = null;
        try
        {
            if (keyInfo == null)
            {
                throw new NullPointerException();
            }
            certString = keyInfo.getX509Datas().get(0).getX509Certificates().get(0).getValue();
            if (certString == null)
            {
                throw new NullPointerException();
            }
        }
        catch (NullPointerException e)
        {
            throw new RuntimeException("Certificate not found in the KeyInfo.");
        }

        return SAMLUtil.createCertificateFromString(certString);
    }

    /**
     * Retrieves a X509 certificate from a <Signature> element which has a <KeyInfo> child
     *
     * @param signature
     * @return
     * @throws RuntimeException
     */
    public static X509Certificate extractCertificateFromSignature(Signature signature) throws RuntimeException
    {
        return SAMLUtil.getCertificateFromKeyInfo(signature.getKeyInfo());
    }

    /**
     * Retrieves a X509 certificate from a <EncryptedAssertion> element which has a <KeyInfo> child
     *
     * @param assertion
     * @return
     * @throws RuntimeException
     */
    public static X509Certificate extractCertificateFromEncryptedAssertion(EncryptedAssertion assertion)
            throws RuntimeException
    {
        KeyInfo keyInfo = null;
        try
        {
            EncryptedKey encryptedKey = assertion.getEncryptedData().getKeyInfo().getEncryptedKeys().get(0);
            if (encryptedKey == null)
            {
                throw new NullPointerException();
            }
            keyInfo = encryptedKey.getKeyInfo();
        }
        catch (NullPointerException e)
        {
            throw new RuntimeException("KeyInfo not found in the encrypted assertion.");
        }

        return SAMLUtil.getCertificateFromKeyInfo(keyInfo);
    }

    /**
     * Retrieves a X509 certificate from a SAML message which has <Extensions> element which has a <KeyInfo> child.
     * Only accepts AuthnRequest SAML message.
     *
     * @param request
     * @return
     * @throws RuntimeException
     */
    public static ArrayList<X509Certificate> extractCertificatesFromExtensions(AuthnRequest request)
            throws RuntimeException
    {
        ArrayList<X509Certificate> certs = new ArrayList<>();

        if (request.getExtensions() == null)
        {
            return null;
        }


        List<XMLObject> certsInExtensions = request.getExtensions().getUnknownXMLObjects(KeyInfo.DEFAULT_ELEMENT_NAME);
        if (certsInExtensions.isEmpty())
        { //no certs in Extensions
            return null;
        }

        for (XMLObject object : certsInExtensions) {
            KeyInfo keyInfo = (KeyInfo) object;
            certs.add(SAMLUtil.getCertificateFromKeyInfo(keyInfo));
        }


        return certs;
    }


    /**
     * A method for encrypting Assertion in a normal or hybrid mode.
     * Parameters have the same
     * @param isHybrid Are we encrypting in a hybrid mode (double encryption)?
     * @param assertion Assertion to encrypt
     * @param encCerts List of certificates which contain the public keys which are used to encrypt the Assertion (2 of them are needed for hybrid)
     * @param encAlgIds List of public key encryption algorithm names used during the encryption. The names are in the "BouncyCastle" format (not XML IDs).
     * @return
     */
    public static EncryptedAssertion encryptAssertion(boolean isHybrid, Assertion assertion, ArrayList<X509Certificate> encCerts, ArrayList<String> encAlgIds)
    {
        DataEncryptionParameters encryptionParameters = new DataEncryptionParameters();
        encryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM);

        X509KeyInfoGeneratorFactory factory = new X509KeyInfoGeneratorFactory();
        factory.setEmitEntityCertificate(true);

        KeyEncryptionParameters primaryKeyEncryptionParameters = new KeyEncryptionParameters();
        primaryKeyEncryptionParameters.setEncryptionCredential(new BasicX509Credential(encCerts.get(0)));
        primaryKeyEncryptionParameters.setAlgorithm(encAlgIds.get(0));
        primaryKeyEncryptionParameters.setKeyInfoGenerator(factory.newInstance());

        Encrypter primaryEncrypter = new Encrypter(encryptionParameters, primaryKeyEncryptionParameters);
        primaryEncrypter.setKeyPlacement(Encrypter.KeyPlacement.INLINE);

        EncryptedAssertion encryptedAssertion = null;
        try
        {
            encryptedAssertion = primaryEncrypter.encrypt(assertion);
        }
        catch (EncryptionException e)
        {
            throw new RuntimeException(e);
        }

        //hybrid encryption. Re-encrypt the result once more.
        if (isHybrid) {
            if (encCerts.get(1).getPublicKey().getAlgorithm().equals("RSA")) {
                throw new RuntimeException("RSA cannot be used on the outer layer due to the plaintext size.");
            }

            KeyEncryptionParameters secondaryKeyEncryptionParameters = new KeyEncryptionParameters();
            secondaryKeyEncryptionParameters.setEncryptionCredential(new BasicX509Credential(encCerts.get(1)));
            secondaryKeyEncryptionParameters.setAlgorithm(encAlgIds.get(1));
            secondaryKeyEncryptionParameters.setKeyInfoGenerator(factory.newInstance());

            Encrypter secondaryEncrypter = new Encrypter(encryptionParameters, secondaryKeyEncryptionParameters);
            secondaryEncrypter.setKeyPlacement(Encrypter.KeyPlacement.INLINE);

            EncryptedAssertion doubleEncryptedAssertion = null;
            try
            {
                doubleEncryptedAssertion = secondaryEncrypter.encrypt(encryptedAssertion);
            }
            catch (EncryptionException e)
            {
                throw new RuntimeException(e);
            }
            //set a MIME type so that the decryption method knows to decrypt twice.
            doubleEncryptedAssertion.getEncryptedData().setMimeType(EncryptionConstants.MIME_TYPE_LAYERED_ENCRYPTED_ASSERTION);
            return doubleEncryptedAssertion;

        }
        return encryptedAssertion;
    }

    /**
     * Completely decrypts and returns Assertion with support for layered encryption (2 layers).
     * EncryptedAssertion which is layered encryption has MimeType attribute equal to EncryptionConstants.MIME_TYPE_LAYERED_ENCRYPTED_ASSERTION.
     *
     * @param encryptedAssertion EncryptedAssertion to decrypt completely.
     * @param keyStore           KeyStore used to retrieve corresponding private keys used for decryption.
     * @return
     */
    public static Assertion decryptAssertion(EncryptedAssertion encryptedAssertion, KeyStore keyStore)
    {
        X509Certificate cert = null;
        Credential cred = null;
        StaticKeyInfoCredentialResolver keyInfoCredentialResolver = null;
        Decrypter decrypter = null;

        String mimeType = encryptedAssertion.getEncryptedData().getMimeType();
        try
        {
            //check if the MIME type is present and corresponds to EncryptedData that were encrypted twice.
            if (mimeType != null && mimeType.equals(EncryptionConstants.MIME_TYPE_LAYERED_ENCRYPTED_ASSERTION))
            {
                cert = SAMLUtil.extractCertificateFromEncryptedAssertion(encryptedAssertion);
                cred = new BasicCredential(cert.getPublicKey(), KeyUtils.getKeyCorrespondingToCertificate(keyStore, cert));
                keyInfoCredentialResolver = new StaticKeyInfoCredentialResolver(cred);
                decrypter = new Decrypter(null, keyInfoCredentialResolver, new InlineEncryptedKeyResolver());

                //we need to use decryptLayer instead of decrypt because the return type is EncryptedAssertion
                EncryptedAssertion decryptedEncryptedAssertion = decrypter.decryptLayer(encryptedAssertion);
                //first layer was decrypted, treat now as a regular EncryptedAssertion
                return SAMLUtil.decryptAssertion(decryptedEncryptedAssertion, keyStore);
            }

            //get new decryption credential
            cert = SAMLUtil.extractCertificateFromEncryptedAssertion(encryptedAssertion);
            cred = new BasicCredential(cert.getPublicKey(), KeyUtils.getKeyCorrespondingToCertificate(keyStore, cert));
            keyInfoCredentialResolver = new StaticKeyInfoCredentialResolver(cred);
            decrypter = new Decrypter(null, keyInfoCredentialResolver, new InlineEncryptedKeyResolver());

            //use traditional decryption method from Decrypted
            return decrypter.decrypt(encryptedAssertion);
        }
        catch (KeyStoreException | NoSuchAlgorithmException | DecryptionException | UnrecoverableKeyException e)
        {
            throw new RuntimeException(e);
        }
    }


    /**
     * Alternative experimental encryptAssertion which only encrypts the EncryptedKey element twice during hybrid encryption.
     * Apache Santuario API does not allow to use "encryptKey" on something that is not a Key so EncryptedKeyKey is the helper structure to "hack" this restriction.
     * Parameters have the same
     * @param isHybrid Are we encrypting in a hybrid mode (double encryption)?
     * @param assertion Assertion to encrypt
     * @param encCerts List of certificates which contain the public keys which are used to encrypt the Assertion (2 of them are needed for hybrid)
     * @param encAlgIds List of public key encryption algorithm names used during the encryption. The names of the algorithms are the XML identifiers.
     * @return
     */
    public static EncryptedAssertion ALT_encryptAssertion(boolean isHybrid, Assertion assertion, ArrayList<X509Certificate> encCerts, ArrayList<String> encAlgIds)
    {
        DataEncryptionParameters encryptionParameters = new DataEncryptionParameters();
        encryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM);

        X509KeyInfoGeneratorFactory factory = new X509KeyInfoGeneratorFactory();
        factory.setEmitEntityCertificate(true);

        KeyEncryptionParameters primaryKeyEncryptionParameters = new KeyEncryptionParameters();
        primaryKeyEncryptionParameters.setEncryptionCredential(new BasicX509Credential(encCerts.get(0)));
        primaryKeyEncryptionParameters.setAlgorithm(encAlgIds.get(0));
        primaryKeyEncryptionParameters.setKeyInfoGenerator(factory.newInstance());

        Encrypter primaryEncrypter = new Encrypter(encryptionParameters, primaryKeyEncryptionParameters);
        primaryEncrypter.setKeyPlacement(Encrypter.KeyPlacement.INLINE);

        EncryptedAssertion encryptedAssertion = null;
        try
        {
            encryptedAssertion = primaryEncrypter.encrypt(assertion);
        }
        catch (EncryptionException e)
        {
            throw new RuntimeException(e);
        }

        //hybrid encryption. Encrypt the EncryptedKey with the PQ PKE.
        if (isHybrid) {
            if (encCerts.get(1).getPublicKey().getAlgorithm().equals("RSA")) {
                throw new RuntimeException("RSA cannot be used on the outer layer due to the plaintext size.");
            }

            KeyEncryptionParameters secondaryKeyEncryptionParameters = new KeyEncryptionParameters();
            secondaryKeyEncryptionParameters.setEncryptionCredential(new BasicX509Credential(encCerts.get(1)));
            secondaryKeyEncryptionParameters.setAlgorithm(encAlgIds.get(1));
            secondaryKeyEncryptionParameters.setKeyInfoGenerator(factory.newInstance());

            Encrypter secondaryEncrypter = new Encrypter(encryptionParameters, secondaryKeyEncryptionParameters);
            secondaryEncrypter.setKeyPlacement(Encrypter.KeyPlacement.INLINE);

            //encode EncryptedKey to bytes and make it a "Key" object so it can be encrypted.
            EncryptedKeyKey encryptedKeyKeyRepresentation = new EncryptedKeyKey(SAMLUtil.getSAMLObjectString(encryptedAssertion.getEncryptedData().getKeyInfo().getEncryptedKeys().get(0)).getBytes(StandardCharsets.UTF_8));
            //remove the EncryptedKey from the EncryptedAssertion (will be replaced with its encrypted variant)
            encryptedAssertion.getEncryptedData().getKeyInfo().getEncryptedKeys().clear();
            EncryptedKey reEncryptedKey = null;
            try
            {
                //marshall so we can reference the owner document on the next line
                XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(encryptedAssertion.getEncryptedData().getKeyInfo()).marshall(encryptedAssertion.getEncryptedData().getKeyInfo());
                reEncryptedKey = secondaryEncrypter.encryptKey(encryptedKeyKeyRepresentation, secondaryKeyEncryptionParameters, encryptedAssertion.getEncryptedData().getKeyInfo().getDOM().getOwnerDocument());
            }
            catch (EncryptionException | MarshallingException e)
            {
                throw new RuntimeException(e);
            }

            reEncryptedKey.setMimeType(EncryptionConstants.MIME_TYPE_LAYERED_ENCRYPTED_ASSERTION);
            //add EncryptedKey to the Assertion
            encryptedAssertion.getEncryptedData().getKeyInfo().getEncryptedKeys().add(reEncryptedKey);
        }

        return encryptedAssertion;

    }

    /**
     * Corresponding alternative decryption method for decrypting assertions that were encrypted in hybrid mode where only the EncryptedKey got encrypted twice.
     *
     * @param encryptedAssertion EncryptedAssertion to decrypt completely.
     * @param keyStore           KeyStore used to retrieve corresponding private keys used for decryption.
     * @return
     */
    public static Assertion ALT_decryptAssertion(EncryptedAssertion encryptedAssertion, KeyStore keyStore)
    {
        X509Certificate cert = null;
        Credential cred = null;
        StaticKeyInfoCredentialResolver keyInfoCredentialResolver = null;
        Decrypter decrypter = null;

        String mimeType = encryptedAssertion.getEncryptedData().getKeyInfo().getEncryptedKeys().get(0).getMimeType();
        try
        {
            if (mimeType != null && mimeType.equals(EncryptionConstants.MIME_TYPE_LAYERED_ENCRYPTED_ASSERTION))
            {
                cert = SAMLUtil.extractCertificateFromEncryptedAssertion(encryptedAssertion);
                cred = new BasicCredential(cert.getPublicKey(), KeyUtils.getKeyCorrespondingToCertificate(keyStore, cert));
                keyInfoCredentialResolver = new StaticKeyInfoCredentialResolver(cred);
                decrypter = new Decrypter(null, keyInfoCredentialResolver, new InlineEncryptedKeyResolver());

                EncryptedKey toBeDecrypted = encryptedAssertion.getEncryptedData().getKeyInfo().getEncryptedKeys().get(0);
                EncryptedKeyKey decryptedLayerKey = new EncryptedKeyKey(decrypter.decryptKey(toBeDecrypted, toBeDecrypted.getEncryptionMethod().getAlgorithm()).getEncoded());
                EncryptedKey decryptedEncryptedKey = (EncryptedKey) XMLObjectSupport.unmarshallFromInputStream(getParserPool(), new ByteArrayInputStream(decryptedLayerKey.getEncoded()));
                encryptedAssertion.getEncryptedData().getKeyInfo().getEncryptedKeys().clear();
                encryptedAssertion.getEncryptedData().getKeyInfo().getEncryptedKeys().add(decryptedEncryptedKey);
                //EncryptedKey was decrypted, treat now as a regular EncryptedAssertion
            }

            //get new decryption credential
            cert = SAMLUtil.extractCertificateFromEncryptedAssertion(encryptedAssertion);
            cred = new BasicCredential(cert.getPublicKey(), KeyUtils.getKeyCorrespondingToCertificate(keyStore, cert));
            keyInfoCredentialResolver = new StaticKeyInfoCredentialResolver(cred);
            decrypter = new Decrypter(null, keyInfoCredentialResolver, new InlineEncryptedKeyResolver());

            //use traditional decryption method from Decrypted
            return decrypter.decrypt(encryptedAssertion);
        }
        catch (KeyStoreException | NoSuchAlgorithmException | DecryptionException | UnrecoverableKeyException |
               XMLParserException | UnmarshallingException e)
        {
            throw new RuntimeException(e);
        }
    }

    /**
     * Method to sign SAML messages in normal or hybrid mode.
     * @param message SAML message to be signed.
     * @param isHybrid Are we using hybrid mode (backward-compatible one).
     * @param keyStore KeyStore containing the signing keys.
     * @param sigAlgIds A list of names of signature algorithms used (2 for hybrid). The names of the algorithms are the XML identifiers.
     * @param digestAlgId Hash function used to hash the signed message.
     */
    public static void signSAMLMessage(SignableSAMLObject message, boolean isHybrid, KeyStore keyStore, ArrayList<String> sigAlgIds, String digestAlgId)
    {
        X509Certificate primaryCert = null;
        Credential primaryCredential = null;
        //get signing credentials. In hybrid mode, these would be the classical keys.
        try
        {
            primaryCert = (X509Certificate) keyStore.getCertificate(GlobalConstants.SIG_PRIV_KEY_KEYSTORE_NAME);
            primaryCredential = new BasicCredential(primaryCert.getPublicKey(), KeyUtils.getKeyCorrespondingToCertificate(keyStore, primaryCert));
        }
        catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e)
        {
            throw new RuntimeException(e);
        }

        //prepare signature metadata
        Signature signature = SAMLUtil.buildSAMLObject(Signature.class);
        signature.setSigningCredential(primaryCredential);
        signature.setSignatureAlgorithm(sigAlgIds.get(0));
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        //Generate KeyInfo
        X509KeyInfoGeneratorFactory factory = new X509KeyInfoGeneratorFactory();
        factory.setEmitEntityCertificate(true);
        KeyInfo keyInfo = null;
        X509Credential x509cred = new BasicX509Credential(primaryCert);
        try
        {
            keyInfo = factory.newInstance().generate(x509cred);
        }
        catch (SecurityException e)
        {
            throw new RuntimeException(e);
        }

        signature.setKeyInfo(keyInfo);

        //In hybrid mode, we first need to sign with the secondary/extra (post-quantum) signature. The signature is inserted into the SAML message which is then signed again using the classical signature (after the if ends).
        //Create an extra signature over the document that is inserted into the Extensions.
        if (isHybrid)
        {
            X509Certificate secondaryCert = null;
            Credential secondaryCredential = null;
            //get signing credentials. These would be post-quantum
            try
            {
                secondaryCert = (X509Certificate) keyStore.getCertificate(GlobalConstants.SIG_EXTRA_PRIV_KEY_KEYSTORE_NAME);
                secondaryCredential = new BasicCredential(secondaryCert.getPublicKey(), KeyUtils.getKeyCorrespondingToCertificate(keyStore, secondaryCert));
            }
            catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e)
            {
                throw new RuntimeException(e);
            }

            //This Signature element is to be inserted into Extensions element of the SAML message. Handle possible cases where the Extensions element already exists of needs to be created.
            Extensions extensions = null;
            boolean hasExistingExtensions = false;
            if (message instanceof AuthnRequest)
            {
                extensions = ((AuthnRequest) message).getExtensions();
            }
            else if (message instanceof Response)
            {
                extensions = ((Response) message).getExtensions();
            } else {
                throw new RuntimeException("Unsupported message for signing.");
            }

            if (extensions == null) {
                extensions = SAMLUtil.buildSAMLObject(Extensions.class);
            } else {
                hasExistingExtensions = true;
            }

            //prepare signature metadata
            Signature extraSignature = SAMLUtil.buildSAMLObject(Signature.class);
            extraSignature.setSignatureAlgorithm(sigAlgIds.get(1));
            extraSignature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
            extraSignature.setSigningCredential(secondaryCredential);

            //Specifically reference the whole Response. For the primary (classical) signature this is done automatically by calling response.setSignature() but we do not that here.
            SAMLObjectContentReference reference = new SAMLObjectContentReference(message, true);
            reference.setDigestAlgorithm(digestAlgId);
            extraSignature.getContentReferences().add(reference);

            //create KeyInfo
            KeyInfo extraKeyInfo = null;
            X509Credential extraX509cred = new BasicX509Credential(secondaryCert);
            try
            {
                extraKeyInfo = factory.newInstance().generate(extraX509cred);
            }
            catch (SecurityException e)
            {
                throw new RuntimeException(e);
            }

            extraSignature.setKeyInfo(extraKeyInfo);

            extensions.getUnknownXMLObjects().add(extraSignature); //add signature element into extensions

            if (!hasExistingExtensions)
            {
                ((Response) message).setExtensions(extensions);
            }

            try
            {
                //Marshalling is needed to calculate the references etc.
                XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(message).marshall(message);
                Signer.signObject(extraSignature); //create the extra signature
            }
            catch (SignatureException | MarshallingException e)
            {
                throw new RuntimeException(e);
            }
        }

        //add the classical signature and marshall
        message.setSignature(signature);
        SAMLObjectContentReference reference = (SAMLObjectContentReference) signature.getContentReferences().get(0);
        reference.setDigestAlgorithm(digestAlgId);
        try
        {
            XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(message).marshall(message);
            Signer.signObject(signature);
        }
        catch (MarshallingException | SignatureException e)
        {
            throw new RuntimeException(e);
        }
    }


}
