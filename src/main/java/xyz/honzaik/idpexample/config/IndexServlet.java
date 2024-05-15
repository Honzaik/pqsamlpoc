package xyz.honzaik.idpexample.config;

import com.google.gson.Gson;
import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import xyz.honzaik.idpexample.GenUtil;
import xyz.honzaik.idpexample.GlobalConstants;
import xyz.honzaik.idpexample.KeyUtils;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Handles demo configuration.
 * Generates keys and certificates based on the configured values.
 */
@WebServlet(name = "configIndexServlet", value = "/config")
public class IndexServlet extends HttpServlet
{

    private VelocityEngine velocityEngine = null;
    private static final Logger LOG = LoggerFactory.getLogger(IndexServlet.class);

    public void init()
    {
        this.velocityEngine = new VelocityEngine();
        this.velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADERS, "file,classpath");
        this.velocityEngine.setProperty("resource.loader.classpath.class", "org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
        this.velocityEngine.setProperty("resource.loader.file.path", getClass().getResource(GlobalConstants.VELOCITY_TEMPLATES_FOLDER).getPath());
        this.velocityEngine.init();
    }

    public void doGet(HttpServletRequest req, HttpServletResponse resp)
    {
        LOG.info("config index servlet");
        resp.setContentType("text/html");
        resp.setCharacterEncoding("UTF-8");
        try
        {
            PrintWriter writer = resp.getWriter();
            VelocityContext vc = new VelocityContext();
            Template t = velocityEngine.getTemplate("configIndex.vm");

            vc.put("supportedSignatures", GlobalConstants.supportedSignatures);
            vc.put("supportedPKEs", GlobalConstants.supportedPKEs);

            Properties currentConfig = GenUtil.getConfig();
            vc.put("config", currentConfig);
            vc.put("constants", GlobalConstants.class);

            t.merge(vc, writer);
        }
        catch (IOException e)
        {
            throw new RuntimeException(e);
        }
    }

    public void doPost(HttpServletRequest req, HttpServletResponse resp) {
        resp.setContentType("application/json");
        resp.setCharacterEncoding("UTF-8");

        try
        {
            Gson gson = new Gson();
            BufferedReader br = req.getReader();
            StringBuilder sb = new StringBuilder();
            String line = null;
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }

            DemoConfig config = gson.fromJson(sb.toString(), DemoConfig.class);
            configureDemo(config);

            PrintWriter writer = resp.getWriter();
            HashMap<String, Object> response = new HashMap<>();
            response.put("success", true);

            writer.print(gson.toJson(response));
        }
        catch (IOException e)
        {
            throw new RuntimeException(e);
        }

    }

    private void configureDemo(DemoConfig newConfig) {

        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());
        //generate config file
        Properties currentConfig = GenUtil.getConfig();
        LOG.info(currentConfig.toString());

        //set first KEM
        currentConfig.put("sp:kemAlg", newConfig.kemSelect);
        //set second KEM
        if (newConfig.kemHybridCheckbox != null) { //hybrid KEM enabled
            currentConfig.put("sp:kemAlgExtra", newConfig.extraKemSelect);
            currentConfig.put("sp:useHybridEnc", "true");
            currentConfig.put("idp:useHybridEnc", "true");
        } else {
            currentConfig.put("sp:kemAlgExtra", "");
            currentConfig.put("sp:useHybridEnc", "false");
            currentConfig.put("idp:useHybridEnc", "false");
        }

        //SP config
        currentConfig.put("sp:hostURL", newConfig.spHost);
        currentConfig.put("sp:signatureAlg", newConfig.spSigSelect);
        if (newConfig.spHybridCheckbox != null) { //hybrid sig enabled
            currentConfig.put("sp:signatureAlgExtra", newConfig.spExtraSigSelect);
            currentConfig.put("sp:useHybridSig", "true");
            currentConfig.put("idp:verifyHybridSig", "true");
        } else {
            currentConfig.put("sp:signatureAlgExtra", "");
            currentConfig.put("sp:useHybridSig", "false");
            currentConfig.put("idp:verifyHybridSig", "false");
        }

        //IdP config
        currentConfig.put("idp:hostURL", newConfig.idpHost);
        currentConfig.put("idp:signatureAlg", newConfig.idpSigSelect);
        if (newConfig.idpHybridCheckbox != null) { //hybrid sig enabled
            currentConfig.put("idp:signatureAlgExtra", newConfig.idpExtraSigSelect);
            currentConfig.put("idp:useHybridSig", "true");
            currentConfig.put("sp:verifyHybridSig", "true");
        } else {
            currentConfig.put("idp:signatureAlgExtra", "");
            currentConfig.put("idp:useHybridSig", "false");
            currentConfig.put("sp:verifyHybridSig", "false");
        }

        generateKeyStores(currentConfig);

        try
        {
            currentConfig.storeToXML(new FileOutputStream(GenUtil.getConfigFilePath()), null); //save config
        }
        catch (IOException e)
        {
            throw new RuntimeException(e);
        }
    }

    private void generateKeyStores(Properties config) {
        LinkedHashSet<String> signatureAlgsXML = new LinkedHashSet<>();
        signatureAlgsXML.add(config.getProperty("sp:signatureAlg"));
        if (config.getProperty("sp:useHybridSig").equals("true")) {
            signatureAlgsXML.add(config.getProperty("sp:signatureAlgExtra"));
        }
        signatureAlgsXML.add(config.getProperty("idp:signatureAlg"));
        if (config.getProperty("idp:useHybridSig").equals("true")) {
            signatureAlgsXML.add(config.getProperty("idp:signatureAlgExtra"));
        }

        for (String signatureAlgXML : signatureAlgsXML) {
            createCA(signatureAlgXML); //generate keystore for CA, we use a separate CA for each sig. alg. so that the cert. chain uses only one signature algorithm.
        }

        generateKemAndSigKeyStores(config, "sp"); //generate a keystore for SP
        generateKemAndSigKeyStores(config, "idp"); //generate a keystore for IdP

        KeyStore keyStore = KeyUtils.loadKeyStore(getClass().getResource(GlobalConstants.KEYSTORE_FOLDER).getPath() + "sp.p12", GlobalConstants.KEYSTORE_PW);
        KeyStore idpkeyStore = KeyUtils.loadKeyStore(getClass().getResource(GlobalConstants.KEYSTORE_FOLDER).getPath() + "idp.p12", GlobalConstants.KEYSTORE_PW);

    }

    private void generateKemAndSigKeyStores(Properties config, String entityName) {
        try
        {
            boolean isHybridSig = Boolean.parseBoolean(config.getProperty(entityName + ":useHybridSig"));
            boolean isHybridEnc = Boolean.parseBoolean(config.getProperty(entityName + ":useHybridEnc"));

            String keyStorePath = getClass().getResource(GlobalConstants.KEYSTORE_FOLDER).getPath() + entityName + ".p12";
            KeyUtils.createKeyStore(keyStorePath, GlobalConstants.KEYSTORE_PW, true);
            KeyStore keyStore = KeyUtils.loadKeyStore(keyStorePath, GlobalConstants.KEYSTORE_PW);

            //save data about keystore into the config
            config.put(entityName + ":keyStoreFilename", entityName + ".p12");
            config.put(entityName + ":keyStorePassword", GlobalConstants.KEYSTORE_PW);

            String signatureAlg = GlobalConstants.XMLIDtoSignatureMap.get(config.getProperty(entityName + ":signatureAlg")); //translate XML algorithm identifier to a BouncyCastle algorithm identifier
            //we load CA which will sign IdP/SP certs
            KeyStore ca = KeyUtils.loadKeyStore(getClass().getResource(GlobalConstants.KEYSTORE_FOLDER).getPath() + "ca_" + signatureAlg.toLowerCase() + ".p12", GlobalConstants.KEYSTORE_PW);
            X509Certificate caCert = (X509Certificate) ca.getCertificate(GlobalConstants.SIG_PRIV_KEY_KEYSTORE_NAME);

            String signatureAlgExtra = null;
            KeyStore caExtra = null;
            X509Certificate caExtraCert = null;
            //if hybrid signatures (non-composite) are used - we load the extra CA: one CA is classical, the other is PQ
            if (isHybridSig)
            {
                signatureAlgExtra = GlobalConstants.XMLIDtoSignatureMap.get(config.getProperty(entityName + ":signatureAlgExtra"));
                caExtra = KeyUtils.loadKeyStore(getClass().getResource(GlobalConstants.KEYSTORE_FOLDER).getPath() + "ca_" + signatureAlgExtra.toLowerCase() + ".p12", GlobalConstants.KEYSTORE_PW);
                caExtraCert = (X509Certificate) caExtra.getCertificate(GlobalConstants.SIG_PRIV_KEY_KEYSTORE_NAME);
            }

            if (entityName == "sp")
            {
                //kem generation
                String kemAlg = GlobalConstants.XMLIDtoPKEMap.get(config.getProperty(entityName + ":kemAlg"));
                KeyPair kemKeyPair = generateKeyPair(kemAlg);
                X509Certificate kemCert = generateCertificate(KeyUtils.getKeyCorrespondingToCertificate(ca, caCert), kemKeyPair.getPublic(), entityName + " " + kemAlg, caCert.getSubjectX500Principal().getName());
                KeyUtils.storeKeyAndCert(keyStore, GlobalConstants.KEM_PRIV_KEY_KEYSTORE_NAME, kemKeyPair.getPrivate(), kemCert);

                if (isHybridEnc)
                {
                    KeyStore signingKeyStore = isHybridSig ? caExtra : ca;
                    X509Certificate signingCert = isHybridSig ? caExtraCert : caCert;
                    kemAlg = GlobalConstants.XMLIDtoPKEMap.get(config.getProperty(entityName + ":kemAlgExtra"));
                    kemKeyPair = generateKeyPair(kemAlg);
                    kemCert = generateCertificate(KeyUtils.getKeyCorrespondingToCertificate(signingKeyStore, signingCert), kemKeyPair.getPublic(), entityName + " " + kemAlg, signingCert.getSubjectX500Principal().getName());
                    KeyUtils.storeKeyAndCert(keyStore, GlobalConstants.KEM_EXTRA_PRIV_KEY_KEYSTORE_NAME, kemKeyPair.getPrivate(), kemCert);
                }
            }

            //sig generation
            KeyPair sigKeyPair = generateKeyPair(signatureAlg);
            X509Certificate sigCert = generateCertificate(KeyUtils.getKeyCorrespondingToCertificate(ca, caCert), sigKeyPair.getPublic(), entityName + " " + signatureAlg, caCert.getSubjectX500Principal().getName());
            KeyUtils.storeKeyAndCert(keyStore, GlobalConstants.SIG_PRIV_KEY_KEYSTORE_NAME, sigKeyPair.getPrivate(), sigCert);

            if (isHybridSig) {
                KeyStore signingKeyStore = isHybridSig ? caExtra : ca;
                X509Certificate signingCert = isHybridSig ? caExtraCert : caCert;
                sigKeyPair = generateKeyPair(signatureAlgExtra);
                sigCert = generateCertificate(KeyUtils.getKeyCorrespondingToCertificate(signingKeyStore, signingCert), sigKeyPair.getPublic(), entityName + " " + signatureAlgExtra, signingCert.getSubjectX500Principal().getName());
                KeyUtils.storeKeyAndCert(keyStore, GlobalConstants.SIG_EXTRA_PRIV_KEY_KEYSTORE_NAME, sigKeyPair.getPrivate(), sigCert);
            }

            KeyUtils.saveKeyStore(keyStore, keyStorePath, GlobalConstants.KEYSTORE_PW);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new RuntimeException(e);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new RuntimeException(e);
        }
        catch (KeyStoreException e)
        {
            throw new RuntimeException(e);
        }
        catch (UnrecoverableKeyException e)
        {
            throw new RuntimeException(e);
        }
    }

    private void createCA(String signatureAlgXML) {
        String signatureAlg = GlobalConstants.XMLIDtoSignatureMap.get(signatureAlgXML);
        String keyStorePath = getClass().getResource(GlobalConstants.KEYSTORE_FOLDER).getPath() + "ca_" + signatureAlg.toLowerCase() + ".p12";
        KeyUtils.createKeyStore(keyStorePath, GlobalConstants.KEYSTORE_PW, true);
        KeyStore keyStore = KeyUtils.loadKeyStore(keyStorePath, GlobalConstants.KEYSTORE_PW);
        try
        {
            KeyPair keyPair = generateKeyPair(signatureAlg.toUpperCase());
            X509Certificate cert = generateCertificate(keyPair.getPrivate(), keyPair.getPublic(), "CA " + signatureAlg, "CA " + signatureAlg);
            KeyUtils.storeKeyAndCert(keyStore, GlobalConstants.SIG_PRIV_KEY_KEYSTORE_NAME, keyPair.getPrivate(), cert);
            KeyUtils.saveKeyStore(keyStore, keyStorePath, GlobalConstants.KEYSTORE_PW);
        }
        catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e)
        {
            throw new RuntimeException(e);
        }
        catch (KeyStoreException e)
        {
            throw new RuntimeException(e);
        }
    }

    //standard Java key generation, we only select the algorithm based on the string name + for each algorithm we have predefined parameters.
    private KeyPair generateKeyPair(String algName) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException
    {
        LOG.info(algName);
        KeyPairGenerator keygen = KeyPairGenerator.getInstance(algName);
        LOG.info(keygen.getAlgorithm());
        switch (keygen.getAlgorithm().toUpperCase())
        {
            case "RSA":
                keygen.initialize(GlobalConstants.RSA_KEY_SIZE, new SecureRandom());
                break;
            case "DILITHIUM":
                keygen.initialize(DilithiumParameterSpec.dilithium2, new SecureRandom());
                break;
            case "FALCON":
                keygen.initialize(FalconParameterSpec.falcon_512, new SecureRandom());
                break;
            case "CMCE":
                keygen.initialize(CMCEParameterSpec.mceliece348864, new SecureRandom());
                break;
            case "KYBER":
                keygen.initialize(KyberParameterSpec.kyber512, new SecureRandom());
                break;
            case "BIKE":
                keygen.initialize(BIKEParameterSpec.bike128, new SecureRandom());
                break;
            case "SPHINCS+":
                keygen.initialize(SPHINCSPlusParameterSpec.shake_128s, new SecureRandom());
                break;
            case "MLDSA44-ECDSA-P256-SHA256":
            case "MLDSA87-ECDSA-P384-SHA512":
            case "FALCON512-ECDSA-P256-SHA256":
                keygen.initialize(null, new SecureRandom());
                break;

            default:
                throw new RuntimeException("Unable to init keygen");
        }
        return keygen.generateKeyPair();
    }

    public static X509Certificate generateCertificate(PrivateKey signingKey, PublicKey publicKey, String subjectName, String issuerName)
    {
        String signatureAlgorithm = signingKey.getAlgorithm();

        if (signatureAlgorithm.equals("RSA"))
        {
            signatureAlgorithm = "SHA256withRSA";
        }

        String provider = "BCPQC";
        if (signatureAlgorithm.contains("RSA") || signatureAlgorithm.contains("-") || signatureAlgorithm.contains("SPHINCS")) { //for classical, composites and SPHINCS+ we need to use the non-PQC provider
            provider = "BC";
        }

        if (!issuerName.contains("CN=")) {
            issuerName = "CN=" + issuerName;
        }

        //standard certificate creation

        X500Name issuer = new X500Name(issuerName);
        BigInteger serial = BigInteger.valueOf(5);
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24 * 365L);
        X500Name subject = new X500Name("CN=" + subjectName);
        X509Certificate cert = null;

        JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, publicKey);

        try
        {
            X509CertificateHolder certHolder = certificateBuilder.build(new JcaContentSignerBuilder(signatureAlgorithm).setProvider(provider).build(signingKey));
            cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
        }
        catch (OperatorCreationException | CertificateException e)
        {
            throw new RuntimeException(e);
        }
        return cert;
    }

}
