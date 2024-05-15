package xyz.honzaik.idpexample;

import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.EncryptionConstants;

import java.util.HashMap;

public abstract class GlobalConstants
{

    public static final String VELOCITY_TEMPLATES_FOLDER = "/templates/";
    public static final String KEYSTORE_FOLDER = "/keys/";
    public static final String configFileName = "appconfig.xml";

    public static final int RSA_KEY_SIZE = 3072;
    public static final String KEYSTORE_PW = "password";
    public static final String SIG_PRIV_KEY_KEYSTORE_NAME = "sig";
    public static final String SIG_EXTRA_PRIV_KEY_KEYSTORE_NAME = "sigExtra";
    public static final String KEM_PRIV_KEY_KEYSTORE_NAME = "kem";
    public static final String KEM_EXTRA_PRIV_KEY_KEYSTORE_NAME = "kemExtra";

    public static final String[] supportedSignatures = {
            "RSA",
            "Dilithium",
            "Falcon",
            "SphincsPlus",
            "MLDSA44-ECDSA-P256-SHA256",
            "MLDSA87-ECDSA-P384-SHA512",
            "Falcon512-ECDSA-P256-SHA256",
    };

    public static final String[] supportedPKEs = {
            "RSA",
            "Kyber",
            "CMCE",
            "BIKE",
    };

    public static final HashMap<String, String> signatureToXMLIDMap;
    public static final HashMap<String, String> XMLIDtoSignatureMap;
    public static final HashMap<String, String> PKEToXMLIDMap;
    public static final HashMap<String, String> XMLIDtoPKEMap;


    static {
        signatureToXMLIDMap = new HashMap<>();
        XMLIDtoSignatureMap = new HashMap<>();
        for (String signature : supportedSignatures) {
            if (signature.contains("-")) {
                signatureToXMLIDMap.put(signature, Constants.XML_DSIG_PQC_COMPOSITES + signature.toLowerCase());
                XMLIDtoSignatureMap.put(Constants.XML_DSIG_PQC_COMPOSITES + signature.toLowerCase(), signature);
            } else if (signature == "RSA") {
                signatureToXMLIDMap.put(signature, XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
                XMLIDtoSignatureMap.put(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, signature);
            } else {
                signatureToXMLIDMap.put(signature, Constants.XML_DSIG_PQC + signature.toLowerCase());
                XMLIDtoSignatureMap.put(Constants.XML_DSIG_PQC + signature.toLowerCase(), signature);
            }
        }

        PKEToXMLIDMap = new HashMap<>();
        XMLIDtoPKEMap = new HashMap<>();
        for (String pke : supportedPKEs) {
            if (pke == "RSA") {
                PKEToXMLIDMap.put(pke, XMLCipher.RSA_OAEP);
                XMLIDtoPKEMap.put(XMLCipher.RSA_OAEP, pke);
            } else {
                PKEToXMLIDMap.put(pke, EncryptionConstants.EncryptionSpecPQC + pke.toLowerCase());
                XMLIDtoPKEMap.put(EncryptionConstants.EncryptionSpecPQC + pke.toLowerCase(), pke);
            }

        }
    }

    //dont remove, used inside the velocity config template.
    public static String[] getSupportedSignatures() {
         return supportedSignatures;
    }
    public static String getSignatureXMLID(String signature) {
         return signatureToXMLIDMap.get(signature);
    }
    public static String[] getSupportedPKEs(){
        return supportedPKEs;
    }
    public static String getPKEXMLID(String pke) {
        return PKEToXMLIDMap.get(pke);
    }

}
