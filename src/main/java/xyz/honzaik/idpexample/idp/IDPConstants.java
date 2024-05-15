package xyz.honzaik.idpexample.idp;

public class IDPConstants
{

    public static final String baseURL = "/idp";
    public static final String authEndpointURL = baseURL + "/auth";
    public static final String loginEndpointURL = baseURL + "/login";
    public static final String resolveEndpointURL = baseURL + "/resolve";
    public static final String issuerName = "IDP";
    public static final String sessionAuthFinished = "IDP_AUTH";
    public static final String sessionAuthResult = "IDP_AUTH_RESULT";
    public static final String sessionAuthSubject = "IDP_AUTH_SUBJECT";
    public static final String sessionAuthnRequestAttrName = "IDP_AuthnRequest";
    public static final String sessionLastURLAttrName = "IDP_lastURL";



}
