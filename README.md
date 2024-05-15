# pqsamlpoc
Proof of concept implementation of a RP and IdP using post-quantum SAML.

# How to run
This POC is a WAR application for Tomcat 9. The result of the build process will output ROOT.war that can be deployed traditionally. Build instructions are described below after prerequisites.

To be able to compile it, we need to build a custom version of OpenSAML 4.3.0 which depends on a custom version of Apache Santuario.

 We also require BouncyCastle (official) version 1.78+ (that version already includes our implementation of composite signatures https://github.com/EntrustCorporation/draft-ounsworth-composite-sigs which can be optionally used in the POC).

We use Maven (tested on version 3.9 on MacOS) for building the POC and the libraries also use Maven.

# Building Apache Santuario
Clone the repository of our modified Apache Santuario version 4.0.3-PQ + install into local Maven repository.
```
git clone https://github.com/PQSAML/santuario-xml-security-java-pqsaml
cd santuario-xml-security-java-pqsaml
mvn install -DskipTests
```

# Building OpenSAML
Note that the official OpenSAML is not hosted on Github (https://shibboleth.atlassian.net/wiki/spaces/DEV/pages/1118699532/Source+Code+Access) but it can be found at https://git.shibboleth.net/view/. 

Our version is a fork of the unnofficial Github mirror https://github.com/unofficial-shibboleth-mirror/java-opensaml as Github allows to view the diff easily.

Note that OpenSAML latest version is 5+ but we developed our solutions for 4.3.0. We presume our modifications should be compatible with the newest version but we have not tested it. 

Before we can initiate the build. We need to modify Maven settings and add dependency repositories as noted here https://shibboleth.atlassian.net/wiki/spaces/DEV/pages/2891317253/MavenRepositories. On MacOS, we need to create a file name `settings.xml` in folder the `~/.m2/` with the contents available at https://github.com/PQSAML/index/blob/main/settings.xml or https://shibboleth.atlassian.net/wiki/spaces/DEV/pages/2891317253/MavenRepositories 

To build OpenSAML, we need to download the code, checkout to the correct branch and install using maven. In total:
```
git clone https://github.com/PQSAML/java-opensaml-pq
cd java-opensaml-pq
git checkout 4.3.0-pq
cd opensaml-parent
mvn -Prelease -DskipTests -D no-check-m2 -Dmaven.javadoc.skip=true install
```

This builds and installs OpenSAML into the local Maven repository.

# Building POC
Navigate into the root directory of this repository (where this readme is).
```
mvn compiler:compile
mvn resources:resources
mvn war:war
```

The resulting WAR is located at target/ROOT.war

# POC usage
After deploying the WAR on a Tomcat server. The index webpage looks like this https://i.imgur.com/lcZHi3d.png. 

Before clicking on the first link (beginning the demo), we need to generate the keys/certificates using the demo configurator (second link). 

The configurator page looks like this https://i.imgur.com/oFJhBPj.png. 

"Common settings" is regarding the XML encryption used to encrypt the Assertion. If hybrid checkbox is checked, then the (extra) algorithm is used in hybrid mode with the first one.

IdP settings asks about the IDP domain (for redirect purposes, can be the same as SP) and the signature algorithms the IdP will use to sign the Response.

SP settings same set of settings but for the SP.

After clicking submit, a loading wheel will appear and it will take a few seconds for everything to get generated. After the process is done, "Saved." should appear next to the submit button.

After that, the demo is ready to be ran using the first link on the index page.