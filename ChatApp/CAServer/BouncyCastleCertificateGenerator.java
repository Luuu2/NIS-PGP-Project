package CAServer;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

public class BouncyCastleCertificateGenerator {

    private static final String BC_PROVIDER = "BC";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    public static void main(String[] args) throws Exception{
        // Add the BouncyCastle Provider
        Security.addProvider(new BouncyCastleProvider());

        // Initialize a new KeyPair generator
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC_PROVIDER);
        keyPairGenerator.initialize(2048);

        // Setup start date to yesterday and end date for 1 year validity
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -1);
        Date startDate = calendar.getTime();

        calendar.add(Calendar.YEAR, 1);
        Date endDate = calendar.getTime();

        // First step is to create a root certificate
        // First Generate a KeyPair,
        // then a random serial number
        // then generate a certificate using the KeyPair
        KeyPair rootKeyPair = keyPairGenerator.generateKeyPair();
        BigInteger rootSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));

        // Issued By and Issued To same for root certificate
        X500Name rootCertIssuer = new X500Name("CN=PGP-rcert");
        X500Name rootCertSubject = rootCertIssuer;
        ContentSigner rootCertContentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER).build(rootKeyPair.getPrivate());
        X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(rootCertIssuer, rootSerialNum, startDate, endDate, rootCertSubject, rootKeyPair.getPublic());

        // Add Extensions
        // A BasicConstraint to mark root certificate as CA certificate
        JcaX509ExtensionUtils rootCertExtUtils = new JcaX509ExtensionUtils();
        rootCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        rootCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, rootCertExtUtils.createSubjectKeyIdentifier(rootKeyPair.getPublic()));

        // Create a cert holder and export to X509Certificate
        X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertContentSigner);
        X509Certificate rootCert = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(rootCertHolder);

        writeCertToFileBase64Encoded(rootCert, "PGP-rcert.cer");
        exportKeyPairToKeystoreFile(rootKeyPair, rootCert, "PGP-rcert", "PGP-rcert.pfx", "PKCS12", "pass");

        ///////////////////////////////    A RANDOM    //////////////////////////////////////
        // Generate a new KeyPair and sign it using the Root Cert Private Key
        // by generating a CSR (Certificate Signing Request)
        X500Name issuedCertSubject = new X500Name("CN=PGP-icert");
        BigInteger issuedCertSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));
        KeyPair issuedCertKeyPair = keyPairGenerator.generateKeyPair();

        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(issuedCertSubject, issuedCertKeyPair.getPublic());
        JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER);

        // Sign the new KeyPair with the root cert Private Key
        ContentSigner csrContentSigner = csrBuilder.build(rootKeyPair.getPrivate());
        PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);

        // Use the Signed KeyPair and CSR to generate an issued Certificate
        // Here serial number is randomly generated. In general, CAs use
        // a sequence to generate Serial number and avoid collisions
        X509v3CertificateBuilder issuedCertBuilder = new X509v3CertificateBuilder(rootCertIssuer, issuedCertSerialNum, startDate, endDate, csr.getSubject(), csr.getSubjectPublicKeyInfo());

        JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils();

        // Add Extensions
        // Use BasicConstraints to say that this Cert is not a CA
        issuedCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        // Add Issuer cert identifier as Extension
        issuedCertBuilder.addExtension(Extension.authorityKeyIdentifier, false, issuedCertExtUtils.createAuthorityKeyIdentifier(rootCert));
        issuedCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));

        // Add intended key usage extension if needed
        issuedCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyEncipherment));

        // Add DNS name is cert is to used for SSL
        issuedCertBuilder.addExtension(Extension.subjectAlternativeName, false, new DERSequence(new ASN1Encodable[] {
                new GeneralName(GeneralName.dNSName, "mydomain.local"),
                new GeneralName(GeneralName.iPAddress, "127.0.0.1")
        }));

        X509CertificateHolder issuedCertHolder = issuedCertBuilder.build(csrContentSigner);
        X509Certificate issuedCert  = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(issuedCertHolder);

        // Verify the issued cert signature against the root (issuer) cert
        issuedCert.verify(rootCert.getPublicKey(), BC_PROVIDER);

        writeCertToFileBase64Encoded(issuedCert, "PGP-icert.cer");
        exportKeyPairToKeystoreFile(issuedCertKeyPair, issuedCert, "PGP-icert", "PGP-icert.pfx", "PKCS12", "pass");

        //System.out.println(issuedCert);
        //System.out.println(issuedCertKeyPair);

        ///////////////////////////////    BOB    //////////////////////////////////////
        // Generate a new KeyPair and sign it using the Root Cert Private Key
        // by generating a CSR (Certificate Signing Request)
        X500Name issuedBCertSubject = new X500Name("CN=PGP-iBcert");
        BigInteger issuedBCertSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));
        KeyPair issuedBCertKeyPair = keyPairGenerator.generateKeyPair();

        PKCS10CertificationRequestBuilder p10BuilderB = new JcaPKCS10CertificationRequestBuilder(issuedBCertSubject, issuedBCertKeyPair.getPublic());
        JcaContentSignerBuilder csrBBuilderB = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER);

        // Sign the new KeyPair with the root cert Private Key
        ContentSigner csrBContentSigner = csrBBuilderB.build(rootKeyPair.getPrivate());
        PKCS10CertificationRequest csrB = p10BuilderB.build(csrBContentSigner);

        // Use the Signed KeyPair and CSR to generate an issued Certificate
        // Here serial number is randomly generated. In general, CAs use
        // a sequence to generate Serial number and avoid collisions
        X509v3CertificateBuilder issuedBCertBuilder = new X509v3CertificateBuilder(rootCertIssuer, issuedBCertSerialNum, startDate, endDate, csrB.getSubject(), csrB.getSubjectPublicKeyInfo());

        JcaX509ExtensionUtils issuedBCertExtUtils = new JcaX509ExtensionUtils();

        // Add Extensions
        // Use BasicConstraints to say that this Cert is not a CA
        issuedBCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        // Add Issuer cert identifier as Extension
        issuedBCertBuilder.addExtension(Extension.authorityKeyIdentifier, false, issuedBCertExtUtils.createAuthorityKeyIdentifier(rootCert));
        issuedBCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, issuedBCertExtUtils.createSubjectKeyIdentifier(csrB.getSubjectPublicKeyInfo()));

        // Add intended key usage extension if needed
        issuedBCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyEncipherment));

        // Add DNS name is cert is to used for SSL
        issuedBCertBuilder.addExtension(Extension.subjectAlternativeName, false, new DERSequence(new ASN1Encodable[] {
                new GeneralName(GeneralName.dNSName, "mydomain.local"),
                new GeneralName(GeneralName.iPAddress, "127.0.0.1")
        }));

        X509CertificateHolder issuedBCertHolder = issuedBCertBuilder.build(csrBContentSigner);
        X509Certificate issuedBCert  = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(issuedBCertHolder);

        // Verify the issuedB cert signature against the root (issuer) cert
        issuedBCert.verify(rootCert.getPublicKey(), BC_PROVIDER);

        writeCertToFileBase64Encoded(issuedBCert, "PGP-iBcert.cer");
        exportKeyPairToKeystoreFile(issuedBCertKeyPair, issuedBCert, "PGP-iBcert", "PGP-iBcert.pfx", "PKCS12", "Bpass");

        //System.out.println(issuedBCert);
        //System.out.println(issuedBCertKeyPair);

        ///////////////////////////////    ALICE    //////////////////////////////////////
        // Generate a new KeyPair and sign it using the Root Cert Private Key
        // by generating a CSR (Certificate Signing Request)
        X500Name issuedACertSubject = new X500Name("CN=PGP-iAcert");
        BigInteger issuedACertSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));
        KeyPair issuedACertKeyPair = keyPairGenerator.generateKeyPair();

        PKCS10CertificationRequestBuilder p10BuilderA = new JcaPKCS10CertificationRequestBuilder(issuedACertSubject, issuedACertKeyPair.getPublic());
        JcaContentSignerBuilder csrABuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER);

        // Sign the new KeyPair with the root cert Private Key
        ContentSigner csrAContentSigner = csrABuilder.build(rootKeyPair.getPrivate());
        PKCS10CertificationRequest csrA = p10BuilderA.build(csrAContentSigner);

        // Use the Signed KeyPair and CSR to generate an issuedA Certificate
        // Here serial number is randomly generated. In general, CAs use
        // a sequence to generate Serial number and avoid collisions
        X509v3CertificateBuilder issuedACertBuilder = new X509v3CertificateBuilder(rootCertIssuer, issuedACertSerialNum, startDate, endDate, csrA.getSubject(), csrA.getSubjectPublicKeyInfo());

        JcaX509ExtensionUtils issuedACertExtUtils = new JcaX509ExtensionUtils();

        // Add Extensions
        // Use BasicConstraints to say that this Cert is not a CA
        issuedACertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        // Add Issuer cert identifier as Extension
        issuedACertBuilder.addExtension(Extension.authorityKeyIdentifier, false, issuedACertExtUtils.createAuthorityKeyIdentifier(rootCert));
        issuedACertBuilder.addExtension(Extension.subjectKeyIdentifier, false, issuedACertExtUtils.createSubjectKeyIdentifier(csrA.getSubjectPublicKeyInfo()));

        // Add intended key usage extension if needed
        issuedACertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyEncipherment));

        // Add DNS name is cert is to used for SSL
        issuedACertBuilder.addExtension(Extension.subjectAlternativeName, false, new DERSequence(new ASN1Encodable[] {
                new GeneralName(GeneralName.dNSName, "mydomain.local"),
                new GeneralName(GeneralName.iPAddress, "127.0.0.1")
        }));

        X509CertificateHolder issuedACertHolder = issuedACertBuilder.build(csrAContentSigner);
        X509Certificate issuedACert  = new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(issuedACertHolder);

        // Verify the issuedA cert signature against the root (issuer) cert
        issuedACert.verify(rootCert.getPublicKey(), BC_PROVIDER);

        writeCertToFileBase64Encoded(issuedACert, "PGP-iAcert.cer");
        exportKeyPairToKeystoreFile(issuedACertKeyPair, issuedACert, "PGP-iAcert", "PGP-iAcert.pfx", "PKCS12", "Apass");

        //System.out.println(issuedACert);
        //System.out.println(issuedACertKeyPair);

    }

    static void exportKeyPairToKeystoreFile(KeyPair keyPair, Certificate certificate, String alias, String fileName, String storeType, String storePass) throws Exception {
        KeyStore sslKeyStore = KeyStore.getInstance(storeType, BC_PROVIDER);
        sslKeyStore.load(null, null);
        sslKeyStore.setKeyEntry(alias, keyPair.getPrivate(),null, new Certificate[]{certificate});
        FileOutputStream keyStoreOs = new FileOutputStream(fileName);
        sslKeyStore.store(keyStoreOs, storePass.toCharArray());
    }

    static void writeCertToFileBase64Encoded(Certificate certificate, String fileName) throws Exception {
        FileOutputStream certificateOut = new FileOutputStream(fileName);
        certificateOut.write("-----BEGIN CERTIFICATE-----".getBytes());
        certificateOut.write(Base64.encode(certificate.getEncoded()));
        certificateOut.write("-----END CERTIFICATE-----".getBytes());
        certificateOut.close();
    }
}