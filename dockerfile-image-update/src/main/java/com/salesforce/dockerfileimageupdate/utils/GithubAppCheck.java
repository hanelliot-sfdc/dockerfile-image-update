package com.salesforce.dockerfileimageupdate.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.salesforce.dockerfileimageupdate.CommandLine;
import net.sourceforge.argparse4j.inf.Namespace;
import org.bouncycastle.util.io.pem.PemReader;
import org.kohsuke.github.GitHub;
import org.kohsuke.github.GitHubBuilder;
import org.kohsuke.github.HttpException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Date;

public class GithubAppCheck {
    private static final Logger log = LoggerFactory.getLogger(GithubAppCheck.class);

    private final String appId;
    private final String privateKeyPath;
    private String jwt;
    private Instant jwtExpiry;
    private GitHub gitHub;

    public GithubAppCheck(final Namespace ns){
        this.appId = ns.get(Constants.SKIP_GITHUB_APP_ID);
        this.privateKeyPath = ns.get(Constants.SKIP_GITHUB_APP_KEY);
        this.jwt = null;
        this.jwtExpiry = null;
        try {
            generateJWT(this.appId, this.privateKeyPath);
        } catch (GeneralSecurityException | IOException exception) {
            log.warn("Could not initialise JWT due to exception: {}", exception.getMessage());
        }
        try {
            this.gitHub = new GitHubBuilder()
                    .withEndpoint(CommandLine.gitApiUrl(ns))
                    .withJwtToken(jwt)
                    .build();
        } catch (IOException exception) {
            log.warn("Could not initialise github due to exception: {}", exception.getMessage());
            this.gitHub = null;
        }
    }

    protected boolean isGithubAppEnabledOnRepository(String fullRepoName){
        refreshJwtIfNeeded(appId, privateKeyPath);
        try {
            gitHub.getApp().getInstallationByRepository(fullRepoName.split("/")[0], fullRepoName.split("/")[1]);
            return true;
        } catch (HttpException exception) {
            if (exception.getResponseCode() != 404) {
                log.warn("Caught a HTTPException {} while trying to get app installation. Defaulting to False", exception.getMessage());
            }
            return false;
        } catch (IOException exception) {
            log.warn("Caught a IOException {} while trying to get app installation. Defaulting to False", exception.getMessage());
            return false;
        }
    }

    private void refreshJwtIfNeeded(String appId, String privateKeyPath){
        if (jwt == null || jwtExpiry.isBefore(Instant.now().minusSeconds(60))) {  // Adding a buffer to ensure token validity
            try {
                generateJWT(appId, privateKeyPath);
            } catch (IOException | GeneralSecurityException exception) {
                log.warn("Could not refresh the JWT due to exception: {}", exception.getMessage());
            }
        }
    }

    private void generateJWT(String appId, String privateKeyPath) throws IOException, GeneralSecurityException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        RSAPrivateKey privateKey = getRSAPrivateKey(privateKeyPath);

        Algorithm algorithm = Algorithm.RSA256(null, privateKey);
        Instant now = Instant.now();
        jwt = JWT.create()
                .withIssuer(appId)
                .withIssuedAt(Date.from(now))
                .withExpiresAt(Date.from(now.plusSeconds(600))) // 10 minutes expiration
                .sign(algorithm);
        jwtExpiry = now.plusSeconds(600);
    }

    private RSAPrivateKey getRSAPrivateKey(String privateKeyPath) throws IOException, GeneralSecurityException {
        try (PemReader pemReader = new PemReader(new FileReader(new File(privateKeyPath)))) {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pemReader.readPemObject().getContent());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(spec);
        }
    }

}
