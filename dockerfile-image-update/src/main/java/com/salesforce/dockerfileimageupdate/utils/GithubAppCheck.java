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
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Date;

import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.Scanner;

import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryConfig;
import io.vavr.control.Try;
import java.time.Duration;


public class GithubAppCheck {
    private static final Logger log = LoggerFactory.getLogger(GithubAppCheck.class);

    private final String appId;
    private final String privateKeyPath;
    private final String appServerApiToken;
    private final String appServerApiEndpoint;
    private String jwt;
    private Instant jwtExpiry;
    private GitHub gitHub;

    public GithubAppCheck(final Namespace ns){
        this.appId = ns.get(Constants.SKIP_GITHUB_APP_ID);
        this.privateKeyPath = ns.get(Constants.SKIP_GITHUB_APP_KEY);
        this.appServerApiToken = ns.get(Constants.SKIP_GITHUB_APP_SERVER_API_TOKEN);
        this.appServerApiEndpoint = ns.get(Constants.SKIP_GITHUB_APP_SERVER_API_ENDPOINT);
        this.jwt = null;
        this.jwtExpiry = null;
        this.gitHub = null;
        if (this.appId != null && this.privateKeyPath != null) {
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
            }
        }
        else {
            log.warn("Could not find any Github app ID and Github app Key in the declared list. Hence assuming this class is no longer needed");
        }
    }

    /**
     * Method to verify whether the github app is installed on a repository or not. 
     * @param fullRepoName = The repository full name, i.e, of the format "owner/repoName". Eg: "Salesforce/dockerfile-image-update"
     * @return True if github app is installed, false otherwise. 
     */
    protected boolean isGithubAppEnabledOnRepository(String fullRepoName) {
        RetryConfig config = RetryConfig.custom()
                .maxAttempts(1)
                .waitDuration(Duration.ofMillis(2000))
                .retryExceptions(IOException.class)
                .build();
        Retry retry = Retry.of("id", config);

        Try<Boolean> retryResult = Try.ofSupplier(Retry.decorateSupplier(retry, () -> isGithubAppEnabledOnRepositoryWithRenovateApi(fullRepoName)))
                .recover(throwable -> isGithubAppEnabledOnRepositoryWithGitApi(fullRepoName));

        return retryResult.get();
    }

    /**
     * Method to verify whether the github app is installed on a repository or not, using Git API
     * @param fullRepoName = The repository full name, i.e, of the format "owner/repoName". Eg: "Salesforce/dockerfile-image-update"
     * @return True if github app is installed, false otherwise. 
     * Reference: https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28#get-a-repository-installation-for-the-authenticated-app
     */
    protected boolean isGithubAppEnabledOnRepositoryWithGitApi(String fullRepoName) {
        refreshJwtIfNeeded(appId, privateKeyPath);
        try {
            gitHub.getApp().getInstallationByRepository(fullRepoName.split("/")[0], fullRepoName.split("/")[1]);
            return true;
        } catch (HttpException exception) {
            if (exception.getResponseCode() != 404) {
                // Log for any HTTP status code other than 404 Not found. 
                log.warn("Caught a HTTPException `{}` while trying to get app installation. Defaulting to False. Status code: {}", exception.getMessage(), exception.getResponseCode());
            }
            return false;
        } catch (IOException exception) {
            // Most often happens on timeout scenarios. 
            log.warn("Caught a IOException {} while trying to get app installation. Defaulting to False", exception.getMessage());
            return false;
        }
    }

    /**
     * Method to verify whether the github app is installed on a repository or not, using Renovate API
     * @param fullRepoName = The repository full name, i.e, of the format "owner/repoName". Eg: "Salesforce/dockerfile-image-update"
     * @return True if github app is installed, false otherwise. 
     * Reference: https://github.com/mend/renovate-ce-ee/blob/main/docs/reporting-apis.md#repo-info
     */
    protected boolean isGithubAppEnabledOnRepositoryWithRenovateApi(String fullRepoName) {
        try {
            String apiEndpoint = appServerApiEndpoint + "/api/repos/" + fullRepoName;
            URL url = new URL(apiEndpoint);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("Authorization", appServerApiToken);
            conn.connect();

            log.info("HTTPS Response Code: " + conn.getResponseCode());
            log.info("HTTPS Response Message: " + conn.getResponseMessage());
            
            if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
                BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                String inputLine;
                StringBuilder response = new StringBuilder();

                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                in.close();

                log.info(response.toString());
                if (response.toString().contains("installed")) {
                    return true;
                } else {
                    return false;
                }
            } else if (conn.getResponseCode() == HttpURLConnection.HTTP_NOT_FOUND) {
                log.warn("Repository not found");
                return false;
            } else {
                log.warn("GET request failed with response code: " + conn.getResponseCode());
                return false;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }


    /**
     * Method to refresh the JWT token if needed. Checks the JWT expiry time, and if it is 60s away from expiring, refreshes it. 
     * @param appId = The id of the Github App to generate the JWT for
     * @param privateKeyPath = The path to the private key of the Github App to generate the JWT for
     */
    private void refreshJwtIfNeeded(String appId, String privateKeyPath) {
        if (jwt == null || jwtExpiry.isBefore(Instant.now().minusSeconds(60))) {  // Adding a buffer to ensure token validity
            try {
                generateJWT(appId, privateKeyPath);
            } catch (IOException | GeneralSecurityException exception) {
                log.warn("Could not refresh the JWT due to exception: {}", exception.getMessage());
            }
        }
    }

    /**
     * Method to generate the JWT used to access the Github App APIs. We generate the JWT to be valid for 600 seconds. 
     * Along with the JWT value, the jwtExpiry value is set to the time of 600 sec from now. 
     * @param appId = The id of the Github App to generate the JWT for
     * @param privateKeyPath = The path to the private key of the Github App to generate the JWT for
     * @throws IOException
     * @throws GeneralSecurityException
     */
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

    /**
     * The method to get the private key in an RSA Encoded format. Makes use of org.bouncycastle.util
     * @param privateKeyPath
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
    private RSAPrivateKey getRSAPrivateKey(String privateKeyPath) throws IOException, GeneralSecurityException {
        try (PemReader pemReader = new PemReader(new FileReader(new File(privateKeyPath)))) {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pemReader.readPemObject().getContent());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) keyFactory.generatePrivate(spec);
        }
    }
}
