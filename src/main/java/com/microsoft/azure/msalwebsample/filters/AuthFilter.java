// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package com.microsoft.azure.msalwebsample.filters;

import java.io.IOException;
import java.util.*;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.azure.security.keyvault.keys.models.KeyVaultKey;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.microsoft.aad.msal4j.*;
import com.microsoft.azure.msalwebsample.beans.BasicConfiguration;
import com.microsoft.azure.msalwebsample.beans.KeyVaultConfiguration;
import com.microsoft.azure.msalwebsample.helpers.AuthHelper;
import com.microsoft.azure.msalwebsample.helpers.KeyVaultHelper;
import com.microsoft.azure.msalwebsample.helpers.SessionManagementHelper;
import com.sun.org.slf4j.internal.Logger;
import com.sun.org.slf4j.internal.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Processes incoming requests based on auth status
 */
@Component
public class AuthFilter implements Filter {

    private List<String> excludedUrls = Arrays.asList("/", "/studentmanagement/");
    private static final Logger logger = LoggerFactory.getLogger(AuthFilter.class);

    @Autowired
    AuthHelper authHelper;

    @Autowired
    KeyVaultHelper keyVaultHelper;

    @Autowired
    BasicConfiguration configuration;

    @Autowired
    KeyVaultConfiguration keyVaultConfiguration;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {

        KeyVaultSecret keyVaultSecret = keyVaultHelper.getSecret("test-key");
        logger.error("filter started "+keyVaultSecret.getValue());

        KeyVaultKey keyVaultKey = keyVaultHelper.getKey("app-secret-key");
        logger.error("filter started key : "+keyVaultKey.getKey());

        if (request instanceof HttpServletRequest) {
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            HttpServletResponse httpResponse = (HttpServletResponse) response;
            try {
                String currentUri = httpRequest.getRequestURL().toString();
                String path = httpRequest.getServletPath();
                String queryStr = httpRequest.getQueryString();
                String fullUrl = currentUri + (queryStr != null ? "?" + queryStr : "");

                // exclude home page
                if(excludedUrls.contains(path)){
                    chain.doFilter(request, response);
                    return;
                }

                if(containsAuthenticationCode(httpRequest)){
                    // response should have authentication code, which will be used to acquire access token
                    authHelper.processAuthenticationCodeRedirect(httpRequest, currentUri, fullUrl);

                    chain.doFilter(request, response);
                    return;
                }

                // check if user has a AuthData in the session
                if (!isAuthenticated(httpRequest)) {
                        // not authenticated, redirecting to login.microsoft.com so user can authenticate
                        authHelper.sendAuthRedirect(
                                httpRequest,
                                httpResponse,
                                null,
                                authHelper.getRedirectUriSignIn());
                        return;
                }

                if (isAccessTokenExpired(httpRequest)) {
                    updateAuthDataUsingSilentFlow(httpRequest, httpResponse);
                }
            } catch (MsalException authException) {
                // something went wrong (like expiration or revocation of token)
                // we should invalidate AuthData stored in session and redirect to Authorization server
                SessionManagementHelper.removePrincipalFromSession(httpRequest);
                authHelper.sendAuthRedirect(
                        httpRequest,
                        httpResponse,
                        null,
                        authHelper.getRedirectUriSignIn());
                return;
            } catch (Throwable exc) {
                httpResponse.setStatus(500);
                System.out.println(exc.getMessage());
                request.setAttribute("error", exc.getMessage());
                request.getRequestDispatcher("/error").forward(request, response);
                return;
            }
        }
        chain.doFilter(request, response);
    }

    private boolean containsAuthenticationCode(HttpServletRequest httpRequest) {
        Map<String, String[]> httpParameters = httpRequest.getParameterMap();

        boolean isPostRequest = httpRequest.getMethod().equalsIgnoreCase("POST");
        boolean containsErrorData = httpParameters.containsKey("error");
        boolean containIdToken = httpParameters.containsKey("id_token");
        boolean containsCode = httpParameters.containsKey("code");

        return isPostRequest && containsErrorData || containsCode || containIdToken;
    }

    private boolean isAccessTokenExpired(HttpServletRequest httpRequest) {
        IAuthenticationResult result = SessionManagementHelper.getAuthSessionObject(httpRequest);
        return result.expiresOnDate().before(new Date());
    }

    private boolean isAuthenticated(HttpServletRequest request) {
        return request.getSession().getAttribute(AuthHelper.PRINCIPAL_SESSION_NAME) != null;
    }

    private void updateAuthDataUsingSilentFlow(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
            throws Throwable {
        IAuthenticationResult authResult = authHelper.getAuthResultBySilentFlow(httpRequest, httpResponse);
        SessionManagementHelper.setSessionPrincipal(httpRequest, authResult);
    }
}
