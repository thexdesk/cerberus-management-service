/*
 * Copyright (c) 2016 Nike, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.nike.cerberus.endpoints.authentication;

import com.nike.backstopper.exception.ApiException;
import com.nike.cerberus.auth.connector.AuthResponse;
import com.nike.cerberus.domain.UserCredentials;
import com.nike.cerberus.endpoints.RiposteEndpoint;
import com.nike.cerberus.error.DefaultApiError;
import com.nike.cerberus.service.AuthenticationService;
import com.nike.cerberus.service.EventProcessorService;
import com.nike.riposte.server.http.RequestInfo;
import com.nike.riposte.server.http.ResponseInfo;
import com.nike.riposte.server.http.StandardEndpoint;
import com.nike.riposte.util.AsyncNettyHelper;
import com.nike.riposte.util.Matcher;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.HttpMethod;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.ArrayUtils;

import javax.inject.Inject;
import javax.ws.rs.core.HttpHeaders;
import java.nio.charset.Charset;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

import static com.nike.cerberus.endpoints.AuditableEventEndpoint.auditableEvent;

/**
 * Authentication endpoint for user credentials.  If valid, a client token will be returned.
 */
@RiposteEndpoint
public class AuthenticateUser extends StandardEndpoint<Void, AuthResponse> {

    private final AuthenticationService authenticationService;
    private final EventProcessorService eventProcessorService;

    @Inject
    public AuthenticateUser(AuthenticationService authenticationService,
                            EventProcessorService eventProcessorService) {

        this.authenticationService = authenticationService;
        this.eventProcessorService = eventProcessorService;
    }

    @Override
    public CompletableFuture<ResponseInfo<AuthResponse>> execute(final RequestInfo<Void> request,
                                                                 final Executor longRunningTaskExecutor,
                                                                 final ChannelHandlerContext ctx) {
        return CompletableFuture.supplyAsync(
                AsyncNettyHelper.supplierWithTracingAndMdc(() -> authenticate(request), ctx),
                longRunningTaskExecutor
        );
    }

    private ResponseInfo<AuthResponse> authenticate(RequestInfo<Void> request) {
        final UserCredentials credentials = extractCredentials(request.getHeaders().get(HttpHeaders.AUTHORIZATION));

        AuthResponse authResponse = null;
        try {
            authResponse = authenticationService.authenticate(credentials);
        } catch (ApiException e) {
            eventProcessorService.ingestEvent(auditableEvent(credentials.getUsername(), request, getClass().getSimpleName())
                    .withAction("failed to authenticate")
                    .withSuccess(false)
                    .build()
            );
            throw e;
        }

        eventProcessorService.ingestEvent(auditableEvent(credentials.getUsername(), request, getClass().getSimpleName())
                .withAction("authenticated")
                .build()
        );

        return ResponseInfo.newBuilder(authResponse).build();
    }

    @Override
    public Matcher requestMatcher() {
        return Matcher.match("/v2/auth/user", HttpMethod.GET);
    }

    /**
     * Extracts credentials from the Authorization header.  Assumes its Basic auth.
     *
     * @param authorizationHeader Value from the authorization header
     * @return User credentials that were extracted
     */
    public UserCredentials extractCredentials(final String authorizationHeader) {
        final String authType = "Basic";
        if (authorizationHeader != null && authorizationHeader.startsWith(authType)) {
            final String encodedCredentials = authorizationHeader.substring(authType.length()).trim();
            final byte[] decodedCredentials = Base64.decodeBase64(encodedCredentials);

            if (ArrayUtils.isNotEmpty(decodedCredentials)) {
                final String[] credentials = new String(decodedCredentials, Charset.defaultCharset()).split(":", 2);

                if (credentials.length == 2) {
                    return new UserCredentials(credentials[0], credentials[1].getBytes(Charset.defaultCharset()));
                }
            }
        }

        throw ApiException.newBuilder().withApiErrors(DefaultApiError.AUTH_BAD_CREDENTIALS).build();
    }
}
