/*
 * Copyright (c) 2017 Nike, Inc.
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
 *
 */

package com.nike.cerberus.endpoints.sdb;

import com.nike.backstopper.exception.ApiException;
import com.nike.cerberus.domain.SafeDepositBoxV2;
import com.nike.cerberus.endpoints.AuditableEventEndpoint;
import com.nike.cerberus.endpoints.CustomizableAuditData;
import com.nike.cerberus.endpoints.RiposteEndpoint;
import com.nike.cerberus.error.DefaultApiError;
import com.nike.cerberus.security.CmsRequestSecurityValidator;
import com.nike.cerberus.security.CerberusPrincipal;
import com.nike.cerberus.service.SafeDepositBoxService;
import com.nike.cerberus.util.Slugger;
import com.nike.riposte.server.http.RequestInfo;
import com.nike.riposte.server.http.ResponseInfo;
import com.nike.riposte.util.AsyncNettyHelper;
import com.nike.riposte.util.Matcher;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.HttpMethod;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.ws.rs.core.SecurityContext;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

/**
 * Extracts the user groups from the security context for the request and attempts to get details about the safe
 * deposit box by its unique id.
 */
@RiposteEndpoint
public class GetSafeDepositBoxV2 extends AuditableEventEndpoint<Void, SafeDepositBoxV2> {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final SafeDepositBoxService safeDepositBoxService;

    @Inject
    public GetSafeDepositBoxV2(final SafeDepositBoxService safeDepositBoxService) {
        this.safeDepositBoxService = safeDepositBoxService;
    }

    @Override
    public CompletableFuture<ResponseInfo<SafeDepositBoxV2>> doExecute(final RequestInfo<Void> request,
                                                                     final Executor longRunningTaskExecutor,
                                                                     final ChannelHandlerContext ctx) {
        return CompletableFuture.supplyAsync(
                AsyncNettyHelper.supplierWithTracingAndMdc(() -> getSafeDepositBox(request), ctx),
                longRunningTaskExecutor
        );
    }

    public ResponseInfo<SafeDepositBoxV2> getSafeDepositBox(final RequestInfo<Void> request) {
        final Optional<SecurityContext> securityContext =
                CmsRequestSecurityValidator.getSecurityContextForRequest(request);

        if (securityContext.isPresent()) {
            final CerberusPrincipal authPrincipal = (CerberusPrincipal) securityContext.get().getUserPrincipal();

            String sdbId = request.getPathParam("id");

            final SafeDepositBoxV2 safeDepositBox =
                    safeDepositBoxService.getSDBAndValidatePrincipalAssociationV2(
                            authPrincipal,
                            sdbId);

            return ResponseInfo.newBuilder(safeDepositBox).build();
        }

        throw ApiException.newBuilder().withApiErrors(DefaultApiError.AUTH_BAD_CREDENTIALS).build();
    }

    @Override
    public Matcher requestMatcher() {
        return Matcher.match("/v2/safe-deposit-box/{id}", HttpMethod.GET);
    }

    @Override
    protected CustomizableAuditData getCustomizableAuditData(RequestInfo<Void> request) {
        String sdbId = request.getPathParam("id");
        Optional<String> sdbNameOptional = safeDepositBoxService.getSafeDepositBoxNameById(sdbId);
        String sdbName = sdbNameOptional.orElse(String.format("(Failed to lookup name from id: %s)", sdbId));
        return  new CustomizableAuditData()
                .setDescription(String.format("Fetch details for SDB with name: '%s' and id: '%s'", sdbName, sdbId))
                .setSdbNameSlug(sdbNameOptional.map(Slugger::toSlug).orElse("_unknown_"));
    }
}
