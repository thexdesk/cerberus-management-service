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
import com.nike.cerberus.validation.group.Updatable;
import com.nike.riposte.server.http.RequestInfo;
import com.nike.riposte.server.http.ResponseInfo;
import com.nike.riposte.util.AsyncNettyHelper;
import com.nike.riposte.util.Matcher;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.DefaultHttpHeaders;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponseStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.ws.rs.core.SecurityContext;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

import static com.nike.cerberus.CerberusHttpHeaders.HEADER_X_REFRESH_TOKEN;

/**
 * Endpoint for updating a safe deposit box.
 */
@RiposteEndpoint
public class UpdateSafeDepositBoxV2 extends AuditableEventEndpoint<SafeDepositBoxV2, SafeDepositBoxV2> {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final SafeDepositBoxService safeDepositBoxService;

    @Inject
    public UpdateSafeDepositBoxV2(final SafeDepositBoxService safeDepositBoxService) {
        this.safeDepositBoxService = safeDepositBoxService;
    }

    @Override
    public CompletableFuture<ResponseInfo<SafeDepositBoxV2>> doExecute(RequestInfo<SafeDepositBoxV2> request,
                                                                     Executor longRunningTaskExecutor,
                                                                     ChannelHandlerContext ctx) {
        return CompletableFuture.supplyAsync(
                AsyncNettyHelper.supplierWithTracingAndMdc(() -> updateSafeDepositBox(request), ctx),
                longRunningTaskExecutor
        );
    }

    private ResponseInfo<SafeDepositBoxV2> updateSafeDepositBox(final RequestInfo<SafeDepositBoxV2> request) {
        final Optional<SecurityContext> securityContext =
                CmsRequestSecurityValidator.getSecurityContextForRequest(request);

        if (securityContext.isPresent()) {
            final CerberusPrincipal authPrincipal = (CerberusPrincipal) securityContext.get().getUserPrincipal();

            SafeDepositBoxV2 safeDepositBoxV2 = safeDepositBoxService.updateSafeDepositBoxV2(request.getContent(),
                    authPrincipal,
                    request.getPathParam("id"));
            return ResponseInfo.newBuilder(safeDepositBoxV2)
                    .withHeaders(new DefaultHttpHeaders().set(HEADER_X_REFRESH_TOKEN, Boolean.FALSE.toString()))
                    .withHttpStatusCode(HttpResponseStatus.OK.code())
                    .build();
        }

        throw ApiException.newBuilder().withApiErrors(DefaultApiError.AUTH_BAD_CREDENTIALS).build();
    }

    @Override
    public Matcher requestMatcher() {
        return Matcher.match("/v2/safe-deposit-box/{id}", HttpMethod.PUT);
    }

    @Override
    public Class[] validationGroups(RequestInfo<?> request) {
        return new Class[] {
            Updatable.class
        };
    }

    @Override
    protected CustomizableAuditData getCustomizableAuditData(RequestInfo<SafeDepositBoxV2> request) {
        String sdbId = request.getPathParam("id");
        Optional<String> sdbNameOptional = safeDepositBoxService.getSafeDepositBoxNameById(sdbId);
        String sdbName = sdbNameOptional.orElseGet(() -> String.format("(Failed to lookup name from id: %s)", sdbId));
        return  new CustomizableAuditData()
                .setDescription(String.format("Update details for SDB with name: '%s' and id: '%s'", sdbName, sdbId))
                .setSdbNameSlug(sdbNameOptional.map(Slugger::toSlug).orElse("_unknown_"));
    }
}
