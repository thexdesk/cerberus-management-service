package com.nike.cerberus.endpoints.test;

import com.nike.cerberus.endpoints.AdminStandardEndpoint;
import com.nike.riposte.server.http.RequestInfo;
import com.nike.riposte.server.http.ResponseInfo;
import com.nike.riposte.util.AsyncNettyHelper;
import com.nike.riposte.util.Matcher;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.HttpMethod;

import javax.ws.rs.core.SecurityContext;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

public class TestEndpoint extends AdminStandardEndpoint<Void, Void> {

    public static final String TEST_PATH = "/klsjdgwjklfasmndlwejraldsfkl";

    @Override
    public CompletableFuture<ResponseInfo<Void>> doExecute(final RequestInfo<Void> request,
                                                           final Executor longRunningTaskExecutor,
                                                           final ChannelHandlerContext ctx,
                                                           final SecurityContext securityContext) {
        return CompletableFuture.supplyAsync(
                AsyncNettyHelper.supplierWithTracingAndMdc(() -> doNothing(), ctx),
                longRunningTaskExecutor
        );
    }

    public ResponseInfo<Void> doNothing() {
        try{
            Thread.sleep(130*1000);
        } catch (Exception e){
            throw new RuntimeException(e);
        }
        return ResponseInfo.<Void>newBuilder()
                .withHttpStatusCode(204)
                .build();
    }

    @Override
    public Matcher requestMatcher() {
        return Matcher.match(TEST_PATH, HttpMethod.GET);
    }
}
