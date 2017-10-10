package com.nike.cerberus.service;

import com.google.common.collect.ImmutableList;
import com.google.common.primitives.Bytes;
import com.nike.backstopper.exception.ApiException;
import com.nike.cerberus.domain.DashboardResourceFile;
import com.nike.cerberus.error.DefaultApiError;
import com.nike.cerberus.util.DashboardResourceFileFactory;
import com.nike.riposte.server.http.RequestInfo;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Named;
import java.nio.charset.Charset;
import java.util.Map;

public class DashboardAssetService {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private static final String REQUEST_PATH_FILENAME_SEPARATOR = "dashboard/";

    private static final String VERSION_RESPONSE_FORMAT = "{\"version\": \"%s\"}";

    private static final String DEFAULT_DASHBOARD_ASSET_FILE_NAME = "index.html";

    private static final String VERSION_FILE_NAME = "version";

    private final Map<String, DashboardResourceFile> dashboardAssetMap;

    private final String cmsVersion;

    @Inject
    public DashboardAssetService(@Named("dashboardAssetMap") Map<String, DashboardResourceFile> dashboardAssetMap,
                                 @Named("service.version") String cmsVersion) {
        this.dashboardAssetMap = dashboardAssetMap;
        this.cmsVersion = cmsVersion;
    }

    public DashboardResourceFile getFileContents(RequestInfo<Void> request) {
        String filename = StringUtils.substringAfterLast(request.getPath(), REQUEST_PATH_FILENAME_SEPARATOR);
        logger.debug("Filename (before empty check) is: '{}'", filename);
        filename = filename.isEmpty() ? DEFAULT_DASHBOARD_ASSET_FILE_NAME : filename;
        logger.debug("Filename (after empty check) is: '{}'", filename);
        logger.debug("Map keys: {}", dashboardAssetMap.keySet());

        if (filename.equals(VERSION_FILE_NAME)) {
            logger.debug("Getting version file");
            return getDashboardVersionContents();
        } else if (dashboardAssetMap.containsKey(filename)) {
            logger.debug("Map contains key");
            return dashboardAssetMap.get(filename);
        } else {
            throw ApiException.newBuilder()
                    .withApiErrors(DefaultApiError.FAILED_TO_READ_DASHBOARD_ASSET_CONTENT)
                    .withExceptionMessage("Could not load dashboard asset: " + filename)
                    .build();
        }

    }

    public DashboardResourceFile getDashboardVersionContents() {
        String versionJson = String.format(VERSION_RESPONSE_FORMAT, cmsVersion);
        byte[] versionJsonInBytes = versionJson.getBytes(Charset.defaultCharset());

        return new DashboardResourceFile(
                VERSION_FILE_NAME,
                VERSION_FILE_NAME,
                DashboardResourceFileFactory.FILE_EXT_TO_MIME_TYPE_MAP.get("json"),
                ImmutableList.<Byte>builder()
                        .addAll(Bytes.asList(versionJsonInBytes))
                        .build());
    }
}
