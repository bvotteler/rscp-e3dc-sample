package io.github.bvotteler.rscp.sample.Utility;

import io.github.bvotteler.rscp.RSCPData;
import io.github.bvotteler.rscp.RSCPDataType;
import io.github.bvotteler.rscp.RSCPFrame;
import io.github.bvotteler.rscp.util.ByteUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;

public class FrameLoggerHelper {
    private static final Logger logger = LoggerFactory.getLogger(FrameLoggerHelper.class);
    private static final DateTimeFormatter isoFormatter = DateTimeFormatter.ISO_LOCAL_DATE_TIME.withZone(ZoneId.from(ZoneOffset.UTC));
    private static final String framePattern = "Frame with timestamp: %s ; data follows below";
    private static final String dataPattern = "Data with Tag: %s; Type: %s ; %s";

    public static void logFrame(RSCPFrame frame) {
        if (frame == null) {
            logger.error("Frame is null, nothing logged!");
            return;
        }

        Instant timestamp = frame.getTimestamp();

        logger.info(String.format(framePattern, isoFormatter.format(timestamp)));

        List<RSCPData> dataList = frame.getData();
        for (RSCPData data : dataList) {
            logData(data, 1);
        }
    }

    private static void logData(RSCPData data, int indentation) {
        String value;
        if (data.getDataType() == RSCPDataType.CONTAINER) {
            value = "contained data follows below";
        } else {
            value = data.getValueAsString()
                    .map(stringValue -> "Value (as string): " + stringValue)
                    .orElseGet(() -> {
                        byte[] rawValue = data.getValueAsByteArray();
                        return "Raw value (hex): " + ByteUtils.byteArrayToHexString(rawValue);
                    });
        }

        StringBuilder sb = new StringBuilder();
        sb.append(StringUtils.leftPad("", indentation, "-")) // prepend '-' character times the indentation
                .append(" ")
                .append(String.format(dataPattern, data.getDataTag().name(), data.getDataType().name(), value));

        logger.info(sb.toString());

        if (data.getDataType() == RSCPDataType.CONTAINER) {
            // log data inside
            List<RSCPData> containedDataList = data.getContainerData();
            for (RSCPData containedData : containedDataList) {
                logData(containedData, indentation + 1);
            }
        }
    }
}
