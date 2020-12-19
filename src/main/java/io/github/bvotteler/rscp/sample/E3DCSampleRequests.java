package io.github.bvotteler.rscp.sample;

import io.github.bvotteler.rscp.RSCPData;
import io.github.bvotteler.rscp.RSCPFrame;
import io.github.bvotteler.rscp.RSCPTag;
import io.github.bvotteler.rscp.util.ByteUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;


public class E3DCSampleRequests {
    private static final Logger logger = LoggerFactory.getLogger(E3DCSampleRequests.class);

    public static byte[] buildAuthenticationMessage(String user, String password) {
        RSCPData authUser = RSCPData.builder()
                .tag(RSCPTag.TAG_RSCP_AUTHENTICATION_USER)
                .stringValue(user)
                .build();

        RSCPData authPwd = RSCPData.builder()
                .tag(RSCPTag.TAG_RSCP_AUTHENTICATION_PASSWORD)
                .stringValue(password)
                .build();

        RSCPData authContainer = RSCPData.builder()
                .tag(RSCPTag.TAG_RSCP_REQ_AUTHENTICATION)
                .containerValues(Arrays.asList(authUser, authPwd))
                .build();

        RSCPFrame authFrame = RSCPFrame.builder()
                .timestamp(Instant.now())
                .addData(authContainer)
                .build();

        return authFrame.getAsByteArray();
    }

    /**
     * Builds a sample request frame to request E3DC history data, starting from start epoch secs, for a duration of intervalSeconds each, for a number of intervals.
     *
     * @param startEpochSeconds Epoch seconds as start time to request data for.
     * @param intervalSeconds   How many seconds to put in each interval.
     * @param numberOfIntervals How many intervals to request.
     * @return A byte array ready to be encrypted and sent.
     */
    public static byte[] buildSampleRequestFrame(long startEpochSeconds, long intervalSeconds, int numberOfIntervals) {
        // build parameters
        RSCPData reqTimeStart = RSCPData.builder()
                .tag(RSCPTag.TAG_DB_REQ_HISTORY_TIME_START)
                .timestampValue(Instant.ofEpochSecond(startEpochSeconds))
                .build();

        RSCPData reqInterval = RSCPData.builder()
                .tag(RSCPTag.TAG_DB_REQ_HISTORY_TIME_INTERVAL)
                .timestampValue(Duration.ofSeconds(intervalSeconds))
                .build();

        RSCPData reqTimeSpan = RSCPData.builder()
                .tag(RSCPTag.TAG_DB_REQ_HISTORY_TIME_SPAN)
                .timestampValue(Duration.ofSeconds(intervalSeconds * numberOfIntervals))
                .build();

        // build request starting with a container
        RSCPData reqContainer = RSCPData.builder()
                .tag(RSCPTag.TAG_DB_REQ_HISTORY_DATA_DAY)
                .containerValues(Arrays.asList(reqTimeStart, reqInterval, reqTimeSpan))
                .build();

        // build frame and append the request container
        RSCPFrame reqFrame = RSCPFrame.builder()
                .timestamp(Instant.now())
                .addData(reqContainer)
                .build();

        return reqFrame.getAsByteArray();
    }

    public static boolean isAuthenticationRequestReplyFrameComplete(byte[] frame) {
        // need a frame object
        if (frame == null) {
            return false;
        }

        // minimum size 27
        if (frame.length < 27) {
            return false;
        }

        // check byte array starts with "E3 DC" bytes
        if (frame[0] != (byte) 0xe3 || frame[1] != (byte) 0xdc) {
            return false;
        }

        // find location of reply tag "01 00 80 00 03"
        byte[] pattern = ByteUtils.hexStringToByteArray("0100800003");
        int positionStart = ByteUtils.arrayPosition(frame, pattern);

        if (positionStart < 0) {
            return false;
        }

        return true;
    }

    public static short getAuthenticationLevel(byte[] frame) {
        // we've got a reply from an authentication request
        // check the authentication level and return that
        // return -1 if unable to retrieve authentication level

        // we need a valid frame
        if (!isAuthenticationRequestReplyFrameComplete(frame))
            return -1;

        // find the position of the tag
        int tagPosition = ByteUtils.arrayPosition(frame, ByteUtils.hexStringToByteArray("0100800003"));

        // get length (index of byte: tagPosition + 4 (tag) + 1 (type) + 2 (length))
        byte[] authLevelInBytes = new byte[Short.BYTES]; // initialized with 00
        authLevelInBytes[Short.BYTES - 1] = frame[tagPosition + 4 + 1 + 2]; // set last byte (big endian style)
        return ByteUtils.bytesToShort(authLevelInBytes);
    }
}
