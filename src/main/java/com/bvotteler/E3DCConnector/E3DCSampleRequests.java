package com.bvotteler.E3DCConnector;

import com.bvotteler.rscp.RSCPData;
import com.bvotteler.rscp.RSCPDataType;
import com.bvotteler.rscp.RSCPFrame;
import com.bvotteler.rscp.RSCPTag;
import com.bvotteler.rscp.util.ByteUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collections;


public class E3DCSampleRequests {
    private static Logger logger = LoggerFactory.getLogger(E3DCSampleRequests.class);

    public static byte[] buildAuthenticationMessage(String user, String password) {
        RSCPData authUser = new RSCPData();
        authUser.setDataTag(RSCPTag.TAG_RSCP_AUTHENTICATION_USER);
        authUser.setData(user);
        RSCPData authPwd = new RSCPData();
        authPwd.setDataTag(RSCPTag.TAG_RSCP_AUTHENTICATION_PASSWORD);
        authPwd.setData(password);

        RSCPData authContainer = new RSCPData();
        authContainer.setDataTag(RSCPTag.TAG_RSCP_REQ_AUTHENTICATION);
        authContainer.setData(authUser);
        authContainer.appendData(authPwd);

        RSCPFrame authFrame = new RSCPFrame();
        authFrame.appendData(authContainer);
        return authFrame.getAsBytes(true);
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
        // build request starting with a container
        RSCPData reqContainer = new RSCPData();
        reqContainer.setDataTag(RSCPTag.TAG_DB_REQ_HISTORY_DATA_DAY);
        reqContainer.setDataType(RSCPDataType.CONTAINER);

        // build parameters
        RSCPData reqTimeStart = new RSCPData();
        reqTimeStart.setDataTag(RSCPTag.TAG_DB_REQ_HISTORY_TIME_START);
        reqTimeStart.setTimeStampData(startEpochSeconds, 0);

        RSCPData reqInterval = new RSCPData();
        reqInterval.setDataTag(RSCPTag.TAG_DB_REQ_HISTORY_TIME_INTERVAL);
        reqInterval.setTimeStampData(intervalSeconds, 0);

        RSCPData reqTimeSpan = new RSCPData();
        reqTimeSpan.setDataTag(RSCPTag.TAG_DB_REQ_HISTORY_TIME_SPAN);
        reqTimeSpan.setTimeStampData(intervalSeconds * numberOfIntervals, 0);

        // put request params into the container
        reqContainer.appendData(Arrays.asList(reqTimeStart, reqInterval, reqTimeSpan));

        // build frame and append the request container
        RSCPFrame reqFrame = new RSCPFrame();
        reqFrame.appendData(reqContainer);
        // get as bytes with refreshed timestamp set to now
        return reqFrame.getAsBytes(true);
    }

    public static boolean isDatabaseRequestReplyFrameComplete(byte[] frame) {
        // this is a heuristic until I know how to check the header properly.
        // for now: just see if there is a row in the data dump somewhere

        // need a frame object
        if (frame == null) {
            return false;
        }

        // minimum size 32 (header) + 143 (row of data)
        if (frame.length < 32 + 143) {
            return false;
        }

        // must find at least one instance of "20 00 80 06 0e" (indicates next row of data)
        byte[] pattern = ByteUtils.hexStringToByteArray("200080060e");
        if (-1 == Collections.indexOfSubList(Arrays.asList(ArrayUtils.toObject(frame)), Arrays.asList(ArrayUtils.toObject(pattern)))) {
            return false;
        }

        return true;
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
        if (false == isAuthenticationRequestReplyFrameComplete(frame))
            return -1;

        // find the position of the tag
        int tagPosition = ByteUtils.arrayPosition(frame, ByteUtils.hexStringToByteArray("0100800003"));

        // get length (index of byte: tagPosition + 4 (tag) + 1 (type) + 2 (length))
        byte[] authLevelInBytes = new byte[Short.BYTES]; // initialized with 00
        authLevelInBytes[Short.BYTES - 1] = frame[tagPosition + 4 + 1 + 2]; // set last byte (big endian style)
        return ByteUtils.bytesToShort(authLevelInBytes);
    }
}
