package com.bvotteler.E3DCConnector;

import com.bvotteler.rscp.util.ByteUtils;
import org.junit.Test;

import static org.junit.Assert.*;

public class E3DCSampleRequestsTest {
	// copied from actual response data
	private static final String testAuthResponse = "e3 dc 00 11 7f 58 00 58 00 00 00 00 d0 29 18 02 08 00 01 00 80 00 03 01 00 0a b2 34 f2 4d 00 00".replaceAll("\\s+", "");
	
	@Test
	public void testAuthenticationFrameCompleteIsTrue() {
		byte[] frame = ByteUtils.hexStringToByteArray(testAuthResponse);
		assertTrue(E3DCSampleRequests.isAuthenticationRequestReplyFrameComplete(frame));
	}

	@Test
	public void testAuthenticationFrameCompleteIsFalse() {
		// replaced first e3 with 00, making this an invalid one
		String broken = testAuthResponse.replace("e3", "00");
		byte[] frame = ByteUtils.hexStringToByteArray(broken);
		assertFalse(E3DCSampleRequests.isAuthenticationRequestReplyFrameComplete(frame));
	}
	
	@Test
	public void testAuthenticationLevelReturnsTen() {
		byte[] frame = ByteUtils.hexStringToByteArray(testAuthResponse);
		short authLevel = E3DCSampleRequests.getAuthenticationLevel(frame);
		assertEquals((short)10, authLevel);
	}
}
