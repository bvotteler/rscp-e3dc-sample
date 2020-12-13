package com.bvotteler.E3DCConnector;

import com.bvotteler.E3DCConnector.Utility.AES256Helper;
import com.bvotteler.E3DCConnector.Utility.BouncyAES256Helper;
import com.bvotteler.rscp.RSCPFrame;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.Socket;

public class E3DCConnectorMain {
	private static Logger logger = LoggerFactory.getLogger(E3DCConnectorMain.class);

	public static void main(String[] args) {
		// sample connection details, update to play
		final String address = "192.168.1.42";	// E3DC ip address as string
		final int port = 5033; 					// default for E3DC
		final String aesPwd = "aes password";	// password set on E3DC for AES
		final String user = "web user name";	// typically email address
		final String pwd = "web user password"; // used to log into E3DC portal

		final long tStart = 1607731200000L;		// start time in epoch milliseconds (e.g. Sat, 12 Dec 2020 00:00:00 GMT)
		final long interval = 900; 				// 15 minutes in seconds
		final int numOfIntervals = 1;			// how many data sets

		Socket socket = null;
		try {
			logger.debug("Constructing AES256 encryption/decryption helper...");
			AES256Helper aesHelper = BouncyAES256Helper.createBouncyAES256Helper(aesPwd);

			logger.debug("Open connection to server {}:{} ...", address, port);
			socket = E3DCConnector.openConnection(address, port);
			// appease lamba's insistence on effectively final variables.
			final Socket finalSocket = socket;

			logger.debug("Build authentication frame...");
			byte[] authFrame = E3DCSampleRequests.buildAuthenticationMessage(user, pwd);

			logger.info("Sending authentication frame to server...");
			E3DCConnector.sendFrameToServer(socket, aesHelper::encrypt, authFrame)
					.peek(bytesSent -> logger.debug("Authentication: Sent " + bytesSent + " bytes to server."))
					.flatMap(bytesSent -> E3DCConnector.receiveFrameFromServer(finalSocket, aesHelper::decrypt))
					.peek(decBytesReceived -> logger.debug("Authentication: Received " + decBytesReceived.length + " decrypted bytes from server."))
					// don't really care about the content, ignore it
					.fold(
							exception -> {
								logger.error("Exception while trying to authenticate.", exception);
								return null;
							},
							decBytes -> null
					);

			logger.info("Building request frame....");
			byte[] reqFrame = E3DCSampleRequests.buildSampleRequestFrame(tStart, interval, numOfIntervals);
			RSCPFrame responseFrame = E3DCConnector.sendFrameToServer(socket, aesHelper::encrypt, reqFrame)
					.peek(bytesSent -> logger.debug("Request data: Sent " + bytesSent + " bytes to server."))
					.flatMap(bytesSent -> E3DCConnector.receiveFrameFromServer(finalSocket, aesHelper::decrypt))
					.peek(decryptedBytesReceived -> logger.debug("Request data: Received " + decryptedBytesReceived.length + " decrypted bytes from server."))
					.map(decryptedBytesReceived -> RSCPFrame.of(decryptedBytesReceived))
					.fold(
							ex -> {
								logger.error("Error while trying to get data from server.", ex);
								return null;
							},
							rscpFrame -> rscpFrame
					);

			// Do as you wish with the frame...
			logger.info("Got a frame with {} number of values. (Probably 1 because it will be a container value in this demo).", responseFrame.getData().size());

			logger.info("Closing connection to server...");
			E3DCConnector.silentlyCloseConnection(socket);
		} catch (Exception e) {
			logger.error("Unhandled exception caught.", e);
		} finally {
			if (socket != null && !socket.isClosed()) {
				logger.info("Closing connection to server... ");
				E3DCConnector.silentlyCloseConnection(socket);
			}
		}

		logger.info("Program finished.");
	}
}
