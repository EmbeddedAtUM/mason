/*Yue Liu,03/29/11
 * Mason protocol experiment controller for laptop*/

package masonexp;

import java.io.*;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Vector;

public class controller {

	private static final int REPLYTIMEOUT = 1000; // init message's reply time out, in milliseconds
	private static final long TRIALSPAN = 2 * 60 * 1000; //the sleep time between trials, in milliseconds
	private static final int MAXPAR = 20; //the maximum number of participants 

	private InetAddress group; // multicast group address
	private int port; // port number
	private MulticastSocket ms; // multicast socket
	private long period = 0; // period for initiating sets of Mason tests in milliseconds
	private Vector<trialInfo> trialinfos;

	// the class that keeps the information of each trial
	private class trialInfo {
		public int attNum;
		public int sybNum;
	}

	// open a multi-cast socket and join the corresponding group
	private int initializeNetwork() {

		// get group address
		try {
			group = InetAddress.getByName("224.0.0.111");
		} catch (UnknownHostException e1) {
			System.err.println("MasonExpCtl: unknown host");
			return -1;
		}

		// get port number
		port = 7128;

		// bind to socket
		try {
			InetAddress deviceAddr = InetAddress.getByName("10.0.0.2");
			NetworkInterface iface = NetworkInterface
					.getByInetAddress(deviceAddr);

			ms = new MulticastSocket(port);
			ms.setNetworkInterface(iface);
			ms.setInterface(deviceAddr);

			ms.joinGroup(group);
		} catch (Exception el) {
			System.err.println("MasonExpCtl: cannot bind to socket"
					+ "\nError: " + el.getMessage());
			return -1;
		}

		return 1;
	}

	private int readinConfig(String fileName) {

		// interpret the config file
		// Two formats:
		// period ***(in minutes)
		//        The period of initiating a set of Mason tests.
		// attacker# sybil_multiplier

		// Open the config file and process line by line
		FileInputStream fstream = null;
		try {
			fstream = new FileInputStream(fileName);
		} catch (FileNotFoundException el) {
			System.err.println("MasonExpCtl: cannot find config file"
					+ "\nError: " + el.getMessage());
			return -1;
		}
		DataInputStream in = new DataInputStream(fstream);
		BufferedReader br = new BufferedReader(new InputStreamReader(in));
		String strLine;

		// read in the config file
		String[] tokens;
		int lineIndex = 1;
		trialinfos = new Vector<trialInfo>();
		while (true) {
			try {
				strLine = br.readLine();
			} catch (IOException el) {
				System.err.println("MasonExpCtl: cannot read config file"
						+ "\nError: " + el.getMessage());
				return -1;
			}
			if (strLine == null)
				break;
			tokens = strLine.split("\\s");

			if (lineIndex == 1) {
				// read the first line and decide whether to periodically
				// initiates or initiates
				// under user instruction
				if (tokens[0].compareToIgnoreCase("period") == 0) {
					period = Integer.valueOf(tokens[1]).longValue()*60*1000;
				}
			} else {
				// read in all the trials into a vector of trialInfo
				trialInfo trialCrt = new trialInfo();
				trialCrt.attNum = Integer.valueOf(tokens[0]).intValue();
				trialCrt.sybNum = Integer.valueOf(tokens[1]).intValue();
				trialinfos.add(trialCrt);
			}

			lineIndex++;
		}

		return 1;
	}

	// arrange the roles of a given trial
	private int iniTrial(trialInfo tinfoCrt) {

		int attSofar = 0;
		Map<Long, Byte> attMap = new HashMap<Long, Byte>();
		long serialNumCrt;
		byte isAttCrt;
		int rplyNum = 0;

		byte[] sendBuffer = new byte[16];
		byte[] recvBuffer = new byte[16];

		// create hello packet
		datagram sendObj = new datagram();
		sendBuffer = datagram.dataTobyteArray(sendObj);
		DatagramPacket sendPacket = new DatagramPacket(sendBuffer,
				sendBuffer.length, group, port);
		// send the packet
		try {
			ms.send(sendPacket);
			System.out.println("Send a hello packet!\n");
		} catch (IOException el) {
			System.err.println("MasonExpCtl: cannot send hello packet"
					+ "\nError: " + el.getMessage());
			return -1;
		}

		System.out.println("The current value of rplyNum :"+rplyNum+"!\n");
		
		// receive all the responses from participants
		try {
			ms.setSoTimeout(REPLYTIMEOUT);
		} catch (SocketException el) {
			System.err.println("MasonExpCtl: cannot set socket timeout"
					+ "\nError: " + el.getMessage());
			return -1;
		}
		while (true) {
			
			DatagramPacket recvPacket = new DatagramPacket(recvBuffer,
					recvBuffer.length);
			System.out.println("Waiting on reply packets!\n");
			try {
				ms.receive(recvPacket);
			} catch (IOException e) {
				break;
			}
			System.out.println("Received a packet!\n");
			datagram recvObj = datagram.byteArrayToData(recvBuffer);
			// parse the message
			byte packetID = recvObj.PacketID;
			// discard the packet if it is not a reply
			if (packetID != datagram.PIDREPLY)
				continue;
			rplyNum++;
			System.out.println("Received a reply packet!\n");
			// push the <serialnum,isAtt> pair into the attMap
			serialNumCrt = recvObj.SerialNum;
			if(rplyNum==1){
				// Always let the first replier of Hello to be the initiator
				isAttCrt = 2;
			}else{
				if (attSofar < tinfoCrt.attNum) {
					isAttCrt = 1;
					attSofar++;
				} else {
					isAttCrt = 0;
				}
			}
			attMap.put(new Long(serialNumCrt), new Byte(isAttCrt));
		}

		// Now send out all the control packets
		System.out.println("Reply collection times out. In total "+rplyNum+ "replies!\n");
		System.out.println("Reply collection times out. Now sending all the " +
				"control packets!\n");
		int parNum = 0;
		Iterator it = attMap.entrySet().iterator();
		while (it.hasNext()) {
			Map.Entry m = (Map.Entry) it.next();
			serialNumCrt = (Long) m.getKey();
			isAttCrt = (Byte) m.getValue();

			// create control packet
			sendObj = new datagram(serialNumCrt, isAttCrt, tinfoCrt.sybNum);
			sendBuffer = datagram.dataTobyteArray(sendObj);
			sendPacket = new DatagramPacket(sendBuffer, sendBuffer.length,
					group, port);
			// send the packet
			try {
				ms.send(sendPacket);
			} catch (IOException el) {
				System.err.println("MasonExpCtl: cannot send control packet"
						+ "\nError: " + el.getMessage());
				return -1;
			}
			
			parNum++;

		}

		System.out.println("***Assigned roles to "+parNum+" participants!\n");
		System.out.println("***In total "+attSofar+" attackers!\n");
		
		return 1;

	}

	// periodic initiation
	private int periodicIni() {
		while (true) {

			Enumeration<trialInfo> trialenum = trialinfos.elements();

			while (trialenum.hasMoreElements()) {
				if (iniTrial((trialInfo) trialenum.nextElement()) == -1) {
					return -1;
				}

				// sleep to allow the proceeding of a Masontest
				try {
					System.out.println("Sleep waiting for the current Mason test to finish!\n");
					Thread.sleep(TRIALSPAN);
				} catch (InterruptedException el) {
					System.err
							.println("MasonExpCtl: cannot put thread to sleep!"
									+ "\nError: " + el.getMessage());
					return -1;
				}
			}
			
			System.out.println("***All trials have been finished in this set of mason test!\n");
			
			//sleep to wait for the next set of Mason tests
			try {
				Thread.sleep(period-trialinfos.size()*(TRIALSPAN+REPLYTIMEOUT*MAXPAR));
			} catch (InterruptedException el) {
				System.err.println("MasonExpCtl: cannot put thread to sleep!"
						+ "\nError: " + el.getMessage());
				return -1;
			}
			
		}
	}

	// controlled initiation
	private int ctlIni() {
		Enumeration<trialInfo> trialenum = trialinfos.elements();

		while (trialenum.hasMoreElements()) {

			// get user "go" signal to start a round configuration
			InputStreamReader istream = new InputStreamReader(System.in);
			BufferedReader bufRead = new BufferedReader(istream);
			String inst = "ready";
			//int isGo = inst.compareToIgnoreCase("go");
			while (inst.compareToIgnoreCase("go") != 0) {
				try {
					System.out
							.println("Please Enter \"go\" When You Are Ready");
					inst = bufRead.readLine();
				} catch (IOException el) {
					System.err.println("MasonExpCtl: cannot get keyboard input"
							+ "\nError: " + el.getMessage());
					return -1;
				}
			}

			if (iniTrial((trialInfo) trialenum.nextElement()) == -1) {
				return -1;
			}
		}

		System.out.println("All the specified trials have been finshed!");
		return 1;
	}

	private void doTheJob() {

		// open a multicast socket and join the corresponding group
		if (initializeNetwork() == -1)
			return;
		
		// get the configuration file name from user input
		InputStreamReader istream = new InputStreamReader(System.in);
		BufferedReader bufRead = new BufferedReader(istream);
		String fileName;
		// Debug
		fileName = "/home/yue/Desktop/expTest";
		//try {
		//	System.out.println("Please Enter The Configuration File Name: ");
		//	fileName = bufRead.readLine();
		//} catch (IOException el) {
		//	System.err.println("MasonExpCtl: cannot get keyboard input"
		//			+ "\nError: " + el.getMessage());
		//	return;
		//}

		// read in the configuration file
		if (readinConfig(fileName) == -1) {
			return;
		}

		if (period != 0) {
			if(period < trialinfos.size()*(TRIALSPAN+REPLYTIMEOUT*MAXPAR)){
				System.err.println("MasonExpCtl: the sleep period between sets " +
						"of trials is not long enough to handle the entire set!");
				return;
			}
			// periodic initiation
			periodicIni();
		} else {
			// controlled initiation
			ctlIni();
		}

	}

	public static void main(String args[]) {
		controller controller = new controller();
		controller.doTheJob();
	}

}