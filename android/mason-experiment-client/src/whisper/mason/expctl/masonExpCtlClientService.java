package whisper.mason.expctl;

import java.io.FileWriter;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.Timer;
import java.util.TimerTask;
import java.util.UUID;

import android.app.Service;
import android.content.Intent;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Handler;
import android.os.IBinder;
import android.util.Log;

public class masonExpCtlClientService extends Service {
	public static final String TAG = "masonExpCtlClientService";
	
	private static final long REPLYTIMEOUT = 1000; // (controller's) init message's reply time out, in milliseconds
	private static final long TRIALSPAN = 2 * 60 * 1000; //(controller's) the sleep time between trials, in milliseconds
	private static final int MAXPAR = 20; //the maximum number of participants 
	
	private static final long CTLTIMEOUT = REPLYTIMEOUT*MAXPAR; // control message's time out, in milliseconds
													// This is the expected longest time that every participant
													// gets the control message. 
													// CTLTIMEOUT 
													// = the number of participants * REPLYTIMEOUT.
	// the amount of time the initiator waits before initiation, in milliseconds
	private static final long INIWAITTIME = CTLTIMEOUT; 
	// the duration of the log for one mason test, in milliseconds
	private static final long LOGSPAN = CTLTIMEOUT + INIWAITTIME+ TRIALSPAN;
	//private static final long LOGSPAN = 500;
	
	private InetAddress group;   //multicast group address
    private int port;            //port number
    private MulticastSocket ms;  //multicast socket
    
    private Handler myHandler;
    
    // the timer for stopping logger service in the future
    private Timer stopLogTimer;
  //the nearest time that is scheduled for stopping the logger
    private long nearestStopLogTime;
    
    //The signal to stop the background working thread
    private Boolean stopThread;
	
    //get the ip address of wifi card
    public String intToIp(int i) {

    	return (i & 0xFF ) + "." +
         ((i >> 8 ) & 0xFF) + "." +
         ((i >> 16 ) & 0xFF) + "." +
         ( (i >> 24 )& 0xFF) ;

 	}
    
    private String getWifiIp(){
    	WifiManager wifiManager = (WifiManager) getSystemService(WIFI_SERVICE);
    	WifiInfo wifiInfo = wifiManager.getConnectionInfo();
    	int ipAddress = wifiInfo.getIpAddress();
    	String ip = intToIp(ipAddress);
    	
    	Log.e(TAG,"MasonExpCtlClient: current IP address"+ip);
    	
    	return ip;
    }
    
    //open a multi-cast socket and join the corresponding group
    private int initializeNetwork(){
    	
        //get group address
        try{
        		group = InetAddress.getByName("224.0.0.111");
        }
        catch(UnknownHostException e1){
        	Log.e(TAG,"MasonExpCtl: unknown host");
        	return -1;
        }
        
        //get port number
        port = 7128;
        
        //bind to socket
        try{
        	InetAddress deviceAddr = InetAddress.getByName(getWifiIp());
            NetworkInterface iface = NetworkInterface.getByInetAddress(deviceAddr);
            
        	ms = new MulticastSocket(port);
        	ms.setNetworkInterface(iface);
        	ms.setInterface(deviceAddr);
        
        	ms.joinGroup(group);
        }catch(Exception el){
        	Log.e(TAG,"MasonExpCtlClient: cannot bind to socket"
        			+ "\nError: " + el.getMessage());
        	return -1;
        }
        
        return 1;
    }
	
	@Override
	public void onCreate() {
		super.onCreate();
		
		myHandler = new Handler();
	    stopLogTimer = null;
	    nearestStopLogTime = 0;
	    stopThread = false;
	    
		//start background thread
		Thread thread = new Thread(new doTheJob());
		thread.start();
	    
	}
	
	private Runnable servFin = new Runnable(){
		public void run(){
			stopSelf();
		}
	};
	
	// timer task that stop the logger service
	private class stopLogger extends TimerTask{
		
		public void run(){
			Intent intentCrt = new Intent("whisper.mason.expctl.accLoggerService");
			masonExpCtlClientService.this.stopService(intentCrt);
		}
	}
	
	//Schedule the logger to start and stop when new control packet is received
	private void maniLogger(){
		Intent intentCrt = new Intent("whisper.mason.expctl.accLoggerService");
		masonExpCtlClientService.this.startService(intentCrt);
		if(System.currentTimeMillis() < nearestStopLogTime){
			//cancel the previous timer
			stopLogTimer.cancel();
			//Start new timer
			stopLogTimer = new Timer();
		}
		if(nearestStopLogTime==0){
			//Start new timer
			stopLogTimer = new Timer();
		}
		stopLogTimer.schedule(new stopLogger(), LOGSPAN);
		nearestStopLogTime = System.currentTimeMillis() + LOGSPAN;
	}
	
	//The processing thread
	private class doTheJob implements Runnable{
		
		public void run(){
			
			//open a multi-cast socket and join the corresponding group
		    if(initializeNetwork()==-1){
		    	myHandler.post(servFin);
		    	return;
		    }
	    				
			byte[] sendBuffer = new byte[16];
	    	byte[] recvBuffer = new byte[16];
	    	
	    	Log.e(TAG,"Start the service!\n");
	    	
	    	int helloTimeOut = (int) (TRIALSPAN/2);
	    	
	    	// receive control packet in a loop
	    	while(stopThread==false){
				DatagramPacket recvPacket = new DatagramPacket(recvBuffer, recvBuffer.length );
	        	
				try {
	    			// Set the timeout for resetting numids to 1
					// The value is half the span of one trial
	    			ms.setSoTimeout(helloTimeOut);
					//ms.setSoTimeout(0);
	    		} catch (SocketException el) {
	    			System.err.println("MasonExpCtlClient: cannot set socket timeout"
	    					+ "\nError: " + el.getMessage());
	    			myHandler.post(servFin);
	    			return;
	    		}
				
				Log.e(TAG,"Waiting on hello packet!\n");
	        	try {
					ms.receive(recvPacket);
				}
	        	catch(SocketTimeoutException el){
					
	        		Log.e(TAG,"Hello packet timeout. Rewrite the Sybil multiplier to 1.");
					
	        		//Rewrite numids to 1
	        		try {
	            		FileWriter out = new FileWriter("/sys/module/mason/parameters/numids");
	            		out.write(Integer.toString(1));
	            		out.flush();
	            		out.close();
					} catch (IOException ell) {
						Log.e(TAG,"MasonExpCtlClient: cannot write to mason config file"
		    					+ "\nError: " + ell.getMessage());
						myHandler.post(servFin);
						return;
					}
					
					// Reset the timeout for hello to infinite
					helloTimeOut = 0;
					
					continue;
				}
	        	catch (IOException el) {
					Log.e(TAG,"MasonExpCtlClient: cannot receive hello packet"
		        			+ "\nError: " + el.getMessage());
					myHandler.post(servFin);
					return;
				}
	        	
	        	Log.e(TAG,"Received a packet!\n");
	        	datagram recvObj = datagram.byteArrayToData(recvBuffer);
	        	//parse the message
	        	byte packetID = recvObj.PacketID;
	        	//discard the packet if it is not a hello
	        	if(packetID != datagram.PIDHELLO) continue;
	        	//create reply packet
	        	Log.e(TAG,"Received a hello packet!\n");
	        	long uid = UUID.randomUUID().getLeastSignificantBits();
	      	    datagram sendObj = new datagram(uid);
	            sendBuffer = datagram.dataTobyteArray(sendObj);
	            DatagramPacket sendPacket = new DatagramPacket(sendBuffer, sendBuffer.length, group, port);
	        	//send the reply packet
	        	try {
	    			ms.send(sendPacket);
	    		} catch (IOException el) {
	    			Log.e(TAG,"MasonExpCtlClient: cannot send reply packet"
	            			+ "\nError: " + el.getMessage());
	    			myHandler.post(servFin);
	    			return;
	    		}
	    		//wait for ctl
	    		try {
	    			// set the timeout for control packet from the controller 
	    			ms.setSoTimeout((int) CTLTIMEOUT);
	    		} catch (SocketException el) {
	    			System.err.println("MasonExpCtlClient: cannot set socket timeout"
	    					+ "\nError: " + el.getMessage());
	    			myHandler.post(servFin);
	    			return;
	    		}
	    		
	    		while(stopThread==false){    			
	    			try {
	    				Log.e(TAG,"Waiting on control packet!\n");
	    				ms.receive(recvPacket);
	    			} 
	    			catch(SocketTimeoutException el){
	    				Log.e(TAG,"control packet timed out");
	    				break;
	    			}
	    			catch (IOException el) {
	    				Log.e(TAG,"cannot receive control packet!"
	    						+ "\nError: " + el.getMessage());
	    				break;
	    			}
	    			Log.e(TAG,"Received a packet!\n");
	    			recvObj = datagram.byteArrayToData(recvBuffer);
	            	//parse the message
	            	packetID = recvObj.PacketID;
	            	//discard the packet if it is not a ctl
	            	if(packetID != datagram.PIDCTL) continue;
	            	//discard the packet if it is not for me
	            	if(recvObj.SerialNum!=uid) continue;
	            	//handle appropriately according to the control packet
	            	Log.e(TAG,"Received a control packet for me!\n");
	            	//Write to the numids file
	            	try {
	            		FileWriter out = new FileWriter("/sys/module/mason/parameters/numids");
	            		if(recvObj.isAtt==1){
	            			out.write(Integer.toString(recvObj.sybNum));
	            			Log.e(TAG,"I am assigned an attacker with "+recvObj.sybNum+"!\n");
	            		}else{
	            			out.write(Integer.toString(1));
	            			Log.e(TAG,"I am assigned a conformer!\n");
	            		}
	            		out.flush();
	            		out.close();
					} catch (IOException el) {
						Log.e(TAG,"MasonExpCtlClient: cannot write to mason config file"
		    					+ "\nError: " + el.getMessage());
						myHandler.post(servFin);
						return;
					}
					
					//Start logger and schedule timer to stop log service
					maniLogger();

					//Schedule the initiation of Mason if necessary
            		if(recvObj.isAtt==2){
            		
            			Log.e(TAG,"I am assigned an initiator!\n");
            			
            			// Sleep for the control setup to finish.
            			try {
							Thread.sleep(INIWAITTIME);
						} catch (InterruptedException el) {
							Log.e(TAG,"MasonExpCtlClient: initiator cannot " +
									"sleep enough time for control setup to finish."
			    					+ "\nError: " + el.getMessage());
							myHandler.post(servFin);
							return;
						}
						
						// Start the mason test
						try {
							FileWriter out = new FileWriter("/proc/net/mason_initiate");
		            		out.write("tiwlan0");
		            		out.flush();
		            		out.close();
				            
						} catch (IOException el) {
							Log.e(TAG,"MasonExpCtlClient: initiator cannot " +
									"write to proc file to start the Mason test."
			    					+ "\nError: " + el.getMessage());
							myHandler.post(servFin);
							return;
						}
						
						Log.e(TAG,"MasonExpCtlClient: Initiator start the Mason test!");
            		}
            		
					break;
	    		}
	    		
	    		helloTimeOut = (int) (TRIALSPAN/2);
			}
			
		}
	}
	
	public void onStart(Intent intent, int startId){
		super.onStart(intent, startId);
	
	}

	@Override
	public void onDestroy() {
		
		//kill the background working thread
		stopThread = true;
		
		//Cancel any pending stopLog task
		if(nearestStopLogTime!=0){
			stopLogTimer.cancel();
		}
		//Stop the log service
		Intent intentCrt = new Intent("whisper.mason.expctl.accLoggerService");
		masonExpCtlClientService.this.stopService(intentCrt);
		
		super.onDestroy();
	}


	@Override
	public IBinder onBind(Intent intent) {
		return null;
	}

}
