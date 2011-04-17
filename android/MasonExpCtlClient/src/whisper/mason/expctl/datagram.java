package whisper.mason.expctl;

public class datagram {

    //packet ID 
	public static final byte PIDHELLO = 0;     //hello packet
	public static final byte PIDREPLY = 1;     //hello packet
	public static final byte PIDCTL = 2; //control packet

	//packet ID for masonexp
	public byte PacketID;
	public long SerialNum;
	public byte isAtt;	// 0: conforming
						// 1: attacker
						// 2: initiator
	public int sybNum;

	public datagram(){
		this.PacketID = PIDHELLO;
	}
	
	public datagram(long serialNum){
		this.PacketID = PIDREPLY;
		this.SerialNum = serialNum;
	}

	public datagram(long serialNum, byte isAtt, int sybNum){
		this.PacketID = PIDCTL;
		this.SerialNum = serialNum;
		this.isAtt = isAtt;
		this.sybNum = sybNum;
	}

	//write int to byte array
	public static byte[] intToByteArray(int data){
		return new byte[] {
                (byte)(data >>> 24),
                (byte)(data >>> 16),
                (byte)(data >>> 8),
                (byte)data};
	}

	//read byte array to int
	public static int byteArrayToInt(byte[] b){
		return (b[0] << 24)
        + ((b[1] & 0xFF) << 16)
        + ((b[2] & 0xFF) << 8)
        + (b[3] & 0xFF);
	}
	
	//write long to byte array
	public static byte[] longToByteArray(long data){
		return new byte[] {
				(byte)(data >>> 56),
                (byte)(data >>> 48),
                (byte)(data >>> 40),
                (byte)(data >>> 32),
                (byte)(data >>> 24),
                (byte)(data >>> 16),
                (byte)(data >>> 8),
                (byte)data};
	}
	
	//read byte array to long
	public static long byteArrayToLong(byte[] b){
		//return (b[0] << 56)
        //+ ((b[1] & 0xFF) << 48)
        //+ ((b[2] & 0xFF) << 40)
        //+ ((b[3] & 0xFF) << 32)
		//+ ((b[4] & 0xFF) << 24)
        //+ ((b[5] & 0xFF) << 16)
        //+ ((b[6] & 0xFF) << 8)
        //+ (b[7] & 0xFF);
		
		long value = 0;
		for (int i = 0; i < b.length; i++)
		{
		   value = (value << 8) + (b[i] & 0xff);
		}

		return value;
	}

	//write a datagram obj to byte[] 
	//to form datagram packet
	public static byte[] dataTobyteArray(datagram Dobj){
		 byte[] result = new byte[16];
		 
		 result[0] = Dobj.PacketID;
		 
		 switch(Dobj.PacketID){
		 case PIDHELLO: break;
		 case PIDREPLY:
			 byte[] serialnum1 = new byte[8];
			 serialnum1 = longToByteArray(Dobj.SerialNum);
			 for(int i=0;i<8;i++){
				 result[1+i] = serialnum1[i];
			 }
			 break;
		 case PIDCTL:
			 byte[] serialnum2 = new byte[8];
			 serialnum2 = longToByteArray(Dobj.SerialNum);
			 for(int i=0;i<8;i++){
				 result[1+i] = serialnum2[i];
			 }
			 
			 result[9] = Dobj.isAtt;
			 
			 byte[] sybnum = new byte[4];
			 sybnum = intToByteArray(Dobj.sybNum);
			 for(int i=0;i<4;i++){
				 result[10+i] = sybnum[i];
			 }
			 break;
		 }
		 
		 return result;
	}

	//read byte array into a datagram obj
	public static datagram byteArrayToData(byte[] data){
		 int i;
		 datagram Dobj = null;
		 
		 byte packetId = data[0];
		 
		 switch(packetId){	
		 	case PIDHELLO:
		 		Dobj = new datagram();
		 		break;
		 	case PIDREPLY:
		 		byte[] serialnum1 = new byte[8];
		 		for(i=0;i<8;i++){
		 			serialnum1[i] = data[1+i];
		 		}
		 		long serialNum1 = byteArrayToLong(serialnum1);
		 		Dobj = new datagram(serialNum1);
		 		break;
		 	case PIDCTL:
		 		byte[] serialnum2 = new byte[8];
		 		for(i=0;i<8;i++){
		 			serialnum2[i] = data[1+i];
		 		}
		 		long serialNum2 = byteArrayToLong(serialnum2);
			 
		 		byte isAtt = data[9];
			 
		 		byte[] sybnum = new byte[4];
		 		for(i=0;i<4;i++){
		 			sybnum[i] = data[10+i];
		 		}
		 		int sybNum = byteArrayToInt(sybnum);
		 		Dobj = new datagram(serialNum2, isAtt, sybNum);
		 		break;
		 }
		 
		 return Dobj;

	}

	
}
