package CardUser;

import javacard.framework.*;
import javacardx.apdu.ExtendedLength;
public class CardUser extends Applet
{
	public static byte[] userId;
	public static byte[] userName;
	public static byte[] gender;
	public static byte[] avatar;
	public static byte[] birthDay;
	
	final static byte marker =(byte)0x2c;


	final static byte USER_CLA =(byte)0x00;
	final static byte VERIFY = (byte) 0x01;
	final static byte CREATE_USER = (byte) 0x02;
	final static byte INSERT_USERID = (byte) 0x02;
    final static byte INSERT_USERNAME = (byte) 0x03;
    final static byte INSERT_GENDER = (byte) 0x04;
    final static byte INSERT_AVATAR = (byte) 0x05;
    final static byte INSERT_BIRTHDAY = (byte) 0x06;
	final static byte INSERT_PASSWORD =(byte)0x07;
	final static byte INSERT_ALL = (byte) 0x08;
    final static byte EDIT_USER = (byte) 0x03;
    final static byte EDIT_USERID = (byte) 0x02;
    final static byte EDIT_USERNAME = (byte) 0x03;
    final static byte EDIT_GENDER = (byte) 0x04;
    final static byte EDIT_AVATAR = (byte) 0x05;
    final static byte EDIT_BIRTHDAY = (byte) 0x06;
	final static byte EDIT_PASSWORD =(byte)0x05;
    final static byte DELETE_USER = (byte) 0x04;
    final static byte DELETE_USERID = (byte) 0x02;
    final static byte DELETE_USERNAME = (byte) 0x03;
    final static byte DELETE_GENDER = (byte) 0x04;
    final static byte DELETE_AVATAR = (byte) 0x05;
    final static byte DELETE_BIRTHDAY = (byte) 0x06;
	final static byte DELETE_PASSWORD =(byte)0x07;
    final static byte GET_USER = (byte) 0x05;
    final static byte GET_USERID = (byte) 0x02;
    final static byte GET_USERNAME = (byte) 0x03;
    final static byte GET_GENDER = (byte) 0x04;
    final static byte GET_AVATAR = (byte) 0x05;
    final static byte GET_BIRTHDAY = (byte) 0x06;
	final static byte GET_PASSWORD =(byte)0x07;
    final static byte UNLOCK_USER = (byte) 0x06;
	final static byte PASSWORD_TRY_LIMIT =(byte)0x05;
	final static byte MAX_PASS_SIZE =(byte)0x08;
	   // signal that the PIN verification failed
    final static short SW_VERIFICATION_FAILED = 0x6300;
    final static short SW_CARD_IS_BLOCKED = 0x6302;
    final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	/* instance variables declaration */
	static OwnerPIN pin;
	
	private CardUser(byte[] bArray, short bOffset, byte bLength) {
		  // It is good programming practice to allocate
        // all the memory that an applet needs during
        // its lifetime inside the constructor
        pin = new OwnerPIN(PASSWORD_TRY_LIMIT,(byte)MAX_PASS_SIZE);
        
        byte iLen = bArray[bOffset]; // aid length
        bOffset = (short) (bOffset+iLen+1);
        byte cLen = bArray[bOffset]; // info length
        bOffset = (short) (bOffset+cLen+1);
        byte aLen = bArray[bOffset]; // applet data length
        
        // The installation parameters contain the PIN
        // initialization value
        byte [] pinArr = {1,2,3,4};
		pin.update(pinArr, (short) 0, (byte)pinArr.length);
        register();
	}
	
	 public boolean select() {
        
        // The applet declines to be selected
        // if the pin is blocked.
        if ( pin.getTriesRemaining() == 0 )
           return false;
        
        return true;
        
    }// end of select method
    
     public void deselect() {
        // reset the pin value
        pin.reset();
        
    }
	
	public static void install(byte[] bArray, short bOffset, byte bLength) 
	{
		new CardUser(bArray, bOffset, bLength);
	}

	public void process(APDU apdu)
	{
		if (selectingApplet())
		{
			return;
		}

		byte[] buf = apdu.getBuffer();
		short byteRead = (short)(apdu.setIncomingAndReceive());
		short dataLen = (short)(buf[ISO7816.OFFSET_LC]&0xff);
		
		if ( pin.getTriesRemaining() == 0 ) 
			ISOException.throwIt(SW_CARD_IS_BLOCKED);
		
		if (buf[ISO7816.OFFSET_CLA] != USER_CLA)
			 ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		switch (buf[ISO7816.OFFSET_INS])
		{
		case CREATE_USER:
			switch(buf[ISO7816.OFFSET_P1]){
				case (byte) INSERT_USERID:
					userId = new byte[byteRead];
					saveInfo(buf,ISO7816.OFFSET_CDATA,userId,(short)0,(short)byteRead);
					break;
				case (byte) INSERT_USERNAME:
					userName = new byte[byteRead];
					saveInfo(buf,ISO7816.OFFSET_CDATA,userName,(short)0,(short)byteRead);
					break;
				case (byte) INSERT_GENDER:
					gender = new byte[byteRead];
					saveInfo(buf,ISO7816.OFFSET_CDATA,gender,(short)0,(short)byteRead);
					break;
				case (byte) INSERT_BIRTHDAY:
					birthDay = new byte[byteRead];
					saveInfo(buf,ISO7816.OFFSET_CDATA,birthDay,(short)0,(short)byteRead);
					break;
				case (byte) INSERT_AVATAR:
					avatar = new byte[byteRead];
					saveInfoLong(apdu,buf,(short)byteRead);
					break;
				case (byte) INSERT_PASSWORD:
					 pin.update(buf, ISO7816.OFFSET_CDATA,(byte) dataLen);
					break;	
			}
			break;
		case (byte) 0x2f:
			initInformation(apdu,buf,byteRead);
			break;
		case (byte) 0x3f:
			showInformation(apdu);
			break;
		case (byte)GET_USER:
			switch(buf[ISO7816.OFFSET_P1]){
				case (byte)GET_USERID:
					showInfo(apdu,buf,userId,(short)userId.length);
					break;
				case (byte)GET_USERNAME:
					showInfo(apdu,buf,userName,(short)userName.length);
					break;
				case (byte)GET_AVATAR:
					showInfoLong(apdu,buf,avatar);
					break;
				case (byte)GET_BIRTHDAY:
					showInfo(apdu,buf,birthDay,(short)birthDay.length);
					break;
				case (byte)GET_GENDER:
					showInfo(apdu,buf,gender,(short)gender.length);
					break;
				case (byte)GET_PASSWORD:
					
					break;
			}
			break;
		case (byte) VERIFY:
			verify(buf,(byte)byteRead);
			break;
		case (byte)UNLOCK_USER: pin.resetAndUnblock();
			return;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	public static short getLengthWithMaker(byte[] buf,short start, short end){
		 short position = start;
		 short isMarker = 0x00;
		 for(short i = start; i < end; i++) {
		 	 position = i;
			    if(buf[i] == marker) {
					isMarker=(short)1;
					break;
			    }
			   
		 }
		 if(isMarker == (short)1) {
			 return (short)(position - start);
		 }
		 return (short)(position+1 - start);
	}
	
	public void initInformation(APDU apdu,byte[] buf,short recvLen) {
		JCSystem.beginTransaction();
		short pointer = 0;
		short dataOffset = apdu.getOffsetCdata();
		short datalength = apdu.getIncomingLength();
		byte[] temp=new byte[datalength];
        short dataOffsetInput = 0;
		while (recvLen > 0)
		{
			Util.arrayCopy(buf, dataOffset, temp, pointer,recvLen);
			pointer += recvLen;
			recvLen = apdu.receiveBytes(dataOffset);
		}
		short lengthUsername = getLengthWithMaker(temp,dataOffsetInput,(short)temp.length);
		userName = new byte[lengthUsername];
		Util.arrayCopy(temp, dataOffsetInput, userName, (short)0,(short)userName.length);
		dataOffsetInput = (short)(userName.length +  dataOffsetInput +1);
		short lengthBirthDay = getLengthWithMaker(temp,dataOffsetInput,(short)temp.length);
		birthDay = new byte[lengthBirthDay];
		Util.arrayCopy(temp, dataOffsetInput, birthDay, (short)0,(short)birthDay.length);
		dataOffsetInput = (short)(birthDay.length + dataOffsetInput +1);
		short lengthGender = getLengthWithMaker(temp,dataOffsetInput,(short)temp.length);
		gender = new byte[lengthGender];
		Util.arrayCopy(temp, dataOffsetInput, gender, (short)0,(short)gender.length);
		dataOffsetInput = (short)(gender.length + dataOffsetInput +1);
		short lengthAvatar = getLengthWithMaker(temp,dataOffsetInput,(short)temp.length);
		 avatar = new byte[lengthAvatar];
		 Util.arrayCopy(temp, dataOffsetInput, avatar, (short)0,(short)avatar.length);
		 dataOffsetInput = (short)(avatar.length + lengthAvatar +1);
		JCSystem.commitTransaction();	
	}
	
	public void showInformation(APDU apdu) {
		JCSystem.beginTransaction();
		short lengthName = (short)userName.length;
        short lengthBirthDay = (short)birthDay.length;
        short lengthGender = (short)gender.length;
        short lengthAvatar = (short)avatar.length;
		short toSend = (short)(lengthName + lengthBirthDay +lengthGender +lengthAvatar);
        byte[] temp = new byte[toSend];
        Util.arrayCopy(userName, (short)0, temp, (short)0,(short)lengthName);
        Util.arrayCopy(birthDay, (short)0, temp, (short)lengthName,(short)lengthBirthDay);
        Util.arrayCopy(gender, (short)0, temp, (short)(lengthBirthDay+lengthName),(short)lengthGender);
        Util.arrayCopy(avatar, (short)0, temp, (short)(lengthBirthDay+lengthName+lengthGender),(short)lengthAvatar);
        short le = apdu.setOutgoing(); // do dai du lieu toi da gui len may tinh

        apdu.setOutgoingLength(toSend);
        short sendLen = 0;
        short pointer = 0;
        while(toSend > 0)
        {
			sendLen = (toSend > le)?le:toSend;

			apdu.sendBytesLong(temp, pointer,sendLen);
			toSend -= sendLen;
			pointer += sendLen;
        }
		JCSystem.commitTransaction();	
	}
	
	public static void showInfo(APDU apdu, byte[] buf,byte[] data,short dataLength) {
		if ( ! pin.isValidated()) ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		Util.arrayCopy(data,(short)0,buf,(short)0,(short)(dataLength));
		apdu.setOutgoingAndSend((short) 0,(short)(dataLength));
	}
	
	public static void saveInfo(byte[] buf,short offset,byte[] target,short offsetTarget, short targetLeng) {
		if ( ! pin.isValidated()) ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		Util.arrayCopy(buf, offset,target, offsetTarget, targetLeng);
	}
	
	public static void saveInfoLong(APDU apdu,byte[] buf, short recvLen ) {
		if ( ! pin.isValidated()) ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		short pointer = 0;
		short dataOffset = apdu.getOffsetCdata();
		short datalength = apdu.getIncomingLength();
		byte[] temp=new byte[datalength];
		while (recvLen > 0)
		{
			Util.arrayCopy(buf, dataOffset, temp, pointer,recvLen);
			pointer += recvLen;
			recvLen = apdu.receiveBytes(dataOffset);
		}
	}
	
	public static void setupNewCard(APDU apdu, byte[] buf){
		short dataOffset = apdu.getOffsetCdata();
				short datalenght = apdu.getIncomingLength();

	}
	
	public static void showInfoLong(APDU apdu, byte[] buf,byte[] data) {
		if ( ! pin.isValidated()) ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		short toSend = (short)data.length;
		short le = apdu.setOutgoing();
		apdu.setOutgoingLength(toSend);
		short sendLen = 0;
		short pointer = 0;
		while(toSend > 0)
		{
			sendLen = (toSend > le)?le:toSend;

			apdu.sendBytesLong(data, pointer,sendLen);
			toSend -= sendLen;
			pointer += sendLen;
		}
	}
	
	private void verify(byte[] buf,byte length) {
		if ( pin.check(buf, ISO7816.OFFSET_CDATA,length) == false ) 
			ISOException.throwIt(SW_VERIFICATION_FAILED);
	}
}
