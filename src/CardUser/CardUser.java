package CardUser;
import javacard.framework.*;
import javacard.framework.OwnerPIN;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;
import javacard.security.AESKey;
import javacard.security.Key;
import javacard.security.KeyAgreement;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacardx.apdu.ExtendedLength;
public class CardUser extends Applet implements ExtendedLength
{
	public static byte[] userId;
	public static byte[] userName;
	public static byte[] gender;
	public static byte[] avatar;
	public static byte[] birthDay;
	public static short usernameLength,userIdLength,genderLength,birthDayLength;
	
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
	private static Cipher aesCipher;
	private static AESKey aesKey;
	private final static byte[] PIN_INIT_VALUE={0x01,0x02,0x03,0x04};
	private static short LENGTH_BLOCK_AES = (short)64;

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
		// init cipher
		byte [] tmpBuffer;
		try {
			tmpBuffer = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
		} catch (SystemException e) {
			tmpBuffer = new byte[(short) 256];
		}
		
		aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        Sha512.init();
		HMacSHA512.init(tmpBuffer);
        byte[] keyBytes = JCSystem.makeTransientByteArray(LENGTH_BLOCK_AES, JCSystem.CLEAR_ON_DESELECT);
        try {
            HMacSHA512.computeHmacSha512(PIN_INIT_VALUE,(short)0x00,(short)PIN_INIT_VALUE.length,keyBytes,(short)0);
            aesKey.setKey(keyBytes, (short) 0);
        } finally {
            Util.arrayFillNonAtomic(keyBytes, (short) 0, LENGTH_BLOCK_AES, (byte) 0);
        }
        // The installation parameters contain the PIN
        // initialization value
		pin.update(PIN_INIT_VALUE, (short) 0, (byte)PIN_INIT_VALUE.length);
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
			// getName(apdu,buf);
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
        byte[] dataEncrypt = new byte[128];
		while (recvLen > 0)
		{
			Util.arrayCopy(buf, dataOffset, temp, pointer,recvLen);
			pointer += recvLen;
			recvLen = apdu.receiveBytes(dataOffset);
		}
		//
		short lengthUserId = getLengthWithMaker(temp,dataOffsetInput,(short)temp.length);
		userIdLength = lengthUserId;
		userId = new byte[128];
		byte[] tempUserId = new byte[lengthUserId];
		Util.arrayCopy(temp, dataOffsetInput, tempUserId, (short)0,(short)lengthUserId);
		dataEncrypt = encrypt(tempUserId);
		Util.arrayCopy(dataEncrypt,(short)0x00, userId, (short)0,(short)dataEncrypt.length);
		dataOffsetInput = (short)(tempUserId.length +  dataOffsetInput +1);
		//
		short lengthUsername = getLengthWithMaker(temp,dataOffsetInput,(short)temp.length);
		usernameLength = lengthUsername;
		userName = new byte[128];
		byte[] tempUsername = new byte[lengthUsername];
		Util.arrayCopy(temp, dataOffsetInput, tempUsername, (short)0,(short)lengthUsername);
		dataEncrypt = encrypt(tempUsername);
		Util.arrayCopy(dataEncrypt, (short)0x00, userName, (short)0,(short)dataEncrypt.length);
		dataOffsetInput = (short)(tempUsername.length +  dataOffsetInput +1);
		//
		short lengthBirthDay = getLengthWithMaker(temp,dataOffsetInput,(short)temp.length);
		birthDayLength = lengthBirthDay;
		birthDay = new byte[128];
		byte[] tempBirthDay = new byte[lengthBirthDay];
		Util.arrayCopy(temp, dataOffsetInput, tempBirthDay, (short)0,(short)lengthBirthDay);
		dataEncrypt = encrypt(tempBirthDay);
		Util.arrayCopy(dataEncrypt, (short)0x00, birthDay, (short)0,(short)dataEncrypt.length);
		dataOffsetInput = (short)(tempBirthDay.length +  dataOffsetInput +1);
		//
		short lengthGender = getLengthWithMaker(temp,dataOffsetInput,(short)temp.length);
		genderLength = lengthGender;
		gender = new byte[128];
		byte[] tempGender = new byte[lengthGender];
		Util.arrayCopy(temp, dataOffsetInput, tempGender, (short)0,(short)lengthGender);
		dataEncrypt = encrypt(tempGender);
		Util.arrayCopy(dataEncrypt, (short)0x00, gender, (short)0,(short)dataEncrypt.length);
		dataOffsetInput = (short)(tempGender.length +  dataOffsetInput +1);
		//
		short lengthAvatar = getLengthWithMaker(temp,dataOffsetInput,(short)temp.length);
		 avatar = new byte[lengthAvatar];
		 Util.arrayCopy(temp, dataOffsetInput, avatar, (short)0,(short)avatar.length);
		 dataOffsetInput = (short)(avatar.length + lengthAvatar +1);
		JCSystem.commitTransaction();	
	}
	
	public void showInformation(APDU apdu) {

		byte[] decryptUserId = decrypt(userId,userIdLength);
		byte[] decryptUsername = decrypt(userName,usernameLength);
		byte[] decryptBirthday = decrypt(birthDay,birthDayLength);
		byte[] decryptGender = decrypt(gender,genderLength);
		short lengthUserId = (short)decryptUserId.length;
		short lengthName = (short)decryptUsername.length;
        short lengthBirthDay = (short)decryptBirthday.length;
        short lengthGender = (short)decryptGender.length;
        short lengthAvatar = (short)avatar.length;
		short toSend = (short)(lengthName + lengthBirthDay +lengthGender +lengthAvatar+lengthUserId + 4);
        byte[] temp = new byte[toSend];
        Util.arrayCopy(decryptUserId, (short)0, temp, (short)0,(short)lengthUserId);
        temp[(short)lengthUserId] = 0x2c;
        Util.arrayCopy(decryptUsername, (short)0, temp, (short)(lengthUserId+1),(short)lengthName);
        temp[(short)(lengthName +lengthUserId +1) ] = 0x2c;
        Util.arrayCopy(decryptBirthday, (short)0, temp, (short)(lengthName+lengthUserId+2),(short)lengthBirthDay);
        temp[(short)(lengthBirthDay + lengthName +lengthUserId +2)] = 0x2c;
        Util.arrayCopy(decryptGender, (short)0, temp, (short)(lengthBirthDay+lengthName+lengthUserId+3),(short)lengthGender);
		temp[(short)(lengthGender + lengthBirthDay + lengthName +lengthUserId +3)] = 0x2c;
		
		short solanCopImg = (short)(lengthAvatar/255);
		short soduCopImg = (short)(lengthAvatar%255);
		
		for(short i = 0;i<solanCopImg;i++) {
			Util.arrayCopy(avatar, (short)(i*255), temp, (short)(lengthBirthDay+lengthName+lengthGender+lengthUserId+4 + i*255),(short)255);
		}
		Util.arrayCopy(avatar, (short)(solanCopImg*255), temp, (short)(lengthBirthDay+lengthName+lengthGender+lengthUserId+4 + solanCopImg*255),(short)soduCopImg);

        // Util.arrayCopy(avatar, (short)0, temp, (short)(lengthBirthDay+lengthName+lengthGender+lengthUserId+4),(short)255);
        short le = apdu.setOutgoing(); // do dai du lieu toi da gui len may tinh

		apdu.setOutgoingLength((short)toSend);
        short sendLen = 0;
        short pointer = 0;
        while(toSend > 0)
        {
			sendLen = (toSend > le)?le:toSend;
			apdu.sendBytesLong(temp, pointer,sendLen);
			toSend -= sendLen;
			pointer += sendLen;
        }
	}
	
	public byte[] encrypt(byte[] encryptData) {
        aesCipher.init(aesKey, Cipher.MODE_ENCRYPT);
        short flag = (short) 1;
	    byte[] temp = new byte[128];
    	while(flag == (short)1){
    		for(short i=0;i<=(short) encryptData.length;i++){
    			if(i!=(short) encryptData.length){
					temp[i] = encryptData[i];
    			}
    			else{
	    			flag = (short) 0;
    			}
    		}
    	}
        // short newLength = addPadding(temp, (short) 0, (short) encryptData.length);
        byte[] dataEncrypted; 
        
        try{
				dataEncrypted = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_DESELECT);
			} catch(SystemException e){
				dataEncrypted = new byte[(short)128];
			}
        aesCipher.doFinal(temp, (short) 0 , (short)128, dataEncrypted, (short) 0x00);
        return dataEncrypted;
    }
    
    private static byte[] decrypt(byte[] decryptData, short length) {
    	if(length != (short)0){
			aesCipher.init(aesKey, Cipher.MODE_DECRYPT);
			byte[] dataDecrypted;
			try{
				dataDecrypted = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_DESELECT);
			} catch(SystemException e){
				dataDecrypted = new byte[(short)128];
			}
			aesCipher.doFinal(decryptData, (short) 0, (short) 128, dataDecrypted, (short) 0x00);
			byte[] temp = new byte[length];
			Util.arrayCopy(dataDecrypted, (short)0x00,temp,(short)0,(short) length);
			return temp;
    	}
    	else{
    		byte[] dataDecrypted = new byte[1];
	    	return dataDecrypted;
    	}
        // short newLength = removePadding(dataDecrypted, (short) length);;
    }
	
	public static void showInfo(APDU apdu, byte[] buf,byte[] data,short dataLength) {
		if ( ! pin.isValidated()) ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		Util.arrayCopy(data ,(short)0,buf,(short)0,(short)(dataLength));
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
	
	public static void getName(APDU apdu,byte[] buf){

		byte[] decryptUsername =avatar;
		short lengthName = (short)avatar.length;
		short toSend = (short)(lengthName);
        byte[] temp = new byte[toSend];
        apdu.setOutgoingLength(toSend);
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



