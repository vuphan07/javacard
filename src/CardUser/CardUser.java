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
import javacard.security.*;
import javacardx.crypto.*;
public class CardUser extends Applet implements ExtendedLength
{
	public static byte[] userId;
	public static byte[] userName;
	public static byte[] gender;
	public static byte[] avatar;
	public static byte[] birthDay;
	public static short usernameLength,userIdLength,genderLength,birthDayLength,avatarLength;
	
	final static byte marker =(byte)0x2c;
	
	public static byte isNewUser;

	final static byte USER_CLA =(byte)0x00;
	final static byte VERIFY = (byte) 0x01;
	final static byte INIT_DATA = (byte) 0x2f;
	final static byte GET_INFO = (byte) 0x3f;
	final static byte CREATE_NAME =(byte)0x22;
	final static byte CREATE_BIRTHDAY =(byte)0x33;
	final static byte CREATE_GENDER =(byte)0x44;
	final static byte CREATE_IMAGE =(byte)0x55;
	final static byte CREATE_PIN =(byte)0x02;
    final static byte UNLOCK_USER = (byte) 0x06;
	final static byte PASSWORD_TRY_LIMIT =(byte)0x05;

	final static byte MAX_PASS_SIZE =(byte)0x08;
	   // signal that the PIN verification failed
    final static short SW_VERIFICATION_FAILED = 0x6300;
    final static short SW_CARD_IS_BLOCKED = 0x6302;
    final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	/* instance variables declaration */
	static OwnerPIN pin;
	private MessageDigest sha;
	private static Cipher aesCipher;
	private static AESKey aesKey;
	private RSAPrivateKey rsaPrivKey;
	private RSAPublicKey rsaPubKey;
	private Signature rsaSig;
	private short sigLen;
	private static final byte INS_SIGN = (byte)0x0f;
	private static final byte INS_VERIFY = (byte)0x1f;
	private byte[] s1, s2, s3, sig_buffer;
	private final static byte[] PIN_INIT_VALUE={(byte)'1',(byte)'2',(byte)'3',(byte)'4'};
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
		s1 = new byte[]{0x01, 0x02, 0x03};
		s2 = new byte[]{0x04, 0x05};
		s3 = new byte[]{0x06, 0x07, 0x08};
		sigLen = (short)(KeyBuilder.LENGTH_RSA_1024/8);
		sig_buffer = new byte[sigLen];
		rsaSig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1,false);
		rsaPrivKey =(RSAPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE,(short)(8*sigLen),false);
		rsaPubKey = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC,(short)(8*sigLen), false);

		KeyPair keyPair = new KeyPair(KeyPair.ALG_RSA,(short)(8*sigLen));
		keyPair.genKeyPair();
		rsaPrivKey = (RSAPrivateKey)keyPair.getPrivate();
		rsaPubKey = (RSAPublicKey)keyPair.getPublic();
		sha = MessageDigest.getInstance(MessageDigest.ALG_MD5,false);
		aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        // Sha512.init();
		// HMacSHA512.init(tmpBuffer);
        byte[] keyBytes = JCSystem.makeTransientByteArray(LENGTH_BLOCK_AES, JCSystem.CLEAR_ON_DESELECT);
        try {
        	short shalen = sha.doFinal(PIN_INIT_VALUE, (short)0,(short)PIN_INIT_VALUE.length, keyBytes, (short)0);
            // HMacSHA512.computeHmacSha512(PIN_INIT_VALUE,(short)0x00,(short)PIN_INIT_VALUE.length,keyBytes,(short)0);
            aesKey.setKey(keyBytes, (short) 0);
        } finally {
            Util.arrayFillNonAtomic(keyBytes, (short) 0, LENGTH_BLOCK_AES, (byte) 0);
        }
        // The installation parameters contain the PIN
        // initialization value
		isNewUser= (byte)'1';
        register();
	}
	
	 public boolean select() {
        return true;
    }
    
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
		
		// if ( pin.getTriesRemaining() == 0 ) 
			// ISOException.throwIt(SW_CARD_IS_BLOCKED);
		
		if (buf[ISO7816.OFFSET_CLA] != USER_CLA)
			 ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		switch (buf[ISO7816.OFFSET_INS])
		{
		case (byte) CREATE_PIN:
			createPin(apdu,buf);
			break;
		case (byte) CREATE_NAME:
			createName(apdu,buf);
			break;
		case (byte) CREATE_GENDER:
			createGender(apdu,buf);
			break;
		case (byte) CREATE_BIRTHDAY:
			createBirthDay(apdu,buf);
			break;
		case (byte) CREATE_IMAGE:
			createImage(apdu,buf,byteRead);
			break;
		case (byte) INIT_DATA:
			initInformation(apdu,buf,byteRead);
			break;
		case (byte) GET_INFO:
			 showInformation(apdu);
			break;
		case (byte) VERIFY:
			verify(apdu,buf,(byte)byteRead);
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
        short numberEncrypt = 0;
		while (recvLen > 0)
		{
			Util.arrayCopy(buf, dataOffset, temp, pointer,recvLen);
			pointer += recvLen;
			recvLen = apdu.receiveBytes(dataOffset);
		}
		//
		short lengthUserId = getLengthWithMaker(temp,dataOffsetInput,(short)temp.length);
		userIdLength = lengthUserId;
		numberEncrypt = (short)(userIdLength/128 +1);
		userId = new byte[(short)(128*numberEncrypt)];
		byte[] tempUserId = new byte[lengthUserId];
		Util.arrayCopy(temp, dataOffsetInput, tempUserId, (short)0,(short)lengthUserId);
		dataEncrypt = encrypt(tempUserId);
		Util.arrayCopy(dataEncrypt,(short)0x00, userId, (short)0,(short)dataEncrypt.length);
		dataOffsetInput = (short)(lengthUserId +  dataOffsetInput +1);
		//
		short lengthUsername = getLengthWithMaker(temp,dataOffsetInput,(short)temp.length);
		usernameLength = lengthUsername;
		numberEncrypt = (short)(lengthUsername/128 +1);
		userName = new byte[(short)(128*numberEncrypt)];
		byte[] tempUsername = new byte[lengthUsername];
		Util.arrayCopy(temp, dataOffsetInput, tempUsername, (short)0,(short)lengthUsername);
		dataEncrypt = encrypt(tempUsername);
		Util.arrayCopy(dataEncrypt, (short)0x00, userName, (short)0,(short)dataEncrypt.length);
		dataOffsetInput = (short)(lengthUsername +  dataOffsetInput +1);
		//
		short lengthBirthDay = getLengthWithMaker(temp,dataOffsetInput,(short)temp.length);
		birthDayLength = lengthBirthDay;
		numberEncrypt = (short)(birthDayLength/128 +1);
		birthDay = new byte[(short)(128*numberEncrypt)];
		byte[] tempBirthDay = new byte[lengthBirthDay];
		Util.arrayCopy(temp, dataOffsetInput, tempBirthDay, (short)0,(short)lengthBirthDay);
		dataEncrypt = encrypt(tempBirthDay);
		Util.arrayCopy(dataEncrypt, (short)0x00, birthDay, (short)0,(short)dataEncrypt.length);
		dataOffsetInput = (short)(lengthBirthDay +  dataOffsetInput +1);
		//
		short lengthGender = getLengthWithMaker(temp,dataOffsetInput,(short)temp.length);
		genderLength = lengthGender;
		numberEncrypt = (short)(genderLength/128 +1);
		gender = new byte[(short)(128*numberEncrypt)];
		byte[] tempGender = new byte[lengthGender];
		Util.arrayCopy(temp, dataOffsetInput, tempGender, (short)0,(short)lengthGender);
		dataEncrypt = encrypt(tempGender);
		Util.arrayCopy(dataEncrypt, (short)0x00, gender, (short)0,(short)dataEncrypt.length);
		dataOffsetInput = (short)(lengthGender +  dataOffsetInput +1);
		//
		short lengthAvatar = getLengthWithMaker(temp,dataOffsetInput,(short)temp.length);
		avatarLength = lengthAvatar;
		 numberEncrypt = (short)(lengthAvatar/128 +1);
		 byte[] tempAvatar = new byte[lengthAvatar];
		 avatar = new byte[(short)(128*numberEncrypt)];
		 Util.arrayCopy(temp, dataOffsetInput, tempAvatar, (short)0,(short)lengthAvatar);
		 dataEncrypt = encrypt(tempAvatar);
		 Util.arrayCopy(dataEncrypt, (short)0x00, avatar, (short)0,(short)dataEncrypt.length);
		 dataOffsetInput = (short)(avatar.length + lengthAvatar +1);
		 pin.update(PIN_INIT_VALUE, (short) 0, (byte)PIN_INIT_VALUE.length);
		JCSystem.commitTransaction();	
	}
	
	public void createName(APDU apdu,byte[] buf){
			 // if(!pin.isValidated()) {
			 // ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
			 // return;
		 // }
		short dataOffset = apdu.getOffsetCdata();
		short datalength = apdu.getIncomingLength();
		usernameLength = datalength;

		short numberEncrypt = (short)(datalength/128 +1);
		userName = new byte[(short)(128*numberEncrypt)];

		byte[] tempUsername = new byte[usernameLength];
		Util.arrayCopy(buf, dataOffset, tempUsername, (short)0,(short)usernameLength);
		byte[] dataEncrypt = encrypt(tempUsername);
		Util.arrayCopy(dataEncrypt, (short)0x00, userName, (short)0,(short)dataEncrypt.length);
	}
	
	public void createBirthDay(APDU apdu,byte[] buf){
			 // if(!pin.isValidated()) {
			 // ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
			 // return;
		 // }
		short dataOffset = apdu.getOffsetCdata();
		short datalength = apdu.getIncomingLength();
		birthDayLength = datalength;
		short numberEncrypt = (short)(datalength/128 +1);
		birthDay = new byte[(short)(128*numberEncrypt)];
		byte[] tempUsername = new byte[birthDayLength];
		Util.arrayCopy(buf, dataOffset, tempUsername, (short)0,(short)birthDayLength);
		byte[] dataEncrypt = encrypt(tempUsername);
		Util.arrayCopy(dataEncrypt, (short)0x00, birthDay, (short)0,(short)dataEncrypt.length);
	}
	
	public void createGender(APDU apdu,byte[] buf){
			 // if(!pin.isValidated()) {
			 // ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
			 // return;
		 // }
		short dataOffset = apdu.getOffsetCdata();
		short datalength = apdu.getIncomingLength();
		genderLength = datalength;
		short numberEncrypt = (short)(datalength/128 +1);
		gender = new byte[(short)(128*numberEncrypt)];
		byte[] tempUsername = new byte[usernameLength];
		Util.arrayCopy(buf, dataOffset, tempUsername, (short)0,(short)genderLength);
		byte[] dataEncrypt = encrypt(tempUsername);
		Util.arrayCopy(dataEncrypt, (short)0x00, gender, (short)0,(short)dataEncrypt.length);
	}
	
	public void createImage(APDU apdu,byte[] buf,short recvLen){
			 // if(!pin.isValidated()) {
			 // ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
			 // return;
		 // }
		short pointer = 0;
		short dataOffset = apdu.getOffsetCdata();
		short datalength = apdu.getIncomingLength();
			
		byte[] temp=new byte[datalength];
		short lengthAvatar = datalength;
		short numberEncrypt = (short)(datalength/128 +1);


		while (recvLen > 0)
		{
			Util.arrayCopy(buf, dataOffset, temp, pointer,recvLen);
			pointer += recvLen;
			recvLen = apdu.receiveBytes(dataOffset);
		}
		avatar = new byte[(short)(128*numberEncrypt)];
		byte[] dataEncrypt = encrypt(temp);
		short lenData = (short)dataEncrypt.length;
		short countCopy = (short)(lenData/128);
		for(short i = 0; i< (short) dataEncrypt.length; i++ )
		{
			avatar[i] = dataEncrypt[i];
		}
		// Util.arrayCopy(dataEncrypt, (short)0x00, avatar, (short)0,(short)dataEncrypt.length);
	}
	
	public void showInformation(APDU apdu) {
		byte[] decryptUserId = decrypt(userId,userIdLength);
		byte[] decryptUsername = decrypt(userName,usernameLength);
		byte[] decryptBirthday = decrypt(birthDay,birthDayLength);
		byte[] decryptGender = decrypt(gender,genderLength);
		byte[] decryptAvatar = decrypt(avatar,avatarLength);
		short lengthUserId = (short)decryptUserId.length;
		short lengthName = (short)decryptUsername.length;
        short lengthBirthDay = (short)decryptBirthday.length;
        short lengthGender = (short)decryptGender.length;
        short lengthAvatar = (short)decryptAvatar.length;
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
			Util.arrayCopy(decryptAvatar, (short)(i*255), temp, (short)(lengthBirthDay+lengthName+lengthGender+lengthUserId+4 + i*255),(short)255);
		}
		Util.arrayCopy(decryptAvatar, (short)(solanCopImg*255), temp, (short)(lengthBirthDay+lengthName+lengthGender+lengthUserId+4 + solanCopImg*255),(short)soduCopImg);

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
	
	public void createPin(APDU apdu,byte[] buf) {
			 if(!pin.isValidated()) {
			 ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
			 return;
		 }
		JCSystem.beginTransaction();
		byte[] decryptUserId = decrypt(userId,userIdLength);
		byte[] decryptUsername = decrypt(userName,usernameLength);
		byte[] decryptBirthday = decrypt(birthDay,birthDayLength);
		byte[] decryptGender = decrypt(gender,genderLength);
		byte[] decryptAvatar = decrypt(avatar,avatarLength);
		short dataOffset = apdu.getOffsetCdata();
		short datalength = apdu.getIncomingLength();
		short numberEncrypt = 0;
		byte[] newPin = new byte[datalength];
		Util.arrayCopy(buf,dataOffset,newPin,(short)0,(short)datalength);
		byte[] keyBytes1;
		try {
			keyBytes1 = JCSystem.makeTransientByteArray((short) LENGTH_BLOCK_AES, JCSystem.CLEAR_ON_DESELECT);
		} catch (SystemException e) {
			keyBytes1 = new byte[(short)LENGTH_BLOCK_AES];
		}
		
        try {
            // HMacSHA512.computeHmacSha512(newPin,(short)0x00,(short)newPin.length,keyBytes,(short)0);
            short shalen = sha.doFinal(newPin, (short)0,(short)newPin.length, keyBytes1, (short)0);
            aesKey.setKey(keyBytes1, (short) 0);
        } finally {
            Util.arrayFillNonAtomic(keyBytes1, (short) 0, LENGTH_BLOCK_AES, (byte) 0);
        }
        pin.update(newPin,(short)0,(byte)newPin.length);
		//
		//
		byte[] dataEncrypt;
		numberEncrypt = (short)(decryptUserId.length/128 +1);
		userId = new byte[(short)(128*numberEncrypt)];
		dataEncrypt = encrypt(decryptUserId);
		Util.arrayCopy(dataEncrypt,(short)0x00, userId, (short)0,(short)dataEncrypt.length);
		//
		numberEncrypt = (short)(decryptUsername.length/128 +1);
		userName = new byte[(short)(128*numberEncrypt)];
		dataEncrypt = encrypt(decryptUsername);
		Util.arrayCopy(dataEncrypt, (short)0x00, userName, (short)0,(short)dataEncrypt.length);
		//
		numberEncrypt = (short)(decryptBirthday.length/128 +1);
		birthDay = new byte[(short)(128*numberEncrypt)];
		dataEncrypt = encrypt(decryptBirthday);
		Util.arrayCopy(dataEncrypt, (short)0x00, birthDay, (short)0,(short)dataEncrypt.length);
		//
		numberEncrypt = (short)(decryptGender.length/128 +1);
		gender = new byte[(short)(128*numberEncrypt)];
		dataEncrypt = encrypt(decryptGender);
		Util.arrayCopy(dataEncrypt, (short)0x00, gender, (short)0,(short)dataEncrypt.length);
		//
		numberEncrypt = (short)(decryptAvatar.length/128 +1);
		avatar = new byte[(short)(128*numberEncrypt)];
		dataEncrypt = encrypt(decryptAvatar);
		Util.arrayCopy(dataEncrypt, (short)0x00, avatar, (short)0,(short)dataEncrypt.length);
		//
		isNewUser= (byte)'0';
		pin.check(newPin,(short)0,(byte)newPin.length);
		JCSystem.commitTransaction();
	}
	
	public byte[] encrypt(byte[] encryptData) {
        aesCipher.init(aesKey, Cipher.MODE_ENCRYPT);
        short lengDataEncrypt = (short)encryptData.length;
        short countEncrypt =	(short) (lengDataEncrypt/128 +1);       
        short lengtDataEncryptEnd = (short) (lengDataEncrypt%128);
		byte[] temp = new byte[128];
		byte[] dataEncrypted; 
		try{
			 dataEncrypted = JCSystem.makeTransientByteArray((short) (128*countEncrypt), JCSystem.CLEAR_ON_DESELECT);
		} catch(SystemException e){
			 dataEncrypted = new byte[(short)(128*countEncrypt)];
		}

        for(short count = 0; count < (short)countEncrypt; count ++) {

            if(count == (short)(countEncrypt - 1)) {
                for(short i=0;i<(short) lengtDataEncryptEnd;i++){
                    temp[i] = encryptData[(short)(128*count+i)];
                }
            }else {
                for(short i=0;i<(short) 128;i++){
                    temp[i] = encryptData[(short)(128*count+i)];
                }
            }
            aesCipher.doFinal(temp, (short) 0 , (short)128, dataEncrypted, (short)(128*count));
        }

        // while(countEncrypt > 0) {
        //     if(countEncrypt === (short)1) {
        //         for(short i=0;i<(short) lengtDataEncryptEnd;i++){
        //             temp[i] = encryptData[(short)(128*(countEncrypt-1)+i)];
        //         }
        //     }
         
        //     countEncrypt = (short)(countEncrypt - 1);
        // }


        // short flag = (short) 1;
	    // byte[] temp = new byte[128];
    	// while(flag == (short)1){
    	// 	for(short i=0;i<=(short) encryptData.length;i++){
    	// 		if(i!=(short) encryptData.length){
		// 			temp[i] = encryptData[i];
    	// 		}
    	// 		else{
	    // 			flag = (short) 0;
    	// 		}
    	// 	}
    	// }
        // byte[] dataEncrypted; 
        // try{
		// 		dataEncrypted = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_DESELECT);
		// 	} catch(SystemException e){
		// 		dataEncrypted = new byte[(short)128];
		// 	}
        // aesCipher.doFinal(temp, (short) 0 , (short)128, dataEncrypted, (short) 0x00);
          // Util.arrayFillNonAtomic(dataEncrypted, (short) 0, 128, (byte) 0);
        return dataEncrypted;
    }
    
    private static byte[] decrypt(byte[] decryptData, short length) {
    	if(length != (short)0){
			aesCipher.init(aesKey, Cipher.MODE_DECRYPT);
			byte[] dataDecrypted = new byte[length];
            short countDecrypt =	(short) (length/128 +1);       
            short lengtDataDecryptEnd = (short) (length%128);
			byte[] temp,temp1;
            try{
				temp = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_DESELECT);				
				temp1 = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_DESELECT);

			} catch(SystemException e){
				temp = new byte[(short)128];
				temp1 = new byte[(short)128];
			}
            for(short count = 0; count < (short)countDecrypt; count ++) {

                if(count == (short)(countDecrypt - 1)) {
                    for(short i=0;i<(short) 128;i++){
                        temp[i] = decryptData[(short)(128*count+i)];
                    }
			        aesCipher.doFinal(temp, (short) 0, (short) 128, temp1, (short)0x00);
					Util.arrayCopy(temp1, (short)0x00,dataDecrypted,(short) (count*128),(short)lengtDataDecryptEnd);
                    // aesCipher.doFinal(decryptData, (short) (count*128), (short) (count*128 +lengtDataDecryptEnd), temp,(short) (count*128));
                }else {
                    for(short i=0;i<(short) 128;i++){
                        temp[i] = decryptData[(short)(128*count+i)];
                    }
                     aesCipher.doFinal(temp, (short) 0, (short) 128, temp1, (short)0x00);
			       Util.arrayCopy(temp1, (short)0x00,dataDecrypted,(short) (count*128),(short)128);

                    // aesCipher.doFinal(decryptData, (short) (count*128), (short) (count*128 +128), temp,(short) (count*128));
                }
            }
    
			// byte[] dataDecrypted;
			// try{
			// 	dataDecrypted = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_DESELECT);
			// } catch(SystemException e){
			// 	dataDecrypted = new byte[(short)128];
			// }
			// aesCipher.doFinal(decryptData, (short) 0, (short) 128, dataDecrypted, (short) 0x00);
			// byte[] temp = new byte[length];
			// Util.arrayCopy(dataDecrypted, (short)0x00,temp,(short)0,(short) length);
			return dataDecrypted;
    	}
    	else{
    		byte[] dataDecrypted = new byte[1];
	    	return dataDecrypted;
    	}
    }
    
    private void rsaSign(APDU apdu)
	{
		rsaSig.init(rsaPrivKey, Signature.MODE_SIGN);
		rsaSig.update(s1, (short)0, (short)(s1.length));
		rsaSig.update(s2, (short)0, (short)(s2.length));
		rsaSig.sign(s3, (short)0, (short)(s3.length),
		sig_buffer, (short)0);
		apdu.setOutgoing();
		apdu.setOutgoingLength(sigLen);

		apdu.sendBytesLong(sig_buffer, (short)0, sigLen);
	}
	private void rsaVerify(APDU apdu)
	{
		byte [] buf = apdu.getBuffer();
		rsaSig.init(rsaPubKey, Signature.MODE_VERIFY);
		rsaSig.update(s1, (short)0, (short)(s1.length));
		rsaSig.update(s2, (short)0, (short)(s2.length));
		boolean ret = rsaSig.verify(s3, (short)0,
		(short)(s3.length), sig_buffer, (short)0, sigLen);

		buf[(short)0] = ret ? (byte)1 : (byte)0;
		apdu.setOutgoingAndSend((short)0, (short)1);
	}
	
	private void verify(APDU apdu,byte[] buf,byte length) {
		if ( pin.check(buf, ISO7816.OFFSET_CDATA,length) == false ) {
			byte[] count = new byte[1];
			switch(pin.getTriesRemaining()){
				case (byte) 0x01:
					count[0] = (byte)'1';
					break;
				case (byte) 0x02:
					count[0] = (byte)'2';
					break;
				case (byte) 0x03:
					count[0] = (byte)'3';
					break;
				case (byte) 0x04:
					count[0] = (byte)'4';
					break;
				case (byte) 0x00:
					count[0] = (byte)'0';
					break;
			}
			
			short le = apdu.setOutgoing();
			apdu.setOutgoingLength((short)1);
			apdu.sendBytesLong(count, (short)0, (short)1);
			ISOException.throwIt(SW_VERIFICATION_FAILED);
		}

			byte[] status = new byte[1];
			status[0] = isNewUser;
			short le = apdu.setOutgoing();
			apdu.setOutgoingLength((short)1);
			apdu.sendBytesLong(status, (short)0, (short)1);
	}
}



