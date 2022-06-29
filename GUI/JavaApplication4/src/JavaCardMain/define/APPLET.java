/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JavaCardMain.define;

/**
 *
 * @author Spark_Mac
 */
public class APPLET {

    public static final byte[] AID_APPLET = {(byte) 0x88, (byte) 0x88, (byte) 0x88, (byte) 0x88, (byte) 0x88, (byte) 0x00};

    public static final byte[] AID_RSA = {
        (byte) 0x25, (byte) 0x10, (byte) 0x19, (byte) 0x99, (byte) 0x00, (byte) 0x00, (byte) 0x03
    };

    public final static byte CLA = (byte) 0x00;
    //Read info
    public final static byte READ_INFO = (byte) 0x3f;
    //init info
    public final static byte INIT_INFO = (byte) 0x2f;
    // edit name
    public final static byte INS_NAME = (byte) 0x22;    
    public final static byte INS_BIRTHDAY= (byte) 0x33;
    public final static byte INS_GENDER = (byte) 0x44;    
    public final static byte INS_IMAGE = (byte) 0x55;    
    public final static byte INS_ENCODE_DATA = (byte) 0x2d;    
    public final static byte INS_DECODE_DATA = (byte) 0x3d;




//
    public final static byte INS_SETUP = (byte) 0x2A;
    //INS-PIN
    public final static byte INS_CREATE_PIN = (byte) 0x02;
    public final static byte INS_VERIFY_PIN = (byte) 0x01;
    public final static byte INS_CHANGE_PIN = (byte) 0x44;
    public final static byte INS_UNBLOCK_PIN = (byte) 0x06;

    public final static byte INS_CHANGE_INFORMATION = (byte) 0x52;
    public final static byte INS_CREATE_INFORMATION = (byte) 0x50;
    public final static byte INS_OUT_INFORMATION = (byte) 0x51;

}
