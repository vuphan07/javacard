/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JavaCardMain.connect;

import JavaCardMain.utils.ConvertData;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import java.util.List;
import javax.smartcardio.*;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.imageio.ImageIO;
import javax.swing.JOptionPane;
import JavaCardMain.define.*;
/**
 *
 * @author Spark_Mac
 */
public class ConnectCard {
    public byte [] data;
    public String message;
    public String strID;
    public String strName;
    public String strDate;
    public String strPhone;
    
    private Card card;
    private TerminalFactory factory;
    public CardChannel channel;
    private CardTerminal terminal;
    private List<CardTerminal> terminals;
    
    private static ConnectCard instance;
    public static ConnectCard getInstance() {
        if (instance == null) {
            instance = new ConnectCard();
        }
        return instance;
    }
    public String connectapplet(){
        try{
            factory = TerminalFactory.getDefault();
            terminals = factory.terminals().list();
            
            terminal = terminals.get(0);
            
            card = terminal.connect("T=1");
            
            channel = card.getBasicChannel();
            
            ResponseAPDU answer = channel.transmit(new CommandAPDU(APPLET.CLA,0xA4,0x04,0x00,APPLET.AID_APPLET));
            String kq = answer.toString();
            data = answer.getData();
            System.out.println("Connect thành công");            
            System.out.println(kq);

            return kq;
            
        }
        catch(Exception ex){
            System.err.println("Connect thất bại");
            return "Error";
        }
    }
    
    
    public String verifyPin(String pin){
        connectapplet();
        byte[] pinbyte =  pin.getBytes();
        try{
            
            TerminalFactory factory = TerminalFactory.getDefault();
            List<CardTerminal> terminals = factory.terminals().list();
            
            CardTerminal terminal = terminals.get(0);
            
            Card card = terminal.connect("T=1");
            
            CardChannel channel = card.getBasicChannel();
            
            ResponseAPDU answer = channel.transmit(new CommandAPDU(APPLET.CLA,APPLET.INS_VERIFY_PIN,0x00,0x00,pinbyte));
            message = Integer.toHexString(answer.getSW());
                  String strData = new String(answer.getData());
            switch (message.toUpperCase()) {
                case RESPONS.SW_NO_ERROR:
                    return strData;
                case RESPONS.SW_AUTH_FAILED:
                    JOptionPane.showMessageDialog(null, "Bạn đã nhập sai PIN");
                    return "";
                case RESPONS.SW_IDENTITY_BLOCKED:
                    JOptionPane.showMessageDialog(null, "Bạn đã nhập sai quá số lần thử!Thẻ đã bị khoá");
                    return "";
                case RESPONS.SW_INVALID_PARAMETER:
                    JOptionPane.showMessageDialog(null, "Độ dài pin chưa hợp lệ");
                    return "";
                default:
                    return "";
            }
            
        }
        catch(Exception ex){
            return "";
        }
    }
    
    public boolean createPIN(String pin){
        
        byte[] pinbyte =  pin.getBytes();
        byte lengt = (byte) pinbyte.length;
        
        byte[] send = new byte[lengt+1];
        send[0] = lengt;
        for(int i =1;i<send.length;i++){
            send[i] = pinbyte[i-1];
        }
        try{
            
            TerminalFactory factory = TerminalFactory.getDefault();
            List<CardTerminal> terminals = factory.terminals().list();
            
            CardTerminal terminal = terminals.get(0);
            
            Card card = terminal.connect("T=1");
            
            CardChannel channel = card.getBasicChannel();
            
            ResponseAPDU answer = channel.transmit(new CommandAPDU(APPLET.CLA,APPLET.INS_CREATE_PIN,0x00,0x03,send));
            
            message = answer.toString();
            switch (((message.split("="))[1]).toUpperCase()) {
                case RESPONS.SW_NO_ERROR:
                    return true;
                case RESPONS.SW_INVALID_PARAMETER:
                    JOptionPane.showMessageDialog(null, "Lỗi độ dài pin");
                    return false;
                case RESPONS.SW_WRONG_LENGTH:
                    JOptionPane.showMessageDialog(null, "Lỗi SW_WRONG_LENGTH");
                    return false;
                default:
                    return false;
            }
            
        }
        catch(Exception ex){
            return false;
        }
    }
    
    public boolean ChangePIN(String oldPin,String newPin){
        connectapplet();
        byte[] pinOldByte =  oldPin.getBytes();
        byte lengtOld = (byte) pinOldByte.length;
        
        byte[] pinNewByte =  newPin.getBytes();
        byte lengtNew = (byte) pinNewByte.length;
        
        byte[] send = new byte[lengtNew+lengtOld+2];
        int offSet = 0;
        send[offSet] = lengtOld;
        offSet+=1;
        System.arraycopy(pinOldByte, 0, send, offSet, lengtOld);
        offSet+=lengtOld;
        send[offSet] = lengtNew;
        offSet+=1;
        System.arraycopy(pinNewByte, 0, send, offSet, lengtNew);
        try{
            
            TerminalFactory factory = TerminalFactory.getDefault();
            List<CardTerminal> terminals = factory.terminals().list();
            
            CardTerminal terminal = terminals.get(0);
            
            Card card = terminal.connect("T=1");
            
            CardChannel channel = card.getBasicChannel();
            
            ResponseAPDU answer = channel.transmit(new CommandAPDU(APPLET.CLA,APPLET.INS_CHANGE_PIN,0x00,0x00,send));
            
            message = answer.toString();
            switch (((message.split("="))[1]).toUpperCase()) {
                case RESPONS.SW_NO_ERROR:
                    JOptionPane.showMessageDialog(null, "Cập nhật PIN thành công!");
                    return true;
                case RESPONS.SW_AUTH_FAILED:
                    JOptionPane.showMessageDialog(null, "Bạn đã nhập sai PIN");
                    return false;
                case RESPONS.SW_IDENTITY_BLOCKED:
                    JOptionPane.showMessageDialog(null, "Bạn đã nhập sai quá số lần thử!Thẻ đã bị khoá");
                    return false;
                default:
                    return false;
            }
            
        }
        catch(Exception ex){
            return false;
        }
    }
    public boolean UnblockPin(byte [] aid){
        try{
            
            TerminalFactory factory = TerminalFactory.getDefault();
            List<CardTerminal> terminals = factory.terminals().list();
            
            CardTerminal terminal = terminals.get(0);
            
            Card card = terminal.connect("T=1");
            
            CardChannel channel = card.getBasicChannel();
            
            ResponseAPDU selectBlockcard = channel.transmit(new CommandAPDU(0x00,0xA4,0x00,0x00,aid));
            
            String check = Integer.toHexString(selectBlockcard.getSW());
            
            if(check.equals(RESPONS.SW_NO_ERROR)){
                CardChannel channel2 = card.getBasicChannel();
            
            ResponseAPDU unblockCard = channel2.transmit(new CommandAPDU(APPLET.CLA,APPLET.INS_UNBLOCK_PIN,0x00,0x00));
                message = unblockCard.toString();
                switch (((message.split("="))[1]).toUpperCase()) {
                    case RESPONS.SW_NO_ERROR:
                        JOptionPane.showMessageDialog(null, "Mở khoá thẻ thành công");
                        return true;
                    case RESPONS.SW_OPERATION_NOT_ALLOWED:
                        JOptionPane.showMessageDialog(null, "Thẻ không bị khoá vui lòng kiểm tra lại!");
                        return false;
                    default:
                        return false;
                }
            }
            else{
                return false;
            }
        }
        catch(Exception ex){
            return false;
        }
    }
    
    public void setUp(){
        
        try{
            
            TerminalFactory factory = TerminalFactory.getDefault();
            List<CardTerminal> terminals = factory.terminals().list();
            
            CardTerminal terminal = terminals.get(0);
            
            Card card = terminal.connect("T=1");
            
            CardChannel channel = card.getBasicChannel();
            
            ResponseAPDU answer = channel.transmit(new CommandAPDU(APPLET.CLA,APPLET.INS_SETUP,0x00,0x00));
            
        }
        catch(Exception ex){
            //return "Error";
        }
    
    }
    
    public boolean EditInformation(byte [] data){
        try{
            connectapplet();
            TerminalFactory factory = TerminalFactory.getDefault();
            List<CardTerminal> terminals = factory.terminals().list();
            
            CardTerminal terminal = terminals.get(0);
            Card card = terminal.connect("T=1");
            CardChannel channel = card.getBasicChannel();
            ResponseAPDU answer = channel.transmit(new CommandAPDU(APPLET.CLA,APPLET.INIT_INFO,0x00,0x00,data));

            message = answer.toString();
            switch (((message.split("="))[1]).toUpperCase()) {
                case "9000":
                    JOptionPane.showMessageDialog(null, "Cập nhật thông tin thành công!");
                    return true;
                case RESPONS.SW_WRONG_LENGTH:
                    JOptionPane.showMessageDialog(null, "Dữ liệu quá lớn, vui lòng kiểm tra lại!");
                    return false;
                default:
                    return false;
            }
            
        }
        catch(Exception ex){
            return false;
        }
    }
    public String ReadInformation(){
        try{
             connectapplet();
            TerminalFactory factory = TerminalFactory.getDefault();
            List<CardTerminal> terminals = factory.terminals().list();
            
            CardTerminal terminal = terminals.get(0);
            
            Card card = terminal.connect("T=1");
            
            CardChannel channel = card.getBasicChannel();
            System.out.println("begin get info");
            ResponseAPDU answerID = channel.transmit(new CommandAPDU(APPLET.CLA,APPLET.READ_INFO,0x00,0x00));

            String strData = new String(answerID.getData());
            return strData;
        }
        catch(Exception ex){
            return "";
        }
    }   
        
    public static void main(String[] args) {
        System.out.println("begin connect");
        new ConnectCard().connectapplet();
    }
    
}