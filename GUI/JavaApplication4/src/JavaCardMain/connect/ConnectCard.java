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
    
    
    public boolean verifyPin(String pin){
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
            switch (message.toUpperCase()) {
                case RESPONS.SW_NO_ERROR:
                    return true;
                case RESPONS.SW_AUTH_FAILED:
                    JOptionPane.showMessageDialog(null, "Bạn đã nhập sai PIN");
                    return false;
                case RESPONS.SW_IDENTITY_BLOCKED:
                    JOptionPane.showMessageDialog(null, "Bạn đã nhập sai quá số lần thử!Thẻ đã bị khoá");
                    return false;
                case RESPONS.SW_INVALID_PARAMETER:
                    JOptionPane.showMessageDialog(null, "Độ dài pin chưa hợp lệ");
                    return false;
                default:
                    return false;
            }
            
        }
        catch(Exception ex){
            return false;
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
            ResponseAPDU answer = channel.transmit(new CommandAPDU(APPLET.CLA,0x2f,0x00,0x00,data));

            message = answer.toString();
            System.out.println(answer);
            System.out.println(message);
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
            ResponseAPDU answerID = channel.transmit(new CommandAPDU(APPLET.CLA,0x3f,0x00,0x00));
                           System.out.println(answerID);

            String strData = new String(answerID.getData());
            return strData;
        }
        catch(Exception ex){
            return "";
        }
    }   
    public boolean UploadImage(File file, String type){
        connectapplet();
        try{
            
            TerminalFactory factory = TerminalFactory.getDefault();
            List<CardTerminal> terminals = factory.terminals().list();
            
            CardTerminal terminal = terminals.get(0);
            
            Card card = terminal.connect("T=1");
            
            CardChannel channel = card.getBasicChannel();
            
            BufferedImage bImage = ImageIO.read(file);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ImageIO.write(bImage, type, bos);
            
            byte[] napanh = bos.toByteArray();
            
            int soLan = napanh.length / 249;
            
            String strsend = soLan + "S" + napanh.length % 249;
            
            byte[] send = strsend.getBytes();
            
            ResponseAPDU response = channel.transmit(new CommandAPDU(APPLET.CLA,APPLET.INS_CREATE_SIZEIMAGE,0x00,0x01,send));
            String check = Integer.toHexString(response.getSW());
            
            if(check.equals(RESPONS.SW_NO_ERROR)){
                for(int i = 0;i<=soLan ;i++){
                    byte p1 = (byte) i;
                    int start = 0, end = 0;
                    start = i * 249;
                    if(i != soLan){
                        end = (i+1) *249;
                    }
                    else{
                        end = napanh.length;
                    }
                    byte[] slice = Arrays.copyOfRange(napanh, start, end);
                    response = channel.transmit(new CommandAPDU(APPLET.CLA,APPLET.INS_CREATE_IMAGE,p1,0x01,slice));
                    String checkSlide = Integer.toHexString(response.getSW());
                    if(!checkSlide.equals(RESPONS.SW_NO_ERROR)){
                        return false;
                    }
                }
                return true;
            }
            return true;
        }
        catch(Exception ex){
            return false;
        }
    }
    public BufferedImage DownloadImage(){
        connectapplet();
        try {
            TerminalFactory factory = TerminalFactory.getDefault();
            
            List<CardTerminal> terminals = factory.terminals().list();
            
            CardTerminal terminal = terminals.get(0);
            
            Card card = terminal.connect("T=1");
            
            CardChannel channelImage = card.getBasicChannel();
            
            int size = 0;
            ResponseAPDU answer = channelImage.transmit(new CommandAPDU(APPLET.CLA,APPLET.INS_OUT_SIZEIMAGE,0x01,0x01));
            String check = Integer.toHexString(answer.getSW());
            if(check.equals(RESPONS.SW_NO_ERROR)){
                byte[] sizeAnh = answer.getData();
                if(ConvertData.isByteArrayAllZero(sizeAnh)){
                    return null;
                }
                byte[] arrAnh = new byte[10000];
                String strSizeAnh = new String(sizeAnh);
                String[] outPut1 = strSizeAnh.split("S");
                
                int lan = Integer.parseInt(outPut1[0].replaceAll("\\D", ""));
                int du = Integer.parseInt(outPut1[1].replaceAll("\\D", ""));
                size = lan * 249 + du;
                int count = size / 249;
                System.err.println(count);
                for(int j=0;j<=count;j++){
                    answer = channelImage.transmit(new CommandAPDU(APPLET.CLA,APPLET.INS_OUT_IMAGE,(byte)j,0x01));
                    String check1 = Integer.toHexString(answer.getSW());
                    if(check1.equals(RESPONS.SW_NO_ERROR)){
                        byte[] result = answer.getData();
                        int leng = 249;
                        if(j == count){
                            leng = size % 249;
                        }
                        System.arraycopy(result, 0, arrAnh, j*249, leng);
                    }
                }
                
                ByteArrayInputStream bais = new ByteArrayInputStream(arrAnh);
                try {
                    BufferedImage image  = ImageIO.read(bais);
                    return image;
                } catch (Exception e) {
                    System.err.println("Error image");
                }
            }
        } catch (Exception e) {
            System.err.println("error dowloadimage");
        }
        return null;
    }
    
    public static void main(String[] args) {
        System.out.println("begin connect");
        new ConnectCard().connectapplet();
    }
    
}