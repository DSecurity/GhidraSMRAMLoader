package smramreader.smram;

import java.util.ArrayList;

public class SMRAM {
    private ArrayList<SMMDriver> smmDrivers = new ArrayList<>();
    private ArrayList<SMMProtocol> smmProtocols = new ArrayList<>();
    private int smramAddress;
    private byte[] bytes;
    private int align;
    private int smst; 

    public SMRAM(){}

    public void setSMMProtocols(ArrayList<SMMProtocol> smmProtocols){
        this.smmProtocols = smmProtocols;
    } 

    public void setSMMDrivers(ArrayList<SMMDriver> smmDrivers){
        this.smmDrivers = smmDrivers;
    }

    public void setSMRAMAddress(int address){
        smramAddress = address;
    }

    public void setContent(byte[] content){
        bytes = content;
    }

    public void setAlign(int align){
        this.align = align;
    }

    public void setSMSTAddress(int address){
        smst = address;
    }

    public ArrayList<SMMDriver> getSMMDrivers(){
        return smmDrivers;
    }

    public ArrayList<SMMProtocol> getSMMProtocols(){
        return smmProtocols;
    }

    public int getSMRAMAddress(){
        return smramAddress;
    }

    public byte[] getSMRAMContent(){
        return bytes;
    }

    public int getAlign(){
        return align;
    }

    public int getSMSTAddress(){
        return smst;
    }
}
