package smramreader.smram;

public class SMMProtocol {
    private int address;
    private String GUID;
    private String name;

    public SMMProtocol(int address, String GUID, String name){
        this.address = address;
        this.GUID = GUID;
        this.name = name;
    }

    @Override
    public String toString(){
        return "addr: 0x" + Integer.toHexString(address) + ", guid: " + GUID;
    }

    public int getAddress(){
        return address;
    }

    public String getGUID(){
        return GUID;
    }

    public String getName(){
        return name;
    }
}