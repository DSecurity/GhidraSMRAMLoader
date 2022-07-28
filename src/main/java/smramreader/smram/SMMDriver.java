package smramreader.smram;

public class SMMDriver {
    private String name;
    private int address;
    private int size;
    private int entryPoint;

    public SMMDriver(int address, int size, int entryPoint, String name){
        this.address = address;
        this.size = size;
        this.entryPoint = entryPoint;
        this.name = name;
    }

    @Override
    public String toString(){
        return "address: 0x" + Integer.toHexString(address) + ", size: 0x" + Integer.toHexString(size) +
                ", entry point: 0x" + Integer.toHexString(entryPoint) + ", name: " + name;
    }

    public void setName(String name){
        this.name = name;
    }

    public String getName(){
        return name;
    }

    public int getAddress(){
        return address;
    }

    public int getSize(){
        return size;
    }

    public int getEntryPoint(){
        return entryPoint;
    }
}
