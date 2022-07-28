package smramreader.parser;
import java.math.BigInteger;
import java.io.File;
import java.io.IOException;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;

import smramreader.smram.SMMDriver;
import smramreader.smram.SMRAM;
import smramreader.smram.SMMProtocol;

public class SMRAMDumpReader{
    private final static int IMAGE_DOS_HEADER_e_lfanew = 0x3c;
    private final static int IMAGE_OPTIONAL_HEADER64_AddressOfEntryPoint = 0x10;
    private final static int IMAGE_OPTIONAL_HEADER64_SizeOfImage = 0x38;
    private final static int IMAGE_NT_HEADERS64_OptionalHeader = 0x18;
    private SMRAM smram = new SMRAM();
    private GuidFinder finder = new GuidFinder();

    public SMRAMDumpReader(String inputFile) throws Exception{
        readDump(inputFile);
        findSMST();
        alignUp();
        findSMRAMAddress();
        finder.findAllGuids(inputFile);
        getSMMDrivers();
        getSMMProtocols();
        finder.clearGuidFinder();
    }

    private void readDump(String inputFile) throws Exception{
        File file = new File(inputFile);
        if (file == null || file.length() == 0){
            throw new Exception("File not found or is empty");
        }

        byte[] bytes = new byte[(int)file.length()];
        try (InputStream inputStream = new FileInputStream(inputFile);){
            inputStream.read(bytes);
        } catch (IOException ex) {
            ex.printStackTrace();
        }

        smram.setContent(bytes);
    }

    private void getSMMDrivers(){
        byte[] bytes = smram.getSMRAMContent();
        ArrayList<SMMDriver> smmDrivers = new ArrayList<>();

        for (int i = 0; i < bytes.length; i+=0x100){
            if (bytes[i] == 0x4d && bytes[i+1] == 0x5a){
                int expr = i + IMAGE_DOS_HEADER_e_lfanew;
                
                int offset = 0;
                for(int j = 0; j < 4; j++){
                    offset += (bytes[expr+j] & 0x000000ff) << (j*8);
                }
                
                if(offset + i > bytes.length || offset + i < 0){
                    continue;
                }

                if (bytes[offset + i] == 0x50 && bytes[offset + i + 1] == 0x45){
                    int address = i + (smram.getAlign() - bytes.length);

                    offset += IMAGE_NT_HEADERS64_OptionalHeader;
                    int entryPoint = 0;
                    int size = 0;
                    for (int j = 0; j < 4; j++){
                        entryPoint += (bytes[i + offset + IMAGE_OPTIONAL_HEADER64_AddressOfEntryPoint + j] & 0x000000ff) << (j*8);
                        size += (bytes[i + offset + IMAGE_OPTIONAL_HEADER64_SizeOfImage + j] & 0x000000ff) << (j*8);
                    }
                    entryPoint = (entryPoint + i) + (smram.getAlign() - bytes.length);

                    String hash = findHash(entryPoint - smram.getSMRAMAddress());
                    smmDrivers.add(new SMMDriver(address, size, entryPoint, finder.getDriverName(hash)));
                }
            }
        }

        smram.setSMMDrivers(smmDrivers);
    }

    private void getSMMProtocols(){
        Integer firstEntry = null;
        byte[] bytes = smram.getSMRAMContent();

        for (int i = 0; i < bytes.length - 0x100; i+=4){
            if(bytes[i] == 0x70 && bytes[i+1] == 0x72 && bytes[i+2] == 0x74 && bytes[i+3] == 0x65){

                int flink = 0; 
                int blink = 0; 
                int info = 0;
                for(int j = 0; j < 4; j++){
                    flink += (bytes[i + 8 + j] & 0x000000ff) << (j*8);
                    blink += (bytes[i + 16 + j] & 0x000000ff) << (j*8);
                    info += (bytes[i + 40 + j] & 0x000000ff) << (j*8);
                }

                if(checkAddress(flink) && checkAddress(blink) && checkAddress(info)){
                    firstEntry = Integer.valueOf(i);
                    break;
                }
            }
        }

        if(firstEntry == null){
            return;
        } 

        ArrayList<SMMProtocol> protocols = new ArrayList<>();
        Integer entry = Integer.valueOf(firstEntry.intValue());

        do{
            int flink = 0; 
            int blink = 0; 
            int info = 0;
            for(int j = 0; j < 4; j++){
                flink += (bytes[entry + 8 + j] & 0x000000ff) << (j*8);
                blink += (bytes[entry + 16 + j] & 0x000000ff) << (j*8);
                info += (bytes[entry + 40 + j] & 0x000000ff) << (j*8);
            }

            if(!checkAddress(flink) || !checkAddress(blink)){
                return;
            }

            if(checkAddress(info)){
                int offset = info - smram.getSMRAMAddress();
                int tmp1 = 0;
                int tmp2 = 0;
                int tmp3 = 0;
                int addr = 0;

                for(int i = 0; i < 4; i++){
                    tmp1 += (bytes[offset + i] & 0x000000ff) << (i*8);
                    tmp2 += (bytes[offset + i + 8] & 0x000000ff) << (i*8);
                    tmp3 += (bytes[offset + i + 16] & 0x000000ff) << (i*8);
                    addr += (bytes[offset + i + 24] & 0x000000ff) << (i*8);
                }

                if(checkAddress(tmp1) && checkAddress(tmp2) && checkAddress(tmp3) && checkAddress(addr)){
                    String guid = parseGuid(bytes, entry);
                    protocols.add(new SMMProtocol(addr, guid, null));
                }
            }

            entry = flink - smram.getSMRAMAddress() - 8;
        } while(entry.intValue() != firstEntry.intValue());

        smram.setSMMProtocols(protocols);
    }

    private String parseGuid(byte[] bytes, int entry){
        int first = 0; //24-40
        for(int i = 0; i < 4; i++){ //24-27
            first += (bytes[entry + i + 24] & 0x000000ff) << (i*8);
        }

        short second = (short)((bytes[entry + 28] & 0x000000ff) + ((bytes[entry + 29] & 0x000000ff) << 8)); //28-29
    
        short third = (short)((bytes[entry + 30] & 0x000000ff) + ((bytes[entry + 31] & 0x000000ff) << 8)); //30-31

        short fourth = (short)((bytes[entry + 33] & 0x000000ff) + ((bytes[entry + 32] & 0x000000ff) << 8)); //32-33

        byte[] fifth = new byte[6];
        for(int i = 34; i < 40; i++){
            fifth[i - 34] = bytes[entry + i];
        }
        
        return String.format("%08x-%04x-%04x-%04x-%012x", first, second, third, fourth, new BigInteger(1, fifth));
    }

    private boolean checkAddress(int addr){
        return (addr >= smram.getSMRAMAddress()) && (addr <= (smram.getSMRAMAddress() + smram.getSMRAMContent().length));
    }

    private String findHash(int offset){
        byte[] toHash = GuidFinder.getByteArray(smram.getSMRAMContent(), offset);
        String hash = GuidFinder.getSHA512(toHash);
        return hash;
    }

    private void findSMST(){
        int smstPos = 0x5a;
        int smst = 0;

        for(int i = 0; i < 4; i++){
            smst += (smram.getSMRAMContent()[smstPos+i] & 0x000000ff) << (i*8);
        }
        smram.setSMSTAddress(smst);
    }

    private void findSMRAMAddress(){
        int smramAddress = smram.getAlign() - smram.getSMRAMContent().length;
        smram.setSMRAMAddress(smramAddress);
    }

    private void alignUp(){
        int align = (smram.getSMSTAddress() + 0x10000 - 1) & ~(0x10000 - 1);
        smram.setAlign(align);
    }

    public ArrayList<SMMDriver> getSmmDriversList(){
        return smram.getSMMDrivers();
    }

    public ArrayList<SMMProtocol> getSmmProtocolsList(){
        return smram.getSMMProtocols();
    }

    public void setSMRAMAdress(int address){
        smram.setSMRAMAddress(address);
    }

    public int getSMRAMAddress(){
        return smram.getSMRAMAddress();
    }

    public int getSMRAMDumpSize() {
    	return smram.getSMRAMContent().length;
    }
}