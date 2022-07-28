package smramreader.parser;

import smramreader.org.json.simple.parser.*;
import smramreader.org.json.simple.JSONObject;

import java.math.BigInteger;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.security.MessageDigest;
import java.util.HashMap;

public class GuidFinder {
    private HashMap<String, String> guids;

    public void findAllGuids(String inputFile){
        guids = new HashMap<>();
        StringBuilder path = new StringBuilder(inputFile);
        path.replace(path.indexOf(".bin"), path.length(), ".json");
        String file = path.toString();
        
        if(new File(file).exists()) {
	        JSONParser jsonParser = new JSONParser();
	        try (FileReader reader = new FileReader(path.toString())){
	            JSONObject obj = (JSONObject)jsonParser.parse(reader);
	            for(Object key : obj.keySet()){
	                guids.put((String)obj.get(key), (String)key);
	            }
	        } catch (FileNotFoundException e) {
	            e.printStackTrace();
	        } catch (IOException e) {
	            e.printStackTrace();
	        } catch (ParseException e) {
	            e.printStackTrace();
	        }
        }
    }

    public String getDriverName(String key){
        if(guids.containsKey(key)){
            return guids.get(key);
        }
		return "Undefined_SMM_Driver.efi";
    }

    public void clearGuidFinder(){
        guids.clear();
    }

    public void printMap(){
        for(String key : guids.keySet()){
            System.out.println(key + " : " + guids.get(key));
        }
    }

    public static byte[] getByteArray(byte[] bytes, int offset){
        byte[] result = new byte[200];

        for(int i = 0; i < result.length; i++){
            result[i] = bytes[offset + i];
        }

        return result;
    }

    public static String getSHA512(byte[] bytes){
        String toReturn = null;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            toReturn = String.format("%0128x", new BigInteger(1, digest.digest(bytes)));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return toReturn;
    }
}
