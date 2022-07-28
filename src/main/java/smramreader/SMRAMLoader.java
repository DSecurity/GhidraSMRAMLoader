/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package smramreader;

import smramreader.parser.SMRAMDumpReader;
import smramreader.smram.SMMDriver;
import smramreader.smram.SMMProtocol;

import java.io.IOException;
import java.util.*;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class SMRAMLoader extends AbstractLibrarySupportLoader {
	
	public SMRAMLoader() {}

	@Override
	public String getName() {

		// TODO: Name the loader.  This name must match the name of the loader in the .opinion 
		// files.

		return "SMRAM Loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		BinaryReader reader = new BinaryReader(provider, true);	
		//read the signature of dump; it must be SMMS3_64
		if(reader.readAsciiString(0x0, 8).equals("SMMS3_64")) {
			
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("x86:LE:64:default", "windows"), true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		
		if (monitor.isCancelled()) {
			return;
		}
		
		FileBytes fileBytes = MemoryBlockUtils.createFileBytes(program, provider, monitor);
		FlatProgramAPI api = new FlatProgramAPI(program,monitor);
		Memory memory = program.getMemory();
		try {
			
			System.out.println();
			SMRAMDumpReader reader = new SMRAMDumpReader(provider.getAbsolutePath());
			
			setMemoryMap(reader, program, memory, fileBytes, api);
			
			if (monitor.isCancelled()) {
				return;
			}
			
			analyse(reader, api);
			
			if (monitor.isCancelled()) {
				return;
			}
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public void analyse(SMRAMDumpReader reader, FlatProgramAPI api) {
		for (SMMDriver driver : reader.getSmmDriversList()) {
            Address entry = api.toAddr(driver.getEntryPoint());
            api.addEntryPoint(entry);
            api.disassemble(entry);
		}
		
		for(SMMProtocol protocol : reader.getSmmProtocolsList()) {
			try {
				defineData(api.toAddr(protocol.getAddress()), protocol.getGUID(), null, api);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	
	public void createIntermediateSMRAMBlock(SMRAMDumpReader reader, Memory memory, SMMDriver driver, FlatProgramAPI api, FileBytes fileBytes, int i) 
													throws LockException, IllegalArgumentException, MemoryConflictException, AddressOverflowException {
    	int offset = driver.getAddress() + driver.getSize() - reader.getSMRAMAddress();
    	SMMDriver nextDriver = reader.getSmmDriversList().get(i+1);
    	int addrNext = nextDriver.getAddress();
    	int addrEndOfDr = driver.getAddress() + driver.getSize();
    	int length = addrNext - addrEndOfDr;
    	MemoryBlock padding = memory.createInitializedBlock("SMRAM_BLOCK_"+i, api.toAddr(driver.getAddress()+driver.getSize()), fileBytes, offset, length, false);
    	padding.setPermissions(true, true, false);
	}
	
	public void setMemoryMap(SMRAMDumpReader reader, Program program, Memory memory, FileBytes fileBytes, FlatProgramAPI api) 
								throws LockException, MemoryConflictException{
		for (int i = 0; i < reader.getSmmDriversList().size(); i++){
			SMMDriver driver = reader.getSmmDriversList().get(i);
			
			try {
				int TransactionID = program.startTransaction("Mapping smm driver");   
				int offset = driver.getAddress() - reader.getSMRAMAddress();
				MemoryBlock block = memory.createInitializedBlock(driver.getName(), api.toAddr(driver.getAddress()), fileBytes, offset, driver.getSize(), false);
	            block.setPermissions(true, true, true);
	            
	            if (i == 0) {
	            	
	            	MemoryBlock padding = memory.createInitializedBlock("SMRAM_BLOCK_START", api.toAddr(reader.getSMRAMAddress()), fileBytes, 0, 
	            							driver.getAddress() - reader.getSMRAMAddress(), false);
	            	padding.setPermissions(true, true, false);
	            	createIntermediateSMRAMBlock(reader, memory, driver, api, fileBytes, i);
	            	
	            } else if (i + 1 == reader.getSmmDriversList().size()) {
	            	
	            	offset = driver.getAddress() + driver.getSize() - reader.getSMRAMAddress();
	            	int length = reader.getSMRAMDumpSize() - offset;
	            	MemoryBlock padding = memory.createInitializedBlock("SMRAM_BLOCK_END", api.toAddr(driver.getAddress()+driver.getSize()), fileBytes, offset, length, false);
	            	padding.setPermissions(true, true, false);
	            	
	            } else {
	            	
	            	createIntermediateSMRAMBlock(reader, memory, driver, api, fileBytes, i);
	      
	            }
				program.endTransaction(TransactionID, true);
			} catch (IllegalArgumentException | AddressOverflowException e) {          
		          e.printStackTrace();
		    }
		}
	
	}
	
	
	
	private void defineData(Address address, String name, String comment, FlatProgramAPI api) throws Exception {		
		boolean primary = true;
		
		SymbolTable symbolTable = api.getCurrentProgram().getSymbolTable();
		for (Symbol symbol : symbolTable.getSymbols(address)) {
			if (symbol.getSource() != SourceType.USER_DEFINED) {
				symbolTable.removeSymbolSpecial(symbol);
			}
			else {
				primary = false;
			}
		}

		//api.createData(address, dataType);

		if (name != null) {
			api.createLabel(address, name, primary, SourceType.IMPORTED);
		}

		if (comment != null) {
			api.setPlateComment(address, comment);
		}
	}
	
	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
		//list.add(new Option("Option name goes here", "Default option value goes here"));
			
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
