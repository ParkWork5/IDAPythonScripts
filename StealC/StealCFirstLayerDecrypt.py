import ida_kernwin
import ida_idaapi
import ida_segment
import ida_funcs
import idc
import idautils
import ida_segment
from collections import namedtuple

def GrabValuesViaHops(address,hops):  # Will grab a value X hops up from the address provided
    
    if(hops == 0):
        currentInstruction = idautils.DecodeInstruction(address) # Gets the instruction at the memory address
        currentValue = currentInstruction.Op1.value  # Gets the value at the memory address. Note number of opcode bytes must be set to 5 in general settings 
        currentContents = get_strlit_contents(currentValue) # Gets String of value
        return currentContents        
    
    for i in range(0,hops,1):
        currentAddress= idc.prev_head(address)
        address = currentAddress
    
    currentInstruction = idautils.DecodeInstruction(address)    
    currentValue = currentInstruction.Op1.value
    currentContents = get_strlit_contents(currentValue) 
    
        
    if(currentContents == None and len(str(currentValue)) != 7):
        return currentValue 
    elif(currentContents == None and len(str(currentValue)) == 7): # If a memory address is reutrned  
        return idc.get_operand_value(currentValue,0) #  This grabs a value from somewhere and I am not sure why it works
        
    return currentContents

def GrabPriorAddress(address, hops):

    if(hops == 0):
        return address        
    for i in range(0,hops,1): # Gets address based on how many hops up
        currentAddress= idc.prev_head(address)        
        address = currentAddress
    
    return currentAddress

def FunctionRefMap(address): # Gets a list of memory addresses with references to function at an address

    functionReferences = list()
    seg = ida_segment.getseg(address) # Gets segment where functions live
    
    for ref in idautils.XrefsTo(address): # Gets all references to a function at an address
        functionReferences.append(ref.frm) 
    
    return functionReferences

def AddressCheck(address,hops,references): # Checks if the current address has a reference to a current function
    
    priorAddress = GrabPriorAddress(address,hops)
    
    for i in references:
        if(priorAddress == i):
            return 1
    return 0

def DetermineMaxHops(baseAddress,references): # Determines max number of hops before hitting other function call
    hops=0
    i=0
    # Added two hardcoded calls based on the functions being the first call of the sub routine
    
    if baseAddress == 0x4029ac or baseAddress == 0x402d9d: 
        return 3
    while i != 1:
        currentAddress= idc.prev_head(baseAddress)
        
        for x in references:
            if(currentAddress == x):
                return hops 
        hops = hops + 1
        baseAddress = currentAddress
    
    print("No upper bounds found for function")
    return 0

def ChunkCheck(chunk):
    numCount = 0
    stringCount = 0
    zeroCount = 0
    
    if(len(chunk) <= 3): # If chunk is less then 3 values then it does not have minimum number of arguements for decrypt funct
        return 0
    for i in chunk:
        if(type(i) == int):
            numCount = numCount + 1
            if(i == 0):
                zeroCount = zeroCount + 1
        elif(type(i) == bytes):
            stringCount = stringCount + 1
    if(stringCount != 2): # If there are not two strings then decrypt funct will not work 
        return 0
    if((len(chunk) - zeroCount) <= 2): # If only zero values are found in a chunk then it is not valid
        return 0
    return 1
    

def ByteLengthCheck(chunk):
    # Compares length of byte array to ints. The valid int will eq the length of byte array.
    byteLength=0
    
    for i in chunk:
        if(type(i) == bytes):
            byteLength=len(i)
    for i in chunk:
        if(type(i) == int):
            if(i == byteLength):
                return 1  
    return 0
                  
def ChunkSorting(chunk):
       DecryptChunk = namedtuple('DecryptChunk',['secretString','key','keyLength'])
      
       secretString = ""
       key = ""
       keyLength = 0
       bytesTrigger = 0
       for y in chunk:
           if(type(y) == int):
            if(y == 0):
                pass  
            else:
                for x in chunk:
                    if(type(x) == bytes): 
                        byteLength=len(x)
                for x in chunk: # Ensure correct key length is saved based on byte string length. Multiple ints can exist.
                    if(x == byteLength):
                        keyLength = x
           elif(type(y) == bytes):
            if(bytesTrigger == 0):
                key = y  # Based on the order of args in Ida the Key will come first then the secretString
                bytesTrigger=1
            elif(bytesTrigger == 1):
                secretString = y
       sortedChunk = DecryptChunk(secretString,key,keyLength)
       
       return sortedChunk
def DecryptFunction(secretString,key,keyLength):
    foundWord = ""
    for i in range(0,keyLength,1):
        foundLetter = chr(secretString[i] ^key[i % len(key)]) # Does the xor operation
        foundWord = foundWord + foundLetter
    print(foundWord)
    print ("#################################")
               
                
          
def main():

    idaapi.msg_clear() # Clear screen
    ea = 0x00404980 # Address of decrypt function
    functionReferences=FunctionRefMap(ea)
    
    
    
    for ref in idautils.XrefsTo(ea): # For each reference to the function
        maxHops = DetermineMaxHops(ref.frm,functionReferences) # Determine the max number of hops
        foundValues = list()
        validChunks = list()
        for h in range(0,maxHops+1,1): # +1 is because the counter for the hops includes the function address so, a +1 is needed to offset that
            currentAddress=GrabPriorAddress(ref.frm,h) # Get the current address based on X hops back from an address
            if(AddressCheck(currentAddress,h,functionReferences)):# If the address stores a Decrypt function call then pass if not grab value
                pass
            else:
                foundValue=GrabValuesViaHops(ref.frm,h)
                foundValues.append(foundValue)
        
        if(ChunkCheck(foundValues)): # Both functions screen against to make sure only the valid chunk gets decrypted
            if(ByteLengthCheck(foundValues)):
                sortedChunk = ChunkSorting(foundValues)
                DecryptFunction(sortedChunk.secretString, sortedChunk.key,sortedChunk.keyLength)
                
main()

