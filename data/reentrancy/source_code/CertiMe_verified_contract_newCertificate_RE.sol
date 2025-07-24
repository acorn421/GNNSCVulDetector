/*
 * ===== SmartInject Injection Details =====
 * Function      : newCertificate
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call**: Inserted a call to the beneficiary address using `beneficiary.call()` to notify them of certificate creation
 * 2. **Moved Critical State Update**: Relocated the `certHashKey` mapping update to occur AFTER the external call, violating the Checks-Effects-Interactions pattern
 * 3. **Created Reentrancy Window**: The external call creates a window where the beneficiary can re-enter the contract before the `certHashKey` mapping is updated
 * 
 * **Multi-Transaction Exploitation Path:**
 * 
 * **Transaction 1 (Setup):** 
 * - Attacker deploys a malicious contract as the beneficiary
 * - Calls `newCertificate()` with the malicious contract as beneficiary
 * - During the external call, the malicious contract can call `newCertificate()` again
 * 
 * **Transaction 2-N (Exploitation):**
 * - In the reentrant calls, `numCerts` continues to increment
 * - Multiple certificates get created with sequential IDs
 * - However, the `certHashKey` mappings are only updated after ALL reentrant calls complete
 * - This creates inconsistent state where `certificates` mapping has entries but `certHashKey` doesn't
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: Each reentrant call increments `numCerts` and creates new certificate entries
 * 2. **Delayed Consistency**: The `certHashKey` updates only happen after the full call chain completes
 * 3. **Persistent Impact**: The inconsistent state persists across transactions, allowing later exploitation of functions that depend on `certHashKey` lookups
 * 4. **Sequential Dependency**: The vulnerability's impact grows with each successive reentrant call
 * 
 * **Exploitation Impact:**
 * - Certificate hash lookups via `certHashKey` will fail for certificates created during reentrancy
 * - Functions like `getCertsByProof()` will not find certificates that should exist
 * - The attacker can create "hidden" certificates that exist in the main mapping but not in the hash key mapping
 */
pragma solidity ^0.4.11;

contract CertiMe {
    // Defines a new type with two fields.
    struct Certificate {
        string certHash;
        address issuer_addr;
        address recepient_addr;
        string version;
        string content;
        bool isRevoked;
        uint256 issuance_time;
    }

    uint numCerts;
    mapping (uint => Certificate) public certificates;
    mapping (string => Certificate) certHashKey;

    function newCertificate(address beneficiary, string certHash, string version, string content ) public returns (uint certID) {
        certID = ++numCerts; // campaignID is return variable
        // Creates new struct and saves in storage. We leave out the mapping type.
        certificates[certID] = Certificate(certHash,msg.sender,beneficiary, version,content,false,block.timestamp);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify beneficiary of certificate creation - VULNERABILITY: External call before final state update
        if(beneficiary.call(bytes4(keccak256("onCertificateCreated(uint256)")), certID)) {
            // External call succeeded, proceed with final state update
        }
        
        certHashKey[certHash]=certificates[certID]; // VULNERABILITY: Critical state update after external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
    
    function arraySum(uint[] arr) internal pure returns (uint){
        uint len= 0;
        for(uint i=0;i<arr.length;i++){
            len+=arr[i];
        }
        return len;
    }
    function getCharacterCount(string str) pure internal returns (uint length)    {
        uint i=0;
        bytes memory string_rep = bytes(str);
    
        while (i<string_rep.length)
        {
            if (string_rep[i]>>7==0)
                i+=1;
            else if (string_rep[i]>>5==0x6)
                i+=2;
            else if (string_rep[i]>>4==0xE)
                i+=3;
            else if (string_rep[i]>>3==0x1E)
                i+=4;
            else
                //For safety
                i+=1;
    
            length++;
        }
    }    
    function batchNewCertificate(address[] beneficiaries, string certHash, string version, string content,uint[] certHashChar, uint[] versionChar,uint[] contentChar) public returns (uint[]) {
        //require(beneficiaries.length==certHashChar.length);
        //require(versionChar.length==certHashChar.length);    
        //require(versionChar.length==contentChar.length);        
        //uint log=getCharacterCount(version);
        //require(arraySum(versionChar)==getCharacterCount(version));             
        //require(arraySum(certHashChar)==getCharacterCount(certHash));        
        //require(arraySum(contentChar)==getCharacterCount(content));        

        
        uint certHashCharSteps=0;
        uint versionCharSteps=0;
        uint contentCharSteps=0;
        
        uint[] memory certID = new uint[](beneficiaries.length);
        for (uint i=0;i<beneficiaries.length;i++){
            certID[i]=newCertificate(
                beneficiaries[i],
                substring(certHash,certHashCharSteps,(certHashCharSteps+certHashChar[i])),
                substring(version,versionCharSteps,(versionCharSteps+versionChar[i])),
                substring(content,contentCharSteps,(contentCharSteps+contentChar[i]))
            );
            
            certHashCharSteps+=certHashChar[i];
            versionCharSteps+=versionChar[i];
            contentCharSteps+=contentChar[i];
            
        }
        return certID;
    }
        
    function revokeCertificate(uint targetCertID) public returns (bool){
        if(msg.sender==certificates[targetCertID].issuer_addr){
            certificates[targetCertID].isRevoked=true;
            return true;
        }else{
            return false;
        }
    }
/*
    function contribute(uint campaignID) public payable {
        Campaign storage c = campaigns[campaignID];
        // Creates a new temporary memory struct, initialised with the given values
        // and copies it over to storage.
        // Note that you can also use Funder(msg.sender, msg.value) to initialise.
        c.funders[c.numFunders++] = CertIssuer({addr: msg.sender, amount: msg.value});
        c.amount += msg.value;
    }
*/
  /*  
    function certHashExist(string value) constant returns (uint) {
        for (uint i=1; i<numCerts+1; i++) {
              if(stringsEqual(certificates[i].certHash,value)){
                return i;
              }
        }
        
        return 0;
    }*/
    function getMatchCountAddress(uint addr_type,address value) public constant returns (uint){
        uint counter = 0;
        for (uint i=1; i<numCerts+1; i++) {
              if((addr_type==0&&certificates[i].issuer_addr==value)||(addr_type==1&&certificates[i].recepient_addr==value)){
                counter++;
              }
        }        
        return counter;
    }
    function getCertsByIssuer(address value) public constant returns (uint[]) {
        uint256[] memory matches=new uint[](getMatchCountAddress(0,value));
        uint matchCount=0;
        for (uint i=1; i<numCerts+1; i++) {
              if(certificates[i].issuer_addr==value){
                matches[matchCount++]=i;
              }
        }
        
        return matches;
    }
    function getCertsByRecepient(address value) public constant returns (uint[]) {
        uint256[] memory matches=new uint[](getMatchCountAddress(1,value));
        uint matchCount=0;
        for (uint i=1; i<numCerts+1; i++) {
              if(certificates[i].recepient_addr==value){
                matches[matchCount++]=i;
              }
        }
        
        return matches;
    }   

    function getMatchCountString(uint string_type,string value) public constant returns (uint){
        uint counter = 0;
        for (uint i=1; i<numCerts+1; i++) {
              if(string_type==0){
                if(stringsEqual(certificates[i].certHash,value)){
                    counter++;
                }
              }
              if(string_type==1){
                if(stringsEqual(certificates[i].version,value)){
                    counter++;
                }
              }
              if(string_type==2){
                if(stringsEqual(certificates[i].content,value)){
                    counter++;
                }
              }
        }        
        return counter;
    }
    
    function getCertsByProof(string value) public constant returns (uint[]) {
        uint256[] memory matches=new uint[](getMatchCountString(0,value));
        uint matchCount=0;
        for (uint i=1; i<numCerts+1; i++) {
              if(stringsEqual(certificates[i].certHash,value)){
                matches[matchCount++]=i;
              }
        }
        
        return matches;
    }    
    function getCertsByVersion(string value) public constant returns (uint[]) {
        uint256[] memory matches=new uint[](getMatchCountString(1,value));
        uint matchCount=0;
        for (uint i=1; i<numCerts+1; i++) {
              if(stringsEqual(certificates[i].version,value)){
                matches[matchCount++]=i;
              }
        }
        
        return matches;
    }
    function getCertsByContent(string value) public constant returns (uint[]) {
        uint256[] memory matches=new uint[](getMatchCountString(2,value));
        uint matchCount=0;
        for (uint i=1; i<numCerts+1; i++) {
              if(stringsEqual(certificates[i].content,value)){
                matches[matchCount++]=i;
              }
        }
        
        return matches;
    }
    
/*    function getCertIssuer(string key) constant returns (address,address,string,string) {
         return (certHashKey[key].issuer_addr,certHashKey[key].recepient_addr,certHashKey[key].version,certHashKey[key].content);
    }
*/
    
	function stringsEqual(string storage _a, string memory _b) internal constant returns (bool) {
		bytes storage a = bytes(_a);
		bytes memory b = bytes(_b);
		if (a.length != b.length)
			return false;
		// @todo unroll this loop
		for (uint i = 0; i < a.length; i ++)
			if (a[i] != b[i])
				return false;
		return true;
	} 
	
	function substring(string str, uint startIndex, uint endIndex) internal pure returns (string) {
        bytes memory strBytes = bytes(str);
        bytes memory result = new bytes(endIndex-startIndex);
        for(uint i = startIndex; i < endIndex; i++) {
            result[i-startIndex] = strBytes[i];
        }
        return string(result);
    }
    
}