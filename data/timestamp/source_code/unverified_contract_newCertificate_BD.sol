/*
 * ===== SmartInject Injection Details =====
 * Function      : newCertificate
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a multi-transaction timestamp dependence vulnerability through time-based certificate activation and rate limiting logic. The vulnerability involves:
 * 
 * 1. **Time-based Certificate Activation**: Certificates have an activation delay calculated using block.timestamp + 3600, making them dependent on miner-manipulable timestamps.
 * 
 * 2. **Rate Limiting with Timestamp Comparison**: The function checks if the same issuer created a certificate within the last 10 minutes using block.timestamp arithmetic, which is vulnerable to miner manipulation.
 * 
 * 3. **Variable Activation Time**: For issuers who recently created certificates, the activation time is calculated using `block.timestamp + (block.timestamp % 300)`, creating a modular dependency on the current timestamp that miners can influence.
 * 
 * **Multi-Transaction Exploitation Scenario**:
 * - **Transaction 1**: Attacker creates an initial certificate, establishing their timestamp baseline in the system state
 * - **Transaction 2+**: Attacker collaborates with miners or exploits timestamp manipulation to create subsequent certificates with favorable activation times by manipulating the block.timestamp used in the rate limiting calculation
 * 
 * **Why Multi-Transaction is Required**:
 * - The vulnerability requires existing state (previous certificates from the same issuer) to trigger the timestamp-dependent rate limiting logic
 * - The exploit depends on the accumulated state of previous certificate issuances stored in the certificates mapping
 * - Single transaction exploitation is impossible because the rate limiting check requires at least one prior certificate to exist in state
 * 
 * **Exploitation Vector**:
 * Miners can manipulate block.timestamp within the allowed 900-second window to:
 * 1. Bypass rate limiting by making old certificates appear older than 600 seconds
 * 2. Control the variable activation delay calculation to create certificates that activate immediately or at advantageous times
 * 3. Game the system across multiple transactions to create certificates with predictable activation patterns
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based certificate activation: certificates become valid only after 1 hour from creation
        uint256 activationTime = block.timestamp + 3600; // 1 hour delay
        
        // Rate limiting: prevent rapid certificate creation by same issuer (anti-spam mechanism)
        // Check if issuer created a certificate in the last 10 minutes (600 seconds)
        if (numCerts > 1) {
            for (uint i = numCerts; i >= 1; i--) {
                if (certificates[i].issuer_addr == msg.sender) {
                    // Vulnerable: Using block.timestamp for time comparison without considering miner manipulation
                    if (block.timestamp - certificates[i].issuance_time < 600) {
                        // Override the normal issuance time with activation time for "premium" certificates
                        // This creates a timing dependency that can be exploited
                        activationTime = block.timestamp + (block.timestamp % 300); // Variable delay based on timestamp
                    }
                    break;
                }
            }
        }
        
        // Creates new struct and saves in storage using the potentially manipulated activation time
        certificates[certID] = Certificate(certHash,msg.sender,beneficiary, version,content,false,activationTime);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        certHashKey[certHash]=certificates[certID];
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