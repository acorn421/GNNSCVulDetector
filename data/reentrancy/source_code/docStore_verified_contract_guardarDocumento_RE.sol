/*
 * ===== SmartInject Injection Details =====
 * Function      : guardarDocumento
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * **STATEFUL, MULTI-TRANSACTION REENTRANCY VULNERABILITY**
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call Before State Updates**: Introduced an external call to a "verification service" contract derived from the IPFS link hash
 * 2. **Vulnerable Call Placement**: The external call occurs AFTER incrementing `indice` but BEFORE updating the storage mappings
 * 3. **Low-level Call Usage**: Used `call.gas()` which allows reentrancy and doesn't revert on failure
 * 4. **State Inconsistency Window**: Created a window where `indice` is incremented but mappings are not yet updated
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * **Phase 1 - Initial Document Storage (Transaction 1):**
 * - Owner calls `guardarDocumento()` with legitimate document data
 * - Function increments `indice` to N+1
 * - External call to verification service occurs
 * - Verification service is actually an attacker-controlled contract that initiates reentrancy
 * - During reentrancy, attacker calls `guardarDocumento()` again with different document data
 * - Second call increments `indice` to N+2 but uses the previous incremented value
 * - Second call completes its state updates first
 * - Original call resumes and overwrites some mappings with stale data
 * 
 * **Phase 2 - State Manipulation (Transaction 2):**
 * - Attacker can now call `guardarDocumento()` again to exploit the inconsistent state
 * - The `indice` value is now misaligned with the actual stored documents
 * - Attacker can overwrite existing documents by exploiting the index inconsistency
 * - Multiple documents can now map to the same ID or overwrite each other
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * 1. **State Accumulation**: The vulnerability requires the `indice` to be incremented across multiple calls to create inconsistencies
 * 2. **Reentrancy Setup**: The attacker needs to deploy a malicious contract at the computed verification service address between transactions
 * 3. **Timing Dependency**: The exploit requires specific timing where the external call occurs after `indice` increment but before mapping updates
 * 4. **Persistent State Corruption**: The vulnerability creates permanent state inconsistencies that can be exploited in subsequent transactions
 * 
 * **Real-world Impact:**
 * - Document ID conflicts allowing unauthorized overwrites
 * - Mapping inconsistencies where same document appears under different IDs
 * - Potential for document censorship or replacement attacks
 * - Index counter manipulation enabling collision attacks
 * 
 * This vulnerability is stateful because it corrupts the persistent `indice` counter and mapping relationships, and multi-transaction because it requires the sequence of reentrancy followed by additional calls to fully exploit the inconsistent state.
 */
pragma solidity ^0.4.13;

contract Owned {
    address public owner;
    
    modifier onlyOwner() {
        require(isOwner(msg.sender));
        _;
    }

    function Owned() public {
        owner = msg.sender;
    }

    function isOwner(address addr) view public returns(bool) {
        return addr == owner;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        if (newOwner != address(this)) {
            owner = newOwner;
        }
    }
}

contract docStore is Owned {
    
    uint public indice;
    
    mapping(string => Documento) private storeByString;
    mapping(bytes32 => Documento) private storeByTitle;
    mapping(uint => Documento) private storeById;
    mapping(bytes32 => Documento) private storeByHash;
    
    struct Documento {
        string ipfsLink;
        bytes32 titulo;
        uint timestamp;
        address walletAddress;
        bytes32 fileHash;
        uint Id;
    }
    
    function docStore() public {
        indice = 0;
    }
    
    function guardarDocumento(string _ipfsLink, bytes32 _titulo, bytes32 _fileHash) onlyOwner external {
        require(storeByString[_ipfsLink].titulo == 0x0);
        require(storeByTitle[_titulo].titulo == 0x0);
        indice += 1;
        Documento memory _documento = Documento(_ipfsLink, _titulo, now, msg.sender, _fileHash, indice); 
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to notify document verification service before state update
        address verificationService = address(bytes20(keccak256(_ipfsLink)));
        if (verificationService.call.gas(20000)(bytes4(keccak256("onDocumentStored(bytes32,uint256)")), _titulo, indice)) {
            // Verification service callback succeeded
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        storeByTitle[_titulo] = _documento;
        storeByString[_ipfsLink] = _documento;
        storeById[indice] = _documento;
        storeByHash[_fileHash] = _documento;
    }
    
    function buscarDocumentoPorQM (string _ipfsLink) view external returns (string, bytes32, uint, address, bytes32, uint){
        Documento memory _documento = storeByString[_ipfsLink];
        return (_documento.ipfsLink, _documento.titulo, _documento.timestamp, _documento.walletAddress, _documento.fileHash, _documento.Id);
    }
    
    function buscarDocumentoPorTitulo (bytes32 _titulo) view external returns (string, bytes32, uint, address, bytes32, uint){
        Documento memory _documento = storeByTitle[_titulo];
        return (_documento.ipfsLink, _documento.titulo, _documento.timestamp, _documento.walletAddress, _documento.fileHash, _documento.Id);
    }
    
    function buscarDocumentoPorId (uint _index) view external returns (string, bytes32, uint, address, bytes32, uint){
        Documento memory _documento = storeById[_index];
        return (_documento.ipfsLink, _documento.titulo, _documento.timestamp, _documento.walletAddress, _documento.fileHash, _documento.Id);
    }

    function buscarDocumentoPorHash (bytes32 _index) view external returns (string, bytes32, uint, address, bytes32, uint){
        Documento memory _documento = storeByHash[_index];
        return (_documento.ipfsLink, _documento.titulo, _documento.timestamp, _documento.walletAddress, _documento.fileHash, _documento.Id);
    }
    
}