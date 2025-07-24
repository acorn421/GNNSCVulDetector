/*
 * ===== SmartInject Injection Details =====
 * Function      : guardarDocumento
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a timestamp-dependent priority system where documents submitted within 24 hours of the first document receive higher priority based on their submission time. The vulnerability allows miners to manipulate block.timestamp to artificially increase document priority. This is a multi-transaction vulnerability because: 1) The first transaction establishes the time window baseline, 2) Subsequent transactions can exploit timestamp manipulation to gain unfair priority, 3) The vulnerability accumulates over multiple document submissions, creating a stateful exploit that persists across transactions. An attacker (miner) could manipulate timestamps in later blocks to make their documents appear as if they were submitted closer to the first document's timestamp, gaining higher priority in the system.
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        
        // Time-based document priority system vulnerable to timestamp manipulation
        uint priority = 1; // Default priority
        
        // Check if this is submitted within 24 hours of the first document
        if (indice > 0) {
            Documento memory firstDoc = storeById[1];
            uint timeWindow = 24 hours;
            
            // Documents submitted within the time window get higher priority
            if (now <= firstDoc.timestamp + timeWindow) {
                // Priority increases based on how close to the first document's timestamp
                priority = ((firstDoc.timestamp + timeWindow) - now) / 3600 + 1; // Priority 1-25
            }
        }
        
        indice += 1;
        
        // Create documento with timestamp-dependent priority
        Documento memory _documento = Documento(_ipfsLink, _titulo, now, msg.sender, _fileHash, indice);
        
        // Store priority in unused bits of fileHash for this example
        // In a real implementation, this would be a separate field
        bytes32 priorityHash = bytes32(uint256(_fileHash) | (priority << 248));
        _documento.fileHash = priorityHash;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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