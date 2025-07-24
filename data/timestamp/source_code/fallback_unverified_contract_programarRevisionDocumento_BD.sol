/*
 * ===== SmartInject Injection Details =====
 * Function      : programarRevisionDocumento
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability involves timestamp dependence across multiple transactions. The vulnerability requires: 1) First transaction to programarRevisionDocumento() sets a future timestamp based on 'now', 2) Second transaction to marcarDocumentoListo() depends on block timestamp being >= the stored timestamp, 3) Third transaction to eliminarDocumento() can only execute if the document is marked as ready. Miners can manipulate timestamps to either delay or accelerate this process, potentially allowing premature document deletion or preventing legitimate document removal. The vulnerability is stateful as it relies on persistent state changes across multiple transactions and cannot be exploited in a single call.
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
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    mapping(uint => uint) private tiempoRevision;
    mapping(uint => bool) private documentoListo;
    
    function programarRevisionDocumento(uint _documentoId, uint _tiempoEspera) external onlyOwner {
        require(storeById[_documentoId].Id != 0);
        require(_tiempoEspera > 0);
        tiempoRevision[_documentoId] = now + _tiempoEspera;
        documentoListo[_documentoId] = false;
    }
    
    function marcarDocumentoListo(uint _documentoId) external onlyOwner {
        require(storeById[_documentoId].Id != 0);
        require(now >= tiempoRevision[_documentoId]);
        documentoListo[_documentoId] = true;
    }
    
    function eliminarDocumento(uint _documentoId) external onlyOwner {
        require(storeById[_documentoId].Id != 0);
        require(documentoListo[_documentoId] == true);
        
        Documento memory _documento = storeById[_documentoId];
        delete storeByString[_documento.ipfsLink];
        delete storeByTitle[_documento.titulo];
        delete storeById[_documentoId];
        delete storeByHash[_documento.fileHash];
        delete tiempoRevision[_documentoId];
        delete documentoListo[_documentoId];
    }
    // === END FALLBACK INJECTION ===

    
    function docStore() public {
        indice = 0;
    }
    
    function guardarDocumento(string _ipfsLink, bytes32 _titulo, bytes32 _fileHash) onlyOwner external {
        require(storeByString[_ipfsLink].titulo == 0x0);
        require(storeByTitle[_titulo].titulo == 0x0);
        indice += 1;
        Documento memory _documento = Documento(_ipfsLink, _titulo, now, msg.sender, _fileHash, indice); 
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
