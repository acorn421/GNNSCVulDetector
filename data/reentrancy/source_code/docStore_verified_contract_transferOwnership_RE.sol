/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability in the transferOwnership function. The vulnerability involves:
 * 
 * 1. **State Persistence**: Added mapping `pendingOwnershipTransfers` and variables `pendingNewOwner`, `transferInitiatedAt` to track transfer state across transactions
 * 
 * 2. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Current owner calls `transferOwnership(maliciousContract)` 
 *    - **Transaction 2**: The malicious contract's `onOwnershipTransferRequested` callback is triggered
 *    - **Transaction 3**: During callback, malicious contract can re-enter and call other owner-only functions while ownership is in intermediate state
 * 
 * 3. **Reentrancy Window**: The external call `newOwner.call()` occurs before the ownership state is fully updated, creating a vulnerability window where:
 *    - The pending state indicates a transfer is in progress
 *    - The callback can re-enter the contract while state is inconsistent
 *    - The malicious contract can exploit this intermediate state
 * 
 * 4. **Multi-Transaction Requirement**: The vulnerability requires:
 *    - Initial transfer request (creates pending state)
 *    - Callback execution (triggers reentrancy opportunity)  
 *    - State accumulated from previous calls enables exploitation in subsequent transactions
 * 
 * 5. **Realistic Pattern**: The notification callback mechanism is a common pattern in ownership transfers, making this vulnerability realistic and subtle.
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

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => bool) private pendingOwnershipTransfers;
    address private pendingNewOwner;
    uint256 private transferInitiatedAt;
    
    function transferOwnership(address newOwner) public onlyOwner {
        if (newOwner != address(this)) {
            // First transaction: Initiate transfer and notify new owner
            if (!pendingOwnershipTransfers[newOwner]) {
                pendingOwnershipTransfers[newOwner] = true;
                pendingNewOwner = newOwner;
                transferInitiatedAt = now;
                
                // External call to notify new owner before state update
                if (newOwner.call(bytes4(keccak256("onOwnershipTransferRequested(address)")), msg.sender)) {
                    // Callback succeeded, but ownership not yet transferred
                }
                
                // State update after external call - creates reentrancy window
                owner = newOwner;
                
                // Reset pending state
                pendingOwnershipTransfers[newOwner] = false;
                pendingNewOwner = address(0);
            }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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