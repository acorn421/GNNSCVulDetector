/*
 * ===== SmartInject Injection Details =====
 * Function      : takeOwnership
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the old owner before state updates. The vulnerability requires multiple transactions to exploit: 1) First transaction - attacker approves a malicious contract as owner, 2) Second transaction - the malicious contract calls takeOwnership, triggering the external call which re-enters to manipulate approvals before state updates complete, 3) Third transaction - exploits the inconsistent state created by the reentrancy. The approval clearing happens after the external call, creating a window where the attacker can manipulate the approval state across multiple transactions while the transfer is in progress.
 */
pragma solidity ^0.4.19;
contract ERC721 {
   string constant private tokenName = "ENCRYPTOART";
   string constant private tokenSymbol = "ENA";
   uint256 constant private totalTokens = 10000000000;
   mapping(address => uint) private balances;
   mapping(uint256 => address) private tokenOwners;
   mapping(uint256 => bool) private tokenExists;
   mapping(address => mapping (address => uint256)) private allowed;
   mapping(address => mapping(uint256 => uint256)) private ownerTokens;
   
   mapping(uint256 => string) tokenLinks;
   function name() public constant returns (string){
       return tokenName;
   }
   function symbol() public constant returns (string) {
       return tokenSymbol;
   }
   function totalSupply() public constant returns (uint256){
       return totalTokens;
   }
   function balanceOf(address _owner) constant returns (uint){
       return balances[_owner];
   }
   function ownerOf(uint256 _tokenId) constant returns (address){
       require(tokenExists[_tokenId]);
       return tokenOwners[_tokenId];
   }
   function approve(address _to, uint256 _tokenId){
       require(msg.sender == ownerOf(_tokenId));
       require(msg.sender != _to);
       allowed[msg.sender][_to] = _tokenId;
       emit Approval(msg.sender, _to, _tokenId);
   }
   function takeOwnership(uint256 _tokenId){
       require(tokenExists[_tokenId]);
       address oldOwner = ownerOf(_tokenId);
       address newOwner = msg.sender;
       require(newOwner != oldOwner);
       require(allowed[oldOwner][newOwner] == _tokenId);
       // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
       // External call to notify old owner before state updates
       if(isContract(oldOwner)) {
           oldOwner.call(bytes4(keccak256("onTokenTransfer(uint256)")), _tokenId);
       }
       // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
       balances[oldOwner] -= 1;
       tokenOwners[_tokenId] = newOwner;
       // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
       balances[newOwner] += 1;
       // Clear the approval after transfer
       allowed[oldOwner][newOwner] = 0;
       // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
       emit Transfer(oldOwner, newOwner, _tokenId);
   }
   function transfer(address _to, uint256 _tokenId){
       address currentOwner = msg.sender;
       address newOwner = _to;
       require(tokenExists[_tokenId]);
       require(currentOwner == ownerOf(_tokenId));
       require(currentOwner != newOwner);
       require(newOwner != address(0));
       require(allowed[currentOwner][newOwner] == _tokenId);
       balances[currentOwner] -= 1;
       tokenOwners[_tokenId] = newOwner;
       balances[newOwner] += 1;
       emit Transfer(currentOwner, newOwner, _tokenId);
   }
   function tokenOfOwnerByIndex(address _owner, uint256 _index) constant returns (uint tokenId){
       return ownerTokens[_owner][_index];
   }
   function tokenMetadata(uint256 _tokenId) constant returns (string infoUrl){
       return tokenLinks[_tokenId];
   }
   event Transfer(address indexed _from, address indexed _to, uint256 _tokenId);
   event Approval(address indexed _owner, address indexed _approved, uint256 _tokenId);
   
   // Helper function to check if an address is a contract
   function isContract(address addr) internal view returns (bool) {
       uint size;
       assembly { size := extcodesize(addr) }
       return size > 0;
   }
}
