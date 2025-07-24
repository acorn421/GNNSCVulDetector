/*
 * ===== SmartInject Injection Details =====
 * Function      : takeOwnership
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by adding time-based approval expiration and transfer cooldown mechanisms. The vulnerability requires multiple transactions to exploit: first, an approval must be set with a timestamp, then the takeOwnership function relies on block.timestamp for critical timing logic that miners can manipulate. The vulnerability stores timestamps in state variables (approvalTimestamps, lastTransferTime) that persist between transactions, making it stateful and requiring sequential operations to exploit. Miners can manipulate block.timestamp within ~15 second windows to bypass the 1-day approval expiration or 1-hour cooldown restrictions.
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
   // ===== Added missing state variables for vulnerability logic =====
   mapping(address => mapping(address => uint256)) private approvalTimestamps;
   mapping(uint256 => uint256) private lastTransferTime;

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
       // ========== PRESERVE VULNERABILITY: also store approval timestamp ==========
       approvalTimestamps[msg.sender][_to] = block.timestamp;
       Approval(msg.sender, _to, _tokenId);
   }
   function takeOwnership(uint256 _tokenId){
       require(tokenExists[_tokenId]);
       address oldOwner = ownerOf(_tokenId);
       address newOwner = msg.sender;
       require(newOwner != oldOwner);
       require(allowed[oldOwner][newOwner] == _tokenId);
       // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
       uint256 approvalTime = approvalTimestamps[oldOwner][newOwner];
       uint256 timeElapsed = block.timestamp - approvalTime;
       require(timeElapsed <= 86400); // 1 day expiration
       uint256 lastTransfer = lastTransferTime[_tokenId];
       require(block.timestamp >= lastTransfer + 3600);
       lastTransferTime[_tokenId] = block.timestamp;
       // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
       balances[oldOwner] -= 1;
       tokenOwners[_tokenId] = newOwner;
       // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
       balances[newOwner] += 1;
       // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
       Transfer(oldOwner, newOwner, _tokenId);
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
       Transfer(currentOwner, newOwner, _tokenId);
   }
   function tokenOfOwnerByIndex(address _owner, uint256 _index) constant returns (uint tokenId){
       return ownerTokens[_owner][_index];
   }
   function tokenMetadata(uint256 _tokenId) constant returns (string infoUrl){
       return tokenLinks[_tokenId];
   }
   event Transfer(address indexed _from, address indexed _to, uint256 _tokenId);
   event Approval(address indexed _owner, address indexed _approved, uint256 _tokenId);
}