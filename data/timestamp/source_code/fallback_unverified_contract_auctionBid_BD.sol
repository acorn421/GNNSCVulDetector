/*
 * ===== SmartInject Injection Details =====
 * Function      : auctionBid
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction timestamp dependence vulnerability in an auction system. The vulnerability requires multiple transactions to exploit: 1) A malicious miner can start an auction, 2) Wait for legitimate bids, 3) Manipulate the timestamp to either extend the auction (allowing more bids) or end it prematurely (preventing legitimate bidders from participating). The vulnerability is stateful because it depends on the auction state (auctionEndTime, highestBid, auctionActive) that persists across transactions. The exploitation requires the attacker to be a miner who can manipulate block timestamps within the allowed range (not smaller than previous block, not too far in future).
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

   // === FALLBACK INJECTION: Timestamp Dependence ===
   // Auction state variables
   mapping(uint256 => address) private highestBidder;
   mapping(uint256 => uint256) private highestBid;
   mapping(uint256 => uint256) private auctionEndTime;
   mapping(uint256 => bool) private auctionActive;
   mapping(uint256 => mapping(address => uint256)) private pendingReturns;

   // Start auction for a token
   function startAuction(uint256 _tokenId, uint256 _duration, uint256 _startingBid) public {
       require(tokenExists[_tokenId]);
       require(msg.sender == ownerOf(_tokenId));
       require(!auctionActive[_tokenId]);
       auctionActive[_tokenId] = true;
       auctionEndTime[_tokenId] = now + _duration;
       highestBid[_tokenId] = _startingBid;
       highestBidder[_tokenId] = msg.sender;
   }
   // Place a bid on a token - vulnerable to timestamp manipulation
   function auctionBid(uint256 _tokenId) public payable {
       require(tokenExists[_tokenId]);
       require(auctionActive[_tokenId]);
       require(now <= auctionEndTime[_tokenId]); // VULNERABLE
       require(msg.value > highestBid[_tokenId]);
       if (highestBidder[_tokenId] != address(0)) {
           pendingReturns[_tokenId][highestBidder[_tokenId]] = highestBid[_tokenId];
       }
       highestBidder[_tokenId] = msg.sender;
       highestBid[_tokenId] = msg.value;
   }
   // End auction and transfer token - vulnerable to timestamp manipulation
   function endAuction(uint256 _tokenId) public {
       require(tokenExists[_tokenId]);
       require(auctionActive[_tokenId]);
       require(now > auctionEndTime[_tokenId]); // VULNERABLE
       auctionActive[_tokenId] = false;
       address winner = highestBidder[_tokenId];
       address oldOwner = ownerOf(_tokenId);
       if (winner != oldOwner) {
           balances[oldOwner] -= 1;
           tokenOwners[_tokenId] = winner;
           balances[winner] += 1;
           Transfer(oldOwner, winner, _tokenId);
       }
   }
   // Withdraw failed bids
   function withdrawBid(uint256 _tokenId) public {
       uint256 amount = pendingReturns[_tokenId][msg.sender];
       require(amount > 0);
       pendingReturns[_tokenId][msg.sender] = 0;
       msg.sender.transfer(amount);
   }
   // === END FALLBACK INJECTION ===

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
       Approval(msg.sender, _to, _tokenId);
   }
   function takeOwnership(uint256 _tokenId){
       require(tokenExists[_tokenId]);
       address oldOwner = ownerOf(_tokenId);
       address newOwner = msg.sender;
       require(newOwner != oldOwner);
       require(allowed[oldOwner][newOwner] == _tokenId);
       balances[oldOwner] -= 1;
       tokenOwners[_tokenId] = newOwner;
       balances[newOwner] += 1;
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
