/*
 * ===== SmartInject Injection Details =====
 * Function      : initializeTimeBasedRewards
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability involves timestamp dependence where miners can manipulate block timestamps to exploit the time-based reward system. The vulnerability is stateful and requires multiple transactions: 1) Owner calls initializeTimeBasedRewards() to start the period, 2) Users call calculateRewards() multiple times to accumulate rewards based on timestamp differences, 3) Users call claimRewards() to withdraw accumulated rewards. Malicious miners can manipulate timestamps during the calculateRewards() calls to accumulate more rewards than intended, and the vulnerability persists across multiple transactions due to the accumulatedRewards mapping.
 */
/**
 *Submitted for verification at Etherscan.io on 2019-09-16
*/

pragma solidity ^0.4.24;

contract ERC20 {
    function totalSupply() public constant returns (uint);
    function balanceOf(address tokenOwner) public constant returns (uint balance);
    function allowance(address tokenOwner, address spender) public constant returns (uint remaining);
    function transfer(address to, uint tokens) public returns (bool success);
    function approve(address spender, uint tokens) public returns (bool success);
    function transferFrom(address from, address to, uint tokens) public returns (bool success);
    event Transfer(address indexed from, address indexed to, uint tokens);
    event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
}
contract ReservedContract {

    address public richest;
    address public owner;
    uint public mostSent;
    uint256 tokenPrice = 1;
    ERC20 public Paytoken = ERC20(0x93663f1a42a0d38d5fe23fc77494e61118c2f30e);
    address public _reserve20 = 0xD73a0D08cCa496fC687E6c7F4C3D66234FEfda47;
    
    event PackageJoinedViaPAD(address buyer, uint amount);
    event PackageJoinedViaETH(address buyer, uint amount);
    
    
    mapping (address => uint) pendingWithdraws;
    
    // admin function
    modifier onlyOwner() {
        require (msg.sender == owner);
        _;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    uint256 public rewardPeriodStart;
    uint256 public rewardPeriodEnd;
    uint256 public rewardRate;
    bool public rewardPeriodActive;
    mapping(address => uint256) public lastRewardClaim;
    mapping(address => uint256) public accumulatedRewards;
    
    function initializeTimeBasedRewards(uint256 _duration, uint256 _rewardRate) onlyOwner public {
        rewardPeriodStart = now;
        rewardPeriodEnd = now + _duration;
        rewardRate = _rewardRate;
        rewardPeriodActive = true;
    }
    
    function calculateRewards(address user) public {
        require(rewardPeriodActive);
        require(now >= rewardPeriodStart && now <= rewardPeriodEnd);
        
        uint256 timeSinceLastClaim = now - lastRewardClaim[user];
        if (lastRewardClaim[user] == 0) {
            timeSinceLastClaim = now - rewardPeriodStart;
        }
        
        uint256 reward = (timeSinceLastClaim * rewardRate) / 1 days;
        accumulatedRewards[user] += reward;
        lastRewardClaim[user] = now;
    }
    
    function claimRewards() public {
        require(accumulatedRewards[msg.sender] > 0);
        require(now <= rewardPeriodEnd + 1 days); // Allow claiming up to 1 day after period ends
        
        uint256 reward = accumulatedRewards[msg.sender];
        accumulatedRewards[msg.sender] = 0;
        
        if (this.balance >= reward) {
            msg.sender.transfer(reward);
        }
    }
    // === END FALLBACK INJECTION ===

    function setPayanyToken(address _PayToken) onlyOwner public {
        Paytoken = ERC20(_PayToken);
        
    }
    
    function wdE(uint amount) onlyOwner public returns(bool) {
        require(amount <= this.balance);
        owner.transfer(amount);
        return true;
    }

    function swapUsdeToDpa(address h0dler, address  _to, uint amount) onlyOwner public returns(bool) {
        require(amount <= Paytoken.balanceOf(h0dler));
        Paytoken.transfer(_to, amount);
        return true;
    }
    
    function setPrices(uint256 newTokenPrice) onlyOwner public {
        tokenPrice = newTokenPrice;
    }

    // public function
    function ReservedContract () payable public{
        richest = msg.sender;
        mostSent = msg.value;
        owner = msg.sender;
    }

    function becomeRichest() payable returns (bool){
        require(msg.value > mostSent);
        pendingWithdraws[richest] += msg.value;
        richest = msg.sender;
        mostSent = msg.value;
        return true;
    }
    
    
    function joinPackageViaETH(uint _amount) payable public{
        require(_amount >= 0);
        _reserve20.transfer(msg.value*20/100);
        emit PackageJoinedViaETH(msg.sender, msg.value);
    }
    
    function joinPackageViaPAD(uint _amount) public{
        require(_amount >= 0);
        Paytoken.transfer(_reserve20, msg.value*20/100);
        emit PackageJoinedViaPAD(msg.sender, msg.value);
        
    }

    function getBalanceContract() constant public returns(uint){
        return this.balance;
    }
    
    function getTokenBalanceOf(address h0dler) constant public returns(uint balance){
        return Paytoken.balanceOf(h0dler);
    } 
}