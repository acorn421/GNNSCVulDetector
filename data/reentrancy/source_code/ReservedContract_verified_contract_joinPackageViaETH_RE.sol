/*
 * ===== SmartInject Injection Details =====
 * Function      : joinPackageViaETH
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Tracking**: Introduced userContributions mapping to track accumulated contributions across multiple transactions
 * 2. **Replaced Safe Transfer**: Changed from safe transfer() to vulnerable call.value() that allows reentrancy
 * 3. **State Updates After External Call**: Moved critical state updates (totalContributions, lastContributor) to occur after the external call
 * 4. **Multi-Transaction Exploitation Pattern**: 
 *    - Transaction 1: Attacker calls function, userContributions is updated, external call triggers malicious contract
 *    - Transaction 2: During reentry, attacker can exploit inconsistent state where userContributions shows contribution but totalContributions hasn't been updated
 *    - Transaction 3+: Further exploitation through accumulated userContributions state
 * 
 * The vulnerability requires multiple transactions because:
 * - The attacker needs to first establish a contribution record in userContributions
 * - The external call allows reentry where state is inconsistent
 * - The exploit depends on accumulated state from previous transactions
 * - Multiple calls are needed to build up sufficient state to make the attack profitable
 * 
 * This creates a realistic vulnerability where the contract state becomes inconsistent across multiple transactions, allowing attackers to exploit the difference between per-user and global state tracking.
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
    
    // Added missing state variables (fix):
    mapping (address => uint) public userContributions;
    uint public totalContributions;
    address public lastContributor;

    // admin function
    modifier onlyOwner() {
        require (msg.sender == owner);
        _;
    }

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
    constructor () payable public{
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add accumulated contribution tracking
        userContributions[msg.sender] += msg.value;
        
        // External call before state finalization - vulnerable to reentrancy
        bool success = _reserve20.call.value(msg.value * 20 / 100)("");
        require(success);
        
        // State updates after external call
        totalContributions += msg.value;
        lastContributor = msg.sender;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
