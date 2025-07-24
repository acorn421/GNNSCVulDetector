/*
 * ===== SmartInject Injection Details =====
 * Function      : requestWithdrawal
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * This creates a stateful, multi-transaction reentrancy vulnerability. The vulnerability requires: 1) First transaction to call requestWithdrawal() to set up pending withdrawal state, 2) Second transaction to call processWithdrawal() which makes external call before updating state. An attacker can exploit this by having their fallback function recursively call processWithdrawal() before the state is cleared, allowing multiple withdrawals of the same amount.
 */
pragma solidity ^0.4.11;

contract ERC20 {
    function transfer(address to, uint tokens) public returns (bool success);
}

contract owned {
    address public owner;

    function owned() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}

library SafeMath {
    function mul(uint a, uint b) internal pure returns (uint) {
        uint c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function div(uint a, uint b) internal pure returns (uint) {
        uint c = a / b;
        return c;
    }

    function sub(uint a, uint b) internal pure returns (uint) {
        assert(b <= a);
        return a - b;
    }

    function add(uint a, uint b) internal pure returns (uint) {
        uint c = a + b;
        assert(c >= a);
        return c;
    }

    function max64(uint64 a, uint64 b) internal pure returns (uint64) {
        return a >= b ? a : b;
    }

    function min64(uint64 a, uint64 b) internal pure returns (uint64) {
        return a < b ? a : b;
    }

    function max256(uint256 a, uint256 b) internal pure returns (uint256) {
        return a >= b ? a : b;
    }

    function min256(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }
}

contract RocketsICO is owned {
    using SafeMath for uint;
    bool public ICOOpening = true;
    uint256 public USD;
    uint256 public ICORate = 1;
    uint256 public ICOBonus = 0;
    address public ROK = 0xca2660F10ec310DF91f3597574634A7E51d717FC;

    // === FALLBACK INJECTION: Reentrancy ===
    // Moved the mapping declarations outside the function for valid syntax
    mapping(address => uint256) public pendingWithdrawals;
    mapping(address => bool) public withdrawalProcessing;

    function updateUSD(uint256 usd) onlyOwner public {
        USD = usd;
    }
    
    function requestWithdrawal(uint256 amount) public {
        require(amount > 0, "Amount must be greater than 0");
        require(pendingWithdrawals[msg.sender] == 0, "Previous withdrawal still pending");
        // Check if user has sufficient balance (simplified check)
        pendingWithdrawals[msg.sender] = amount;
    }
    
    function processWithdrawal() public {
        require(pendingWithdrawals[msg.sender] > 0, "No pending withdrawal");
        require(!withdrawalProcessing[msg.sender], "Withdrawal already being processed");
        uint256 amount = pendingWithdrawals[msg.sender];
        withdrawalProcessing[msg.sender] = true;
        // External call before state update - vulnerable to reentrancy
        msg.sender.call.value(amount)("");
        // State updates after external call - this is the vulnerability
        pendingWithdrawals[msg.sender] = 0;
        withdrawalProcessing[msg.sender] = false;
    }
    // === END FALLBACK INJECTION ===

    function updateRate(uint256 rate, uint256 bonus) onlyOwner public {
        ICORate = rate;
        ICOBonus = bonus;
    }

    function updateOpen(bool opening) onlyOwner public{
        ICOOpening = opening;
    }

    function RocketsICO() public {
        // constructor
    }

    function() public payable {
        buy();
    }

    function getAmountToBuy(uint256 ethAmount) public view returns (uint256){
        uint256 tokensToBuy;
        tokensToBuy = ethAmount.div(10 ** 18).mul(USD).mul(ICORate);
        if(ICOBonus > 0){
            uint256 bonusAmount;
            bonusAmount = tokensToBuy.div(100).mul(ICOBonus);
            tokensToBuy = tokensToBuy.add(bonusAmount);
        }
        return tokensToBuy;
    }

    function buy() public payable {
        require(ICOOpening == true);
        uint256 tokensToBuy;
        uint256 ethAmount = msg.value;
        tokensToBuy = ethAmount.div(10 ** 18).mul(USD).mul(ICORate);
        if(ICOBonus > 0){
            uint256 bonusAmount;
            bonusAmount = tokensToBuy.div(100).mul(ICOBonus);
            tokensToBuy = tokensToBuy.add(bonusAmount);
        }
        ERC20(ROK).transfer(msg.sender, tokensToBuy);
    }

    function withdrawROK(uint256 amount, address sendTo) onlyOwner public {
        ERC20(ROK).transfer(sendTo, amount);
    }

    function withdrawEther(uint256 amount, address sendTo) onlyOwner public {
        address(sendTo).transfer(amount);
    }

    function withdrawToken(ERC20 token, uint256 amount, address sendTo) onlyOwner public {
        require(token.transfer(sendTo, amount));
    }
}