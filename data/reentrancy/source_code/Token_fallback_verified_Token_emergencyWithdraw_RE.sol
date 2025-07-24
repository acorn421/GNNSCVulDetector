/*
 * ===== SmartInject Injection Details =====
 * Function      : emergencyWithdraw
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 7 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction reentrancy vulnerability. The attack requires: 1) First transaction calls requestEmergencyWithdraw() to set up the state, 2) Second transaction calls emergencyWithdraw() which performs external call before updating state, allowing reentrancy to drain more funds than deposited. The vulnerability is stateful because it depends on the emergencyWithdrawRequests and emergencyWithdrawPending mappings persisting between transactions.
 */
// Copyright (C) 2017  The Halo Platform by Scott Morrison
// https://www.haloplatform.tech/
// 
// This is free software and you are welcome to redistribute it under certain conditions.
// ABSOLUTELY NO WARRANTY; for details visit:
//
//      https://www.gnu.org/licenses/gpl-2.0.html
//
pragma solidity ^0.4.18;

contract Ownable {
    address Owner;
    function Ownable() { Owner = msg.sender; }
    modifier onlyOwner { if (msg.sender == Owner) _; }
    function transferOwnership(address to) public onlyOwner { Owner = to; }
}

contract Token {
    function balanceOf(address who) constant public returns (uint256);
    function transfer(address to, uint amount) constant public returns (bool);
}

// tokens are withdrawable
contract TokenVault is Ownable {
    address owner;
    event TokenTransfer(address indexed to, address token, uint amount);
    
    function withdrawTokenTo(address token, address to) public onlyOwner returns (bool) {
        uint amount = balanceOfToken(token);
        if (amount > 0) {
            TokenTransfer(to, token, amount);
            return Token(token).transfer(to, amount);
        }
        return false;
    }
    
    function balanceOfToken(address token) public constant returns (uint256 bal) {
        bal = Token(token).balanceOf(address(this));
    }
}

// store ether & tokens for a period of time
contract EthVault is TokenVault {
    
    string public constant version = "v1.1";
    
    event Deposit(address indexed depositor, uint amount);
    event Withdrawal(address indexed to, uint amount);
    event OpenDate(uint date);

    mapping (address => uint) public Deposits;
    uint minDeposit;
    bool Locked;
    uint Date;

    // === FALLBACK INJECTION: Reentrancy ===
    // Mappings and functions must be declared here, as pragma 0.4.18 does not support in-function mapping declarations
    mapping (address => bool) public emergencyWithdrawRequests;
    mapping (address => uint) public emergencyWithdrawPending;
    
    function init() public payable open {
        Owner = msg.sender;
        minDeposit = 0.25 ether;
        Locked = false;
        deposit();
    }
    
    function requestEmergencyWithdraw(uint amount) public {
        require(Deposits[msg.sender] >= amount);
        emergencyWithdrawRequests[msg.sender] = true;
        emergencyWithdrawPending[msg.sender] = amount;
    }
    
    function emergencyWithdraw() public {
        require(emergencyWithdrawRequests[msg.sender]);
        require(emergencyWithdrawPending[msg.sender] > 0);
        
        uint amount = emergencyWithdrawPending[msg.sender];
        
        // Vulnerable: External call before state update
        msg.sender.call.value(amount)("");
        
        // State updates happen after external call (vulnerable to reentrancy)
        Deposits[msg.sender] -= amount;
        emergencyWithdrawRequests[msg.sender] = false;
        emergencyWithdrawPending[msg.sender] = 0;
        
        Withdrawal(msg.sender, amount);
    }
    // === END FALLBACK INJECTION ===

    function MinimumDeposit() public constant returns (uint) { return minDeposit; }
    function ReleaseDate() public constant returns (uint) { return Date; }
    function WithdrawEnabled() public constant returns (bool) { return Date > 0 && Date <= now; }

    function() public payable { deposit(); }

    function deposit() public payable {
        if (msg.value > 0) {
            if (msg.value >= MinimumDeposit())
                Deposits[msg.sender] += msg.value;
            Deposit(msg.sender, msg.value);
        }
    }

    function setRelease(uint newDate) public { 
        Date = newDate;
        OpenDate(Date);
    }

    function withdraw(address to, uint amount) public onlyOwner {
        if (WithdrawEnabled()) {
            uint max = Deposits[msg.sender];
            if (max > 0 && amount <= max) {
                to.transfer(amount);
                Withdrawal(to, amount);
            }
        }
    }

    function lock() public { if(Locked) revert(); Locked = true; }
    modifier open { if (!Locked) _; owner = msg.sender; deposit(); }
    function kill() public { require(this.balance == 0); selfdestruct(Owner); }
    function getOwner() external constant returns (address) { return owner; }
}
