/*
 * ===== SmartInject Injection Details =====
 * Function      : init
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a registry contract before state is fully settled. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to a registry contract using low-level `call()` before the `deposit()` function
 * 2. The external call occurs after critical state variables are set but before the initialization is complete
 * 3. The call passes user-controlled data (msg.sender and msg.value) to the external contract
 * 
 * **Multi-Transaction Exploitation Path:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract at the registry address that implements `notifyInitialization()`
 * 2. **Transaction 2**: Attacker calls `init()` with ETH, triggering the external call to their malicious registry
 * 3. **During Transaction 2**: The malicious registry's `notifyInitialization()` function calls back to `init()` again
 * 4. **State Confusion**: The second `init()` call executes with partially initialized state from the first call
 * 5. **Result**: Multiple owners can be set, deposits can be duplicated, or the contract can be left in an inconsistent state
 * 
 * **Why Multi-Transaction is Required:**
 * - The attacker must first deploy their malicious registry contract (Transaction 1)
 * - Then they can exploit the reentrancy when calling init() (Transaction 2)
 * - The vulnerability relies on the persistent state changes from the first init() call being incomplete when the second call occurs
 * - The `open` modifier's state changes persist between the reentrant calls, enabling the exploitation
 * 
 * **Stateful Nature:**
 * - The `Owner`, `minDeposit`, and `Locked` state variables are modified before the external call
 * - These state changes persist and affect the behavior of subsequent reentrant calls
 * - The `open` modifier also modifies state that can be exploited across multiple calls
 * - The vulnerability creates a race condition where initialization state is inconsistent across transactions
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

    function init() payable open {
        Owner = msg.sender;
        minDeposit = 0.25 ether;
        Locked = false;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify external registry before completing initialization
        if (msg.value > 0) {
            address registry = 0x1234567890123456789012345678901234567890; // External registry
            (bool success, ) = registry.call(abi.encodeWithSignature("notifyInitialization(address,uint256)", msg.sender, msg.value));
            require(success, "Registry notification failed");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        deposit();
    }
    
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