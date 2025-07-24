/*
 * ===== SmartInject Injection Details =====
 * Function      : deposit
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 4 findings
 * Total Found   : 10 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 * ... and 1 more
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback to the depositor before updating the Deposits mapping. This creates a classic reentrancy vulnerability where:
 * 
 * 1. **Multi-Transaction Setup**: An attacker must first deploy a malicious contract and then call deposit() from it, requiring at least 2 separate transactions.
 * 
 * 2. **State Persistence Exploitation**: The vulnerability leverages the persistent Deposits mapping state. The attacker can:
 *    - Transaction 1: Deploy malicious contract
 *    - Transaction 2: Call deposit() from the malicious contract
 *    - During the callback, the malicious contract can re-enter deposit() before the Deposits mapping is updated
 *    - This allows the attacker to receive multiple deposit credits for a single payment
 * 
 * 3. **Stateful Nature**: The vulnerability depends on the accumulated state in the Deposits mapping across multiple transactions. Each successful re-entrant call adds to the attacker's balance without requiring additional payment.
 * 
 * 4. **Realistic Pattern**: The callback mechanism is disguised as a legitimate deposit notification system, making it appear as a feature rather than a vulnerability.
 * 
 * The vulnerability violates the Checks-Effects-Interactions pattern by performing the external call (interaction) before the state update (effect), creating the reentrancy window that can be exploited across multiple function calls within the same transaction context.
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
    function Ownable() public { Owner = msg.sender; } // updated visibility
    modifier onlyOwner { if (msg.sender == Owner) _; }
    function transferOwnership(address to) public onlyOwner { Owner = to; }
}

contract Token {
    function balanceOf(address who) public constant returns (uint256);
    function transfer(address to, uint amount) public returns (bool); // removed constant (transfer can't be constant)
}

// tokens are withdrawable
contract TokenVault is Ownable {
    address owner;
    event TokenTransfer(address indexed to, address token, uint amount);
    
    function withdrawTokenTo(address token, address to) public onlyOwner returns (bool) {
        uint amount = balanceOfToken(token);
        if (amount > 0) {
            emit TokenTransfer(to, token, amount); // add 'emit' prefix
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

    function init() public payable open { // add public visibility
        Owner = msg.sender;
        minDeposit = 0.25 ether;
        Locked = false;
        deposit();
    }
    
    function MinimumDeposit() public constant returns (uint) { return minDeposit; }
    function ReleaseDate() public constant returns (uint) { return Date; }
    function WithdrawEnabled() public constant returns (bool) { return Date > 0 && Date <= now; }

    function() public payable { deposit(); }

    function deposit() public payable {
        if (msg.value > 0) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            if (msg.value >= MinimumDeposit()) {
                // Notify external contract of deposit before state update
                if (extcodesize(msg.sender) > 0) { // fix: use extcodesize
                    /* solium-disable-next-line security/no-low-level-calls */
                    msg.sender.call(
                        abi.encodeWithSignature("onDeposit(uint256)", msg.value)
                    );
                    // Continue regardless of callback success
                }
                Deposits[msg.sender] += msg.value;
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            emit Deposit(msg.sender, msg.value); // add 'emit' prefix
        }
    }
    // extcodesize helper for <0.5.0
    function extcodesize(address _addr) internal view returns (uint256 size) {
        assembly { size := extcodesize(_addr) }
    }

    function setRelease(uint newDate) public { 
        Date = newDate;
        emit OpenDate(Date); // add 'emit'
    }

    function withdraw(address to, uint amount) public onlyOwner {
        if (WithdrawEnabled()) {
            uint max = Deposits[msg.sender];
            if (max > 0 && amount <= max) {
                to.transfer(amount);
                emit Withdrawal(to, amount); // add 'emit'
            }
        }
    }

    function lock() public { if(Locked) revert(); Locked = true; }
    modifier open { if (!Locked) _; owner = msg.sender; deposit(); }
    function kill() public { require(this.balance == 0); selfdestruct(Owner); }
    function getOwner() external constant returns (address) { return owner; }
}