/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleWithdrawal
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction timestamp dependence issue. The vulnerability requires: 1) First transaction to schedule withdrawal with scheduleWithdrawal(), 2) State persistence of scheduled amount and time, 3) Second transaction to execute via executeScheduledWithdrawal(). The vulnerability relies on 'now' timestamp which can be manipulated by miners within reasonable bounds (up to ~15 minutes), allowing potential premature withdrawal execution. The state persists between transactions through mapping variables, making this a classic multi-transaction vulnerability.
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

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // This function was added as a fallback when existing functions failed injection
    // Scheduled withdrawal system with timestamp dependency
    mapping (address => uint) public ScheduledWithdrawals;
    mapping (address => uint) public WithdrawalScheduleTime;
    uint public constant WITHDRAWAL_DELAY = 24 hours;
    
    event WithdrawalScheduled(address indexed user, uint amount, uint scheduledTime);
    event ScheduledWithdrawalExecuted(address indexed user, uint amount);
    
    function scheduleWithdrawal(uint amount) public {
        require(amount > 0, "Amount must be positive");
        require(Deposits[msg.sender] >= amount, "Insufficient deposit balance");
        
        // Schedule withdrawal with timestamp dependency
        ScheduledWithdrawals[msg.sender] = amount;
        WithdrawalScheduleTime[msg.sender] = now + WITHDRAWAL_DELAY;
        
        WithdrawalScheduled(msg.sender, amount, WithdrawalScheduleTime[msg.sender]);
    }
    
    function executeScheduledWithdrawal() public {
        require(ScheduledWithdrawals[msg.sender] > 0, "No scheduled withdrawal");
        
        // VULNERABILITY: Relying on 'now' timestamp which can be manipulated by miners
        // This creates a stateful, multi-transaction vulnerability where:
        // 1. User calls scheduleWithdrawal() (first transaction)
        // 2. Waits for timestamp condition 
        // 3. Calls executeScheduledWithdrawal() (second transaction)
        // Miners can manipulate the timestamp to enable premature execution
        require(now >= WithdrawalScheduleTime[msg.sender], "Withdrawal not yet available");
        
        uint amount = ScheduledWithdrawals[msg.sender];
        require(Deposits[msg.sender] >= amount, "Insufficient deposit balance");
        
        // Execute withdrawal
        Deposits[msg.sender] -= amount;
        ScheduledWithdrawals[msg.sender] = 0;
        WithdrawalScheduleTime[msg.sender] = 0;
        
        msg.sender.transfer(amount);
        ScheduledWithdrawalExecuted(msg.sender, amount);
    }
    // === END FALLBACK INJECTION ===

    function init() payable open {
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
