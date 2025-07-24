/*
 * ===== SmartInject Injection Details =====
 * Function      : setTimedWithdrawalWindow
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
 * This vulnerability introduces a timestamp dependence issue where the withdrawal window validation is incomplete. The vulnerability requires multiple transactions: first to request withdrawal during the valid window, then to execute withdrawal. However, the executeWithdrawal function only checks if the current time is after the window start, not if the window is still open. This allows users to execute withdrawals even after the window has closed, and miners can manipulate timestamps to exploit this timing inconsistency across multiple transactions.
 */
pragma solidity ^0.4.8;

// ----------------------------------------------------------------------------------------------
// Unique ICO deposit contacts for customers to deposit ethers that are sent to different
// wallets
//
// Enjoy. (c) Bok Consulting Pty Ltd & Incent Rewards 2017. The MIT Licence.
// ----------------------------------------------------------------------------------------------

contract Owned {
    address public owner;
    event OwnershipTransferred(address indexed _from, address indexed _to);

    function Owned() {
        owner = msg.sender;
    }

    modifier onlyOwner {
        if (msg.sender != owner) throw;
        _;
    }

    function transferOwnership(address newOwner) onlyOwner {
        OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}

contract ICODepositContract {
    uint256 public totalDeposit;
    ICOCustomerDeposit public customerDeposit;

    function ICODepositContract(ICOCustomerDeposit _customerDeposit) {
        customerDeposit = _customerDeposit;
    }

    function () payable {
        totalDeposit += msg.value;
        customerDeposit.customerDepositedEther.value(msg.value)();
    }
}

contract ICOCustomerDeposit is Owned {
    uint256 public totalDeposits;
    ICODepositContract[] public contracts;

    event Deposit(address indexed _from, uint _value);

    // Define destination addresses
    // 0.5%
    address incentToCustomer = 0xa5f93F2516939d592f00c1ADF0Af4ABE589289ba;
    // 0.5%
    address icoFees = 0x38671398aD25461FB446A9BfaC2f4ED857C86863;
    // 99%
    address icoClientWallet = 0x994B085D71e0f9a7A36bE4BE691789DBf19009c8;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    uint256 public withdrawalWindowStart;
    uint256 public withdrawalWindowDuration = 24 hours;
    mapping(address => uint256) public pendingWithdrawals;

    // Allow owner to set a withdrawal window based on block timestamp
    function setTimedWithdrawalWindow(uint256 _startTime, uint256 _duration) onlyOwner {
        withdrawalWindowStart = _startTime;
        withdrawalWindowDuration = _duration;
    }
    
    // First transaction: Request withdrawal during the time window
    function requestWithdrawal(uint256 amount) {
        if (now < withdrawalWindowStart || now > withdrawalWindowStart + withdrawalWindowDuration) {
            throw;
        }
        pendingWithdrawals[msg.sender] = amount;
    }
    
    // Second transaction: Execute withdrawal after window validation
    function executeWithdrawal() {
        uint256 amount = pendingWithdrawals[msg.sender];
        if (amount == 0) throw;
        
        // Vulnerable: Only checks if current time is after window start, not if window is still open
        if (now >= withdrawalWindowStart) {
            pendingWithdrawals[msg.sender] = 0;
            if (!msg.sender.send(amount)) throw;
        }
    }
    // === END FALLBACK INJECTION ===

    function createNewDepositContract(uint256 number) onlyOwner {
        for (uint256 i = 0; i < number; i++) {
            ICODepositContract depositContract = new ICODepositContract(this);
            contracts.push(depositContract);
        }
    }

    function customerDepositedEther() payable {
        totalDeposits += msg.value;
        uint256 value1 = msg.value * 1 / 200;
        if (!incentToCustomer.send(value1)) throw;
        uint256 value2 = msg.value * 1 / 200;
        if (!icoFees.send(value2)) throw;
        uint256 value3 = msg.value - value1 - value2;
        if (!icoClientWallet.send(value3)) throw;
        Deposit(msg.sender, msg.value);
    }

    // Prevent accidental sending of ethers
    function () {
        throw;
    }
}
