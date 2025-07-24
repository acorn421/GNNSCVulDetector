/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
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
 * Introduced a two-phase ownership transfer mechanism using block.timestamp for delay validation. The function now requires two separate transactions: first to initiate the transfer with a timestamp, and second to complete it after a specified delay period. The vulnerability lies in the use of block.timestamp which can be manipulated by miners within a 900-second window, allowing them to bypass the intended security delay by manipulating timestamps across multiple blocks. State variables (ownershipTransferPending, pendingOwner, ownershipTransferTimestamp, ownershipTransferDelay) persist between transactions, making this a stateful vulnerability that requires multiple transaction calls to exploit. Miners can manipulate block.timestamp in the first transaction to set an earlier timestamp, then manipulate it again in subsequent transactions to meet the delay requirement prematurely.
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

    address public pendingOwner;
    bool public ownershipTransferPending;
    uint256 public ownershipTransferTimestamp;
    uint256 public ownershipTransferDelay = 1 days;

    function Owned() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        if (msg.sender != owner) throw;
        _;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        if (ownershipTransferPending) {
            // Complete the ownership transfer if enough time has passed
            if (block.timestamp >= ownershipTransferTimestamp + ownershipTransferDelay) {
                OwnershipTransferred(owner, pendingOwner);
                owner = pendingOwner;
                ownershipTransferPending = false;
                pendingOwner = address(0);
                ownershipTransferTimestamp = 0;
            }
        } else {
            // Initiate ownership transfer with timestamp-based delay
            pendingOwner = newOwner;
            ownershipTransferPending = true;
            ownershipTransferTimestamp = block.timestamp;
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
}

contract ICODepositContract {
    uint256 public totalDeposit;
    ICOCustomerDeposit public customerDeposit;

    function ICODepositContract(ICOCustomerDeposit _customerDeposit) public {
        customerDeposit = _customerDeposit;
    }

    function () public payable {
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
    address public incentToCustomer = 0xa5f93F2516939d592f00c1ADF0Af4ABE589289ba;
    // 0.5%
    address public icoFees = 0x38671398aD25461FB446A9BfaC2f4ED857C86863;
    // 99%
    address public icoClientWallet = 0x994B085D71e0f9a7A36bE4BE691789DBf19009c8;

    function createNewDepositContract(uint256 number) onlyOwner public {
        for (uint256 i = 0; i < number; i++) {
            ICODepositContract depositContract = new ICODepositContract(this);
            contracts.push(depositContract);
        }
    }

    function customerDepositedEther() public payable {
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
    function () public {
        throw;
    }
}