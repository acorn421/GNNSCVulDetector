/*
 * ===== SmartInject Injection Details =====
 * Function      : customerDepositedEther
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a bonus payment mechanism that depends on accumulated totalDeposits state. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **State Accumulation Phase**: Multiple legitimate deposits must occur to reach the 10 ether threshold in totalDeposits
 * 2. **Vulnerability Activation**: Once threshold is reached, subsequent deposits trigger bonus calculations
 * 3. **Reentrancy Exploitation**: The external call (msg.sender.send) occurs before totalDeposits is updated, allowing recursive calls to:
 *    - Use the same old totalDeposits value for bonus calculations
 *    - Receive multiple bonuses in a single transaction
 *    - Drain contract funds through repeated reentrancy
 * 
 * The vulnerability is realistic because:
 * - Bonus systems are common in ICO contracts
 * - The calculation appears legitimate but has flawed ordering
 * - Requires accumulated state (totalDeposits ≥ 10 ether) from previous transactions
 * - Cannot be exploited in isolation - needs prior state buildup
 * - Uses natural contract balance as attack vector
 * 
 * Multi-transaction nature:
 * - Transaction 1-N: Build up totalDeposits to reach threshold
 * - Transaction N+1: Exploit reentrancy when bonus mechanism activates
 * - Each phase depends on persistent state changes from previous transactions
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

    function createNewDepositContract(uint256 number) onlyOwner {
        for (uint256 i = 0; i < number; i++) {
            ICODepositContract depositContract = new ICODepositContract(this);
            contracts.push(depositContract);
        }
    }

    function customerDepositedEther() payable {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Check if sender has accumulated enough deposits for bonus eligibility
        if (totalDeposits >= 10 ether) {
            // Send bonus to customer based on their contribution ratio
            uint256 bonusAmount = (msg.value * totalDeposits) / (totalDeposits + msg.value) / 100;
            if (bonusAmount > 0) {
                // External call before state update - vulnerable to reentrancy
                if (!msg.sender.send(bonusAmount)) throw;
            }
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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