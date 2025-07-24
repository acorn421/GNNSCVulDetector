/*
 * ===== SmartInject Injection Details =====
 * Function      : createNewDepositContract
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a contractRegistry before updating the contracts array. The vulnerability is exploitable through the following multi-transaction sequence:
 * 
 * **Transaction 1 (Setup)**: 
 * - Attacker deploys a malicious contract implementing the registry interface
 * - Attacker calls a setter function (not shown but would exist) to set their malicious contract as the contractRegistry
 * - This establishes the attack surface for future transactions
 * 
 * **Transaction 2-N (Exploitation)**:
 * - Owner calls createNewDepositContract(n) 
 * - During the loop, the external call to contractRegistry.notifyContractCreated() occurs BEFORE contracts.push()
 * - The malicious registry contract reenters createNewDepositContract() during the notification
 * - This creates inconsistent state where some contracts are created but not yet added to the contracts array
 * - Multiple reentrant calls can manipulate the contract creation process and the contracts array state
 * - The vulnerability accumulates over multiple transactions as the contracts array grows inconsistently
 * 
 * **Why Multi-Transaction**:
 * 1. **State Accumulation**: Each transaction adds to the contracts array, creating growing state that can be manipulated
 * 2. **Setup Phase Required**: The malicious registry must be set in a prior transaction  
 * 3. **Persistent State Corruption**: The inconsistent state between contract creation and array updates persists between transactions
 * 4. **Sequential Exploitation**: Each subsequent call to createNewDepositContract builds upon the corrupted state from previous calls
 * 
 * The vulnerability requires multiple transactions because the attacker must first establish the malicious registry, then exploit the reentrancy across multiple contract creation cycles to fully compromise the system state.
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

    function Owned() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        if (msg.sender != owner) throw;
        _;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}

contract IContractRegistry {
    function notifyContractCreated(address _contract) public;
}

contract ICODepositContract {
    uint256 public totalDeposit;
    ICOCustomerDeposit public customerDeposit;

    function ICODepositContract(ICOCustomerDeposit _customerDeposit) public {
        customerDeposit = _customerDeposit;
    }

    function () payable public {
        totalDeposit += msg.value;
        customerDeposit.customerDepositedEther.value(msg.value)();
    }
}


contract ICOCustomerDeposit is Owned {
    uint256 public totalDeposits;
    ICODepositContract[] public contracts;
    IContractRegistry public contractRegistry;

    event Deposit(address indexed _from, uint _value);

    // Define destination addresses
    // 0.5%
    address incentToCustomer = 0xa5f93F2516939d592f00c1ADF0Af4ABE589289ba;
    // 0.5%
    address icoFees = 0x38671398aD25461FB446A9BfaC2f4ED857C86863;
    // 99%
    address icoClientWallet = 0x994B085D71e0f9a7A36bE4BE691789DBf19009c8;

    function ICOCustomerDeposit() public Owned() {}

    function setContractRegistry(address _registry) public onlyOwner {
        contractRegistry = IContractRegistry(_registry);
    }
    
    function createNewDepositContract(uint256 number) onlyOwner public {
        for (uint256 i = 0; i < number; i++) {
            ICODepositContract depositContract = new ICODepositContract(this);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Notify external registry about new contract creation
            // This external call happens before state update, creating reentrancy vulnerability
            if (address(contractRegistry) != 0) {
                contractRegistry.notifyContractCreated(address(depositContract));
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            contracts.push(depositContract);
        }
    }

    function customerDepositedEther() payable public {
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
