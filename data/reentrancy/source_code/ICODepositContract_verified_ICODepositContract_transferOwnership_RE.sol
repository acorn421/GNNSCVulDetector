/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the new owner before updating the owner state. This creates a window where:
 * 
 * 1. **Transaction 1**: Current owner calls transferOwnership() with a malicious contract address
 * 2. **Intermediate State**: OwnershipTransferred event is emitted, but owner variable is not yet updated
 * 3. **Reentrant Call**: The malicious contract's onOwnershipReceived() callback can re-enter the contract
 * 4. **Transaction 2**: During reentrancy, the contract still sees the old owner (due to state not updated yet), allowing potential exploitation of owner-only functions
 * 5. **State Persistence**: The ownership transfer state persists between transactions, creating a multi-transaction attack vector
 * 
 * The vulnerability is realistic as notifying new owners is a common pattern, and the external call before state update violates the Checks-Effects-Interactions pattern. The attack requires multiple transactions: the initial transfer call, the reentrant callback execution, and potentially additional calls to exploit the intermediate state. This makes it a genuine stateful, multi-transaction vulnerability that cannot be exploited in a single atomic transaction.
 */
pragma solidity ^0.4.8;

// ----------------------------------------------------------------------------------------------
// Unique ICO deposit contacts for customers to deposit ethers that are sent to different
// wallets
//
// Enjoy. (c) Bok Consulting Pty Ltd & Incent Rewards 2017. The MIT Licence.
// ----------------------------------------------------------------------------------------------

interface IOwnableCallback {
    function onOwnershipReceived(address previousOwner, address newOwner) external;
}

contract Owned {
    address public owner;
    event OwnershipTransferred(address indexed _from, address indexed _to);

    function Owned() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        if (msg.sender != owner) revert();
        _;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        emit OwnershipTransferred(owner, newOwner);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify new owner of ownership transfer (vulnerable external call)
        if (isContract(newOwner)) {
            IOwnableCallback(newOwner).onOwnershipReceived(owner, newOwner);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        owner = newOwner;
    }

    // Polyfill for Solidity <0.5.0 to check if address is a contract
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
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
    address incentToCustomer = 0xa5f93F2516939d592f00c1ADF0Af4ABE589289ba;
    // 0.5%
    address icoFees = 0x38671398aD25461FB446A9BfaC2f4ED857C86863;
    // 99%
    address icoClientWallet = 0x994B085D71e0f9a7A36bE4BE691789DBf19009c8;

    function createNewDepositContract(uint256 number) onlyOwner public {
        for (uint256 i = 0; i < number; i++) {
            ICODepositContract depositContract = new ICODepositContract(this);
            contracts.push(depositContract);
        }
    }

    function customerDepositedEther() public payable {
        totalDeposits += msg.value;
        uint256 value1 = msg.value * 1 / 200;
        if (!incentToCustomer.send(value1)) revert();
        uint256 value2 = msg.value * 1 / 200;
        if (!icoFees.send(value2)) revert();
        uint256 value3 = msg.value - value1 - value2;
        if (!icoClientWallet.send(value3)) revert();
        emit Deposit(msg.sender, msg.value);
    }

    // Prevent accidental sending of ethers
    function () public {
        revert();
    }
}
