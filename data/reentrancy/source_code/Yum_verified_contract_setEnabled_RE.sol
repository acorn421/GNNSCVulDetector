/*
 * ===== SmartInject Injection Details =====
 * Function      : setEnabled
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1: Setup Phase**
 * - Deploy malicious contract that implements onStatusChange callback
 * - This contract tracks previous enabled states and plans the attack
 * 
 * **Transaction 2: Exploitation Phase**
 * - Owner calls setEnabled(maliciousContract, true)
 * - External call to maliciousContract.onStatusChange(true) occurs BEFORE state update
 * - Malicious contract can re-enter setEnabled during callback, potentially:
 *   - Calling setEnabled for other addresses while current state is inconsistent
 *   - Exploiting the fact that accounts[_addr].enabled hasn't been updated yet
 *   - Creating race conditions with other dependent functions
 * 
 * **Multi-Transaction Nature:**
 * - Initial deployment transaction needed to set up malicious contract
 * - Exploitation requires the callback mechanism to be triggered
 * - State changes persist between transactions, allowing accumulated exploitation
 * - The vulnerability depends on the sequence: external call → state change, creating a window for reentrancy
 * 
 * **Realistic Attack Vector:**
 * A malicious contract could exploit this by maintaining state between transactions and coordinating multiple setEnabled calls to create inconsistent account states or bypass intended access controls.
 */
pragma solidity ^0.4.18;

contract ERC20Interface {
    uint256 public totalSupply;
    function balanceOf(address who) public constant returns (uint256);
    function transfer(address to, uint256 value) public returns (bool);
    event Transfer(address indexed from, address indexed to, uint256 value);
}

contract Yum is ERC20Interface {
    uint8 public constant decimals = 18;
    uint256 public constant INITIAL_SUPPLY = 3000000 * (10 ** uint256(decimals));
    string public constant symbol = "YUM";
    string public constant name = "YUM Token";
    uint256 public constant totalSupply = INITIAL_SUPPLY;
    
    // Owner is the address controlled by FilletX.
    address constant owner = 0x045da370c3c0A1A55501F3B78Becc78a084CC488;

    // Account represents a user account.
    struct Account {
        // Balance is the user balance. 
        uint256 balance;
        // Addr is the address of the account.
        address addr;
        // Enabled is true if the user is able to transfer funds.
        bool enabled;
    }

    // Accounts holds user accounts.
    mapping(address => Account) accounts;
    
    // Constructor.
    constructor() public {
        accounts[owner] = Account({
          addr: owner,
          balance: INITIAL_SUPPLY,
          enabled: true
        });
    }

    // Get balace of an account.
    function balanceOf(address _owner) public constant returns (uint balance) {
        return accounts[_owner].balance;
    }
    
    // Set enabled status of the account.
    function setEnabled(address _addr, bool _enabled) public {
        assert(msg.sender == owner);
        if (accounts[_addr].enabled != _enabled) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // Notify the account about status change via callback
            if (isContract(_addr)) {
                // Call unchanged (uses low-level call for reentrancy vulnerability)
                require(_addr.call(bytes4(keccak256("onStatusChange(bool)")), _enabled));
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            accounts[_addr].enabled = _enabled;
        }
    }
    
    // Helper to check if address is a contract
    function isContract(address _addr) private view returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return length > 0;
    }

    // Transfer funds.
    function transfer(address _to, uint256 _amount) public returns (bool) {
        require(_to != address(0));
        require(_amount <= accounts[msg.sender].balance);
        // Enable the receiver if the sender is the exchange.
        if (msg.sender == owner && !accounts[_to].enabled) {
            accounts[_to].enabled = true;
        }
        if (
            // Check that the sender's account is enabled.
            accounts[msg.sender].enabled
            // Check that the receiver's account is enabled.
            && accounts[_to].enabled
            // Check that the sender has sufficient balance.
            && accounts[msg.sender].balance >= _amount
            // Check that the amount is valid.
            && _amount > 0
            // Check for overflow.
            && accounts[_to].balance + _amount > accounts[_to].balance) {
                // Credit the sender.
                accounts[msg.sender].balance -= _amount;
                // Debit the receiver.
                accounts[_to].balance += _amount;
                Transfer(msg.sender, _to, _amount);
                return true;
        }
        return false;
    }
}
