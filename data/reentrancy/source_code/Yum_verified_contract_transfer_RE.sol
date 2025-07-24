/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the receiver contract before state updates are complete. The vulnerability enables a multi-transaction attack where:
 * 
 * **Transaction 1**: Attacker calls transfer(), receives the callback, and can re-enter to observe/manipulate state while the original transfer is still in progress. The attacker can record the current state and prepare for the second transaction.
 * 
 * **Transaction 2**: Attacker exploits the state inconsistencies created from the first transaction by calling transfer() again, potentially draining more funds than their actual balance allows.
 * 
 * **Multi-Transaction Nature**: 
 * - The vulnerability requires at least 2 separate transactions because the attacker needs to first establish the state manipulation in transaction 1, then exploit it in transaction 2
 * - State changes from the first transaction (partial balance updates, enabled status changes) persist and create vulnerabilities for subsequent transactions
 * - A single transaction cannot fully exploit this because the attacker needs to complete the first transfer to create the exploitable state condition
 * 
 * **Exploitation Mechanism**:
 * 1. **Transaction 1**: Attacker initiates transfer, receives callback, and can re-enter to examine state
 * 2. **Between Transactions**: State remains partially updated, creating inconsistencies
 * 3. **Transaction 2**: Attacker exploits the accumulated state changes to drain additional funds
 * 4. The vulnerability depends on the persistent state changes across multiple transaction boundaries
 * 
 * The external call violates the checks-effects-interactions pattern and creates a window where state can be manipulated across transaction boundaries, making this a realistic stateful reentrancy vulnerability.
 */
pragma solidity ^0.4.18;

contract ERC20Interface {
    uint256 public totalSupply;
    function balanceOf(address who) public constant returns (uint256);
    function transfer(address _to, uint256 _amount) public returns (bool);
    event Transfer(address indexed from, address indexed to, uint256 value);
}

contract Yum is ERC20Interface {
    uint256 public constant INITIAL_SUPPLY = 3000000 * (10 ** uint256(decimals));
    string public constant symbol = "YUM";
    string public constant name = "YUM Token";
    uint8 public constant decimals = 18;
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
    function Yum() public {
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
            accounts[_addr].enabled = _enabled;
        }
    }
    
    // Vulnerable transfer function with reentrancy
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
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                // Notify receiver about incoming transfer - VULNERABILITY INJECTION
                // This allows receiver to re-enter before state is fully updated
                if (isContract(_to)) {
                    _to.call(abi.encodeWithSignature("onTransferReceived(address,uint256)", msg.sender, _amount));
                    // Continue execution regardless of callback success
                }
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                // Credit the sender.
                accounts[msg.sender].balance -= _amount;
                // Debit the receiver.
                accounts[_to].balance += _amount;
                emit Transfer(msg.sender, _to, _amount);
                return true;
        }
        return false;
    }

    // Internal utility to check if address is a contract
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}
