/*
 * ===== SmartInject Injection Details =====
 * Function      : setEnabled
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by adding time-based activation controls. The function now uses block.timestamp to manage delayed account activations and cooldown periods. This creates a vulnerability where miners can manipulate timestamps across multiple transactions to bypass intended timing constraints. The vulnerability requires: 1) First transaction to set pending activation time, 2) Second transaction where timestamp manipulation allows premature activation or extended cooldown bypass. State variables pendingActivations and lastDisableTime persist between transactions, making this a stateful vulnerability that accumulates timing-dependent state changes.
 */
pragma solidity ^0.4.18;

contract ERC20Interface {
    uint256 public totalSupply;
    function balanceOf(address who) public constant returns (uint256);
    function transfer(address to, uint256 value) public returns (bool);
    event Transfer(address indexed from, address indexed to, uint256 value);
}

contract Yum is ERC20Interface {
    string public constant symbol = "YUM";
    string public constant name = "YUM Token";
    uint8 public constant decimals = 18;
    uint256 public constant INITIAL_SUPPLY = 3000000 * (10 ** uint256(decimals));
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

    // Pending activation times for accounts
    mapping(address => uint256) pendingActivations;
    // Last disable times for accounts
    mapping(address => uint256) lastDisableTime;
    
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
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            if (_enabled) {
                // Enable immediately if no pending activation time
                if (pendingActivations[_addr] == 0) {
                    accounts[_addr].enabled = true;
                } else {
                    // Check if activation time has passed using block.timestamp
                    if (block.timestamp >= pendingActivations[_addr]) {
                        accounts[_addr].enabled = true;
                        pendingActivations[_addr] = 0; // Clear pending activation
                    }
                }
            } else {
                // Disable with cooldown period
                accounts[_addr].enabled = false;
                lastDisableTime[_addr] = block.timestamp;
            }
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        }
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