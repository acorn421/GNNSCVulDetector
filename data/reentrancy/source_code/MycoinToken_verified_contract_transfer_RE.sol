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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before completing the balance update. The vulnerability follows this pattern:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call `ITransferReceiver(_to).onTokenReceived(msg.sender, _value)` to notify recipient contracts
 * 2. Positioned the external call BETWEEN the sender balance deduction and recipient balance addition
 * 3. Added a check `if (_to.code.length > 0)` to only call contracts, making it realistic
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls `transfer()` with a malicious contract as recipient
 * 2. **During External Call**: The malicious contract's `onTokenReceived` is called
 * 3. **Reentrant Call**: Malicious contract calls `transfer()` again before original call completes
 * 4. **State Manipulation**: Original sender's balance is already reduced, but recipient hasn't received tokens yet
 * 5. **Transaction 2+**: Subsequent calls exploit this inconsistent state across multiple transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the external call to trigger a callback that can re-enter the contract
 * - Each reentrant call operates on persistent state that was modified by previous calls
 * - The attacker must accumulate multiple transfers to exploit the timing window between balance deduction and addition
 * - The exploit builds up over multiple transactions as the attacker drains funds progressively
 * 
 * **Persistent State Impact:**
 * - Balance modifications persist between transactions in the blockchain state
 * - Each reentrant call sees the updated sender balance but not the recipient balance
 * - This allows multiple withdrawals against the same balance across sequential transactions
 * 
 * This creates a realistic stateful vulnerability that requires multiple coordinated transactions to exploit, typical of sophisticated reentrancy attacks in DeFi protocols.
 */
pragma solidity ^0.4.11;

contract MycoinToken {

    string public name = "Mycoin";      //  token name
    string public symbol = "MYC";           //  token symbol
    uint256 public decimals = 6;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 2100000000000000;
    address owner = 0x0;

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    modifier isRunning {
        assert (!stopped);
        _;
    }

    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }

    // Fixed: Changed constructor style to avoid deprecation warning
    function MycoinToken(address _addressFounder) public {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[_addressFounder] = valueFounder;
        Transfer(0x0, _addressFounder, valueFounder);
    }

    // Fixed: Moved interface outside contract (Solidity 0.4.x requirement)
    // interface ITransferReceiver {
    //     function onTokenReceived(address from, uint256 value) external;
    // }

    function transfer(address _to, uint256 _value) isRunning validAddress returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Deduct from sender balance first
        balanceOf[msg.sender] -= _value;
        
        // External call to notify recipient - vulnerable to reentrancy
        if (isContract(_to)) {
            ITransferReceiver(_to).onTokenReceived(msg.sender, _value);
        }
        
        // Add to recipient balance AFTER external call - vulnerable state
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) isRunning validAddress returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) isRunning validAddress returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function stop() isOwner {
        stopped = true;
    }

    function start() isOwner {
        stopped = false;
    }

    function setName(string _name) isOwner {
        name = _name;
    }

    function burn(uint256 _value) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        Transfer(msg.sender, 0x0, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    // Helper function to check if address is a contract
    function isContract(address _addr) internal constant returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}

// Moved interface outside contract (as per Solidity <0.5.0 requirements)
interface ITransferReceiver {
    function onTokenReceived(address from, uint256 value) external;
}
