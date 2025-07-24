/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback mechanism that executes before state updates. The vulnerability works by:
 * 
 * 1. **State Persistence**: Added a burnCallback address that persists between transactions
 * 2. **External Call Before State Update**: The callback to IBurnCallback.onTokenBurn() occurs before balanceOf is updated
 * 3. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: Attacker registers their malicious contract as burnCallback
 *    - Transaction 2: Attacker calls burn(), triggering the callback while their balance is still unchanged
 *    - During callback: Attacker's contract can call burn() again, re-entering with the same balance
 *    - This creates a classic reentrancy where state is read before being updated
 * 
 * 4. **Realistic Implementation**: The burn notification pattern is common in DeFi protocols for tracking burns, making this a realistic vulnerability
 * 
 * The vulnerability requires multiple transactions because:
 * - First transaction must set up the callback contract
 * - Second transaction triggers the actual reentrancy
 * - State accumulation occurs as balances are manipulated across nested calls
 * - The exploit depends on the persistent burnCallback state being set in a previous transaction
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

    // Declare IBurnCallback interface outside of contract to fix Solidity 0.4.x scoping rules
    // See below contract body for the interface declaration
    address public burnCallback = address(0);
    function setBurnCallback(address _cb) public {
        burnCallback = _cb;
    }
    
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
    // Fixed constructor style for ^0.4.11 compiler
    function MycoinToken(address _addressFounder) public {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[_addressFounder] = valueFounder;
        Transfer(0x0, _addressFounder, valueFounder);
    }

    function transfer(address _to, uint256 _value) isRunning validAddress returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Store original balance for callback
        uint256 originalBalance = balanceOf[msg.sender];
        // External call to notify burn listeners BEFORE state update
        if (burnCallback != address(0)) {
            IBurnCallback(burnCallback).onTokenBurn(msg.sender, _value, originalBalance);
        }
        // State updates after external call - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(msg.sender, 0x0, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

// Moved interface declaration outside contract, as required in Solidity 0.4.x
interface IBurnCallback {
    function onTokenBurn(address who, uint256 value, uint256 originalBalance) external;
}
