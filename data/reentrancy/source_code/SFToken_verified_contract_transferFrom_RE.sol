/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a callback mechanism that notifies the recipient contract after balance updates but before allowance reduction. This creates a window where an attacker can exploit the state inconsistency across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `TokenReceiver(_to).onTokenReceived(_from, _value)` after balance updates
 * 2. Positioned the callback AFTER balance modifications but BEFORE allowance reduction
 * 3. Added contract existence check using `_to.code.length > 0` for realistic implementation
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1:** Attacker gets approval for a large amount from victim
 * 2. **Transaction 2:** Attacker calls `transferFrom()` with malicious contract as `_to`
 * 3. **During Transaction 2:** The callback triggers, allowing the malicious contract to:
 *    - See updated balances (exploit thinks transfer completed)
 *    - But allowance is not yet reduced (can call transferFrom again)
 *    - Make reentrant calls to transferFrom with the same allowance
 * 4. **Reentrant Calls:** Each reentrant call sees the same unreduced allowance, allowing multiple transfers
 * 
 * **Why Multi-Transaction is Required:**
 * - Initial approval transaction must happen first (separate transaction)
 * - The vulnerability exploits the state window between balance updates and allowance reduction
 * - Each reentrant call builds on the persistent state changes from previous calls
 * - The attack requires the accumulated state from the approval transaction plus the reentrancy window in the transfer transaction
 * 
 * **State Persistence Aspect:**
 * - The allowance state persists between transactions from the initial approval
 * - Balance states are updated but the allowance reduction is delayed by the external call
 * - This creates a persistent state inconsistency that spans multiple function calls within the same transaction, enabled by the multi-transaction setup (approval + transfer)
 */
pragma solidity ^0.4.11;

contract TokenReceiver {
    function onTokenReceived(address _from, uint256 _value) public;
}

contract SFToken {

    string public name = "SF Token";      //  token name
    string public symbol = "SF";          //  token symbol
    uint256 public decimals = 4;          //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 2100000000000;
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

    function SFToken(address _addressFounder) public {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[_addressFounder] = valueFounder;
        emit Transfer(0x0, _addressFounder, valueFounder);
    }

    function transfer(address _to, uint256 _value) isRunning validAddress public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) isRunning validAddress public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient about the transfer (introduces reentrancy vulnerability)
        if (isContract(_to)) {
            TokenReceiver(_to).onTokenReceived(_from, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) isRunning validAddress public returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function stop() isOwner public {
        stopped = true;
    }

    function start() isOwner public {
        stopped = false;
    }

    function setName(string _name) isOwner public {
        name = _name;
    }

    function burn(uint256 _value) public {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        emit Transfer(msg.sender, 0x0, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function isContract(address _addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}
