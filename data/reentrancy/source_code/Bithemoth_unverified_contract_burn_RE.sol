/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled contract (IBurnNotifier) before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call `IBurnNotifier(msg.sender).onBeforeBurn(_value)` before balance updates
 * 2. Used `msg.sender.code.length > 0` check to identify contract callers
 * 3. Positioned the external call strategically before state modifications
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1-N**: Attacker calls burn() multiple times to build up state in their malicious contract
 * 2. **Transaction N+1**: During the final burn() call, the attacker's contract exploits accumulated state:
 *    - The onBeforeBurn callback is triggered with the current balance still intact
 *    - Attacker's contract can call burn() again recursively while balances haven't been updated
 *    - The accumulated state from previous burns enables the attacker to drain more tokens than they should be able to
 * 
 * **Why Multi-Transaction Dependency:**
 * - The vulnerability requires the attacker to build up state (burn history, timing, or accumulated values) across multiple transactions
 * - Each previous burn call contributes to the exploitable state
 * - The final exploitation relies on the accumulated state from all previous transactions
 * - Single transaction exploitation is not possible because the attacker needs the historical context
 * 
 * **Realistic Attack Vector:**
 * The attacker deploys a malicious contract that implements IBurnNotifier and tracks burn history. Over multiple transactions, they accumulate state that enables them to calculate the optimal moment to exploit the reentrancy and drain tokens beyond their actual balance.
 */
pragma solidity ^0.4.11;

contract Bithemoth {

    string public name = "Bithemoth";      //  token name
    string public symbol = "BHM";           //  token symbol
    uint256 public decimals = 18;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 200000000000000000000000000;
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

    // Moved IBurnNotifier interface outside contract per Solidity 0.4.11 rules
}

interface IBurnNotifier {
    function onBeforeBurn(uint256 _value) external;
}

contract Bithemoth2 is Bithemoth {
    // Use constructor syntax instead of deprecated function constructor
    function Bithemoth2(address _addressFounder) public {
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
        // External call to user-controlled contract BEFORE state updates
        // This enables reentrancy exploitation across multiple transactions
        if (msg.sender.code.length > 0) {
            IBurnNotifier(msg.sender).onBeforeBurn(_value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        Transfer(msg.sender, 0x0, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
