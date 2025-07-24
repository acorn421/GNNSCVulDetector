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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to IBurnRegistry(msg.sender).onBurn(_value) after the balance check but before the balance update. This creates a classic reentrancy scenario where:
 * 
 * 1. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions to exploit:
 *    - Transaction 1: Attacker deploys a malicious contract implementing IBurnRegistry
 *    - Transaction 2: Attacker calls burn() from their malicious contract
 *    - During the external call in Transaction 2: The malicious contract re-enters burn() multiple times before the original balance is updated
 * 
 * 2. **State Persistence**: The balanceOf mapping persists between function calls, allowing the attacker to exploit the unchanged balance across multiple reentrant calls.
 * 
 * 3. **Exploitation Pattern**: 
 *    - Attacker contract calls burn(1000) 
 *    - External call to onBurn(1000) is made while balanceOf[attacker] still contains original amount
 *    - In onBurn(), attacker calls burn(1000) again recursively
 *    - Each reentrant call sees the same original balance, allowing burning more tokens than owned
 * 
 * 4. **Realistic Integration**: The external call appears legitimate - notifying a burn registry is a common pattern in token contracts for tracking or auditing purposes.
 * 
 * 5. **Violation of CEI Pattern**: The code violates Checks-Effects-Interactions by making the external call before updating the balance state, creating the reentrancy window.
 * 
 * The vulnerability is subtle and realistic, as the external call appears to be a legitimate feature, but the ordering creates a critical security flaw that can only be exploited through multiple function calls and state manipulation.
 */
pragma solidity ^0.4.11;

contract RepostiX   {

    string public name = "RepostiX";      //  token name
    string public symbol = "REPX";           //  token symbol
    uint256 public decimals = 6;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 21000000000000000;
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

    function RepostiX(address _addressFounder) public {
        owner = msg.sender;
        totalSupply = valueFounder;
        balanceOf[_addressFounder] = valueFounder;
        Transfer(0x0, _addressFounder, valueFounder);
    }

    function transfer(address _to, uint256 _value) isRunning validAddress public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) isRunning validAddress public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        require(allowance[_from][msg.sender] >= _value);
        balanceOf[_to] += _value;
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) isRunning validAddress public returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify external burn registry before updating state
        if (msg.sender != address(this)) {
            IBurnRegistry(msg.sender).onBurn(_value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        Transfer(msg.sender, 0x0, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

interface IBurnRegistry {
    function onBurn(uint256 _value) external;
}
