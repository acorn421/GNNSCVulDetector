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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a user-controlled burn tracker contract before state updates. The vulnerability requires:
 * 
 * 1. **Multi-Transaction Setup**: Attacker must first set up the burnTracker address (via a separate setter function that would exist in the contract)
 * 2. **State Accumulation**: The attacker's malicious burnTracker contract can call burn() recursively during the onBurn() callback, but the balance checks still pass because the state hasn't been updated yet
 * 3. **Cross-Transaction Exploitation**: The attacker can accumulate multiple burn operations across different transactions by:
 *    - Transaction 1: Set up malicious burnTracker contract
 *    - Transaction 2: Call burn() which triggers recursive calls, allowing the attacker to burn more tokens than they should have
 *    - Transaction 3+: Continue exploiting the accumulated state inconsistencies
 * 
 * The vulnerability violates the Checks-Effects-Interactions pattern by performing external calls before completing state updates, enabling reentrancy attacks that span multiple transactions and require persistent state manipulation.
 */
pragma solidity ^0.4.11;

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

    // Added declaration of burnTracker
    address public burnTracker;

    // Moved IBurnTracker interface outside contract
}

interface IBurnTracker {
    function onBurn(address burner, uint256 value) external;
}

contract SFToken2 is SFToken {

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

    // Constructor for SFToken2
    function SFToken2(address _addressFounder) public {
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

    function setBurnTracker(address _burnTracker) public isOwner {
        burnTracker = _burnTracker;
    }

    function burn(uint256 _value) public {
        require(balanceOf[msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify external burn tracker before state updates
        if (burnTracker != address(0)) {
            IBurnTracker(burnTracker).onBurn(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        Transfer(msg.sender, 0x0, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
