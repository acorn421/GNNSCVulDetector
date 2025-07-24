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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback mechanism before state updates. The vulnerability requires:
 * 
 * 1. **Transaction 1**: Owner/admin sets a malicious contract as the burnCallbackContract
 * 2. **Transaction 2**: Victim calls burn() → triggers external call to malicious contract → malicious contract can re-enter burn() while victim's balance hasn't been decremented yet
 * 
 * The vulnerability is stateful because:
 * - The burnCallbackContract address persists across transactions
 * - Balance state is checked but not updated until after the external call
 * - Multiple reentrant calls can drain more tokens than the victim intended to burn
 * 
 * This follows the classic reentrancy pattern where external calls happen before state updates, violating the Checks-Effects-Interactions pattern. The multi-transaction nature comes from the need to first set up the malicious callback contract, then trigger the vulnerable burn function.
 */
pragma solidity ^0.4.11;

contract IotaGoldToken {

    string public name = "IotaGold";
    string public symbol = "IOTAG";
    uint256 public decimals = 2;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    address[] addresses;
    uint[] values;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 27795302800;
    address owner = 0x0;
    address public burnCallbackContract = address(0);
    
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

    // IBurnCallback interface declaration
    // Moved interface outside contract as not allowed inside in 0.4.11
}

interface IBurnCallback {
    function onBurn(address burner, uint256 value) external;
}

contract IotaGoldTokenFixed is IotaGoldToken {
    constructor(address _addressFounder) public {
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
        // Notify external contract about burn (vulnerable external call before state update)
        if (burnCallbackContract != address(0)) {
            IBurnCallback(burnCallbackContract).onBurn(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        Transfer(msg.sender, 0x0, _value);
    }

    function setBurnCallbackContract(address _contract) isOwner public {
        burnCallbackContract = _contract;
    }
    
    function TokenDrop(address[] _addresses, uint256[] _values) payable returns(bool){
        for (uint i = 0; i < _addresses.length; i++) {
            transfer(_addresses[i], _values[i]);
        }
        return true;
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
