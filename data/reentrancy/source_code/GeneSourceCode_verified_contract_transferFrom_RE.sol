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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 1. Adding an external call to the recipient contract (_to) via a callback mechanism for "token received notification"
 * 2. Moving critical state updates (balanceOf[_from] and allowance decrements) to occur AFTER the external call
 * 3. Only updating balanceOf[_to] before the external call, creating an inconsistent state window
 * 
 * Multi-Transaction Exploitation Scenario:
 * - Transaction 1: Attacker sets up allowance and deploys malicious recipient contract
 * - Transaction 2: Call transferFrom() which triggers the callback, allowing the malicious contract to:
 *   * Re-enter transferFrom() during the callback while balanceOf[_from] and allowance haven't been decremented yet
 *   * Drain more tokens than originally approved because the allowance check passes but allowance hasn't been updated
 *   * Exploit the window where balanceOf[_to] shows updated balance but balanceOf[_from] hasn't been decremented
 * 
 * The vulnerability requires multiple transactions because:
 * 1. Initial setup (allowance approval) must happen in a separate transaction
 * 2. The actual exploit spans the callback window created by the external call
 * 3. State inconsistencies accumulate across the callback chain, enabling over-withdrawal
 */
pragma solidity ^0.4.11;

contract  GeneSourceCode {

    string public name = "Gene Source Code Chain";      //  the GSC Chain token name
    string public symbol = "Gene";           //  the GSC Chain token symbol
    uint256 public decimals = 18;            //  the GSC Chain token digits

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 2000000000000000000000000000;
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

    constructor(address _addressFounder) public {
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update recipient balance first
        balanceOf[_to] += _value;
        
        // External call to notify recipient before completing all state updates
        if(_isContract(_to)) {
            _to.call(
                abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value)
            );
            // Continue regardless of callback success
        }
        
        // Complete state updates after external call (vulnerability!)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;
        allowance[_from][msg.sender] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value);
        return true;
    }

    // Helper function to check if address is a contract
    function _isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
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
}