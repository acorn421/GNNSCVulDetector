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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify token recipients BEFORE updating the allowance. This creates a Check-Effects-Interactions pattern violation where:
 * 
 * 1. **Transaction 1**: Attacker calls transferFrom() with a malicious recipient contract
 *    - Balances are updated (effects)
 *    - External call to recipient occurs (interaction)
 *    - Malicious recipient reenters transferFrom() with same allowance
 *    - Reentrant call succeeds because allowance hasn't been decremented yet
 *    - Multiple token transfers occur using the same allowance
 * 
 * 2. **Transaction 2**: Original call completes, finally updating allowance
 *    - This leaves the system in an inconsistent state
 *    - More tokens were transferred than the allowance should have permitted
 * 
 * The vulnerability requires multiple transactions because:
 * - The allowance state persists between transactions
 * - The attacker needs to set up the malicious recipient contract first
 * - The exploitation depends on the timing of state updates across function calls
 * - Each reentrant call modifies balances but the allowance update is delayed
 * 
 * This is realistic because token recipient notification is a common pattern in modern token contracts (ERC777, ERC1363), and the external call placement creates a subtle but exploitable CEI violation.
 */
/**
 *Submitted for verification at Etherscan.io on 2017-08-28
*/

pragma solidity ^0.4.11;

contract ITokenReceiver {
    function onTokenReceived(address _from, uint256 _value, bytes _data) public;
}

contract BatToken {

    string public name = "Basic Attention Token";      //  token name
    string public symbol = "BAT";           //  token symbol
    uint256 public decimals = 6;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 0;
    bool public stopped = false;

    uint256 constant valueFounder = 100000000000000000;
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

    function BatToken(address _addressFounder) public {
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        if (isContract(_to)) {
            // External call, susceptible to reentrancy
            ITokenReceiver(_to).onTokenReceived(_from, _value, "");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
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
        balanceOf[msg.sender] -= _value;
        balanceOf[0x0] += _value;
        Transfer(msg.sender, 0x0, _value);
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
