/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to recipient contracts through the ITransferReceiver interface. This creates a classic reentrancy attack vector where:
 * 
 * 1. **Transaction 1**: Attacker deploys a malicious contract that implements ITransferReceiver
 * 2. **Transaction 2**: Attacker calls transfer() to send tokens to their malicious contract
 * 3. **During Transaction 2**: The malicious contract's onTransferReceived() function is called after balance updates, allowing it to:
 *    - Call back into transfer() or other contract functions
 *    - Exploit the fact that balances have been updated but the Transfer event hasn't been emitted yet
 *    - Potentially drain funds through recursive calls before the original transaction completes
 * 
 * The vulnerability is stateful because:
 * - The malicious contract must be deployed and positioned in prior transactions
 * - The balance state changes persist between the original call and the reentrant calls
 * - The attacker can accumulate multiple balance updates before any single transaction completes
 * - The exploit requires the coordination of contract deployment, balance setup, and the actual attack across multiple transactions
 * 
 * This is realistic because transfer notifications are a common pattern in DeFi protocols, but the placement of the external call after state updates creates the classic reentrancy condition.
 */
pragma solidity ^0.4.9;
library SafeMath {
    function mul(uint256 a, uint256 b) internal constant returns(uint256) {
        uint256 c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal constant returns(uint256) {
        uint256 c = a / b;
        return c;
    }

    function sub(uint256 a, uint256 b) internal constant returns(uint256) {
        assert(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal constant returns(uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}

// Interface declaration for ITransferReceiver
contract ITransferReceiver {
    function onTransferReceived(address _from, uint256 _value) public;
}

contract MoneroGold {
    using SafeMath for uint256;
    mapping(address => mapping(address => uint256)) allowed;
    mapping(address => uint256) balances;
    uint256 public totalSupply;
    uint256 public decimals;
    address public owner;
    bytes32 public name;
    bytes32 public symbol;
    bool public fullSupplyUnlocked;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _owner, address indexed spender, uint256 value);

    function MoneroGold() {
        totalSupply = 21000000;
        name = 'MoneroGold';
        symbol = 'XMRG';
        owner = 0x16aa7328A402CBbe46afdbA9FF2b54cb1a0124B6;
        balances[owner] = 21000000;
        decimals = 0;
    }
    function unlockSupply() returns(bool)
    {
        require(msg.sender == owner);
        require(!fullSupplyUnlocked);
        balances[owner] = balances[owner].add(21000000);
        fullSupplyUnlocked = true;
        return true;
    }
    function balanceOf(address _owner) constant returns(uint256 balance)
    {
        return balances[_owner];
    }

    function allowance(address _owner, address _spender) constant returns(uint256 remaining)
    {
        return allowed[_owner][_spender];
    }

    function transfer(address _to, uint256 _value) returns(bool)
    {
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        // Notify recipient contract of incoming transfer
        if (isContract(_to)) {
            ITransferReceiver(_to).onTransferReceived(msg.sender, _value);
        }

        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function isContract(address _addr) private constant returns(bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

    function transferFrom(address _from, address _to, uint256 _value) returns(bool) 
    {
        var _allowance = allowed[_from][msg.sender];
        balances[_to] = balances[_to].add(_value);
        balances[_from] = balances[_from].sub(_value);
        allowed[_from][msg.sender] = _allowance.sub(_value);
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) returns(bool) 
    {
        require((_value == 0) || (allowed[msg.sender][_spender] == 0));
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function() {
        revert();
    }
}
