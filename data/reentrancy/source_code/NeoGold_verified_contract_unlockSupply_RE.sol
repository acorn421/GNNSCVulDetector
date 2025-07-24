/*
 * ===== SmartInject Injection Details =====
 * Function      : unlockSupply
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
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the owner contract before updating the fullSupplyUnlocked state. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Owner calls unlockSupply() which triggers the external call to owner.call()
 * 2. **During external call**: The owner contract (attacker-controlled) can call unlockSupply() again since fullSupplyUnlocked is still false
 * 3. **Transaction 2+**: Each reentrant call adds another 50M tokens to the owner's balance before fullSupplyUnlocked is set
 * 
 * **Why Multi-Transaction:**
 * - The vulnerability exploits the time window between the external call and the state update
 * - The attacker must have set up their contract to handle the onSupplyUnlock callback beforehand (separate transaction)
 * - Each reentrancy occurs in the call stack but represents logically separate operations that accumulate state
 * - The fullSupplyUnlocked flag remains false throughout the reentrant calls, enabling multiple token mints
 * 
 * **State Persistence Requirements:**
 * - The attacker must deploy and configure their malicious contract in prior transactions
 * - Each reentrant call modifies the balances mapping persistently
 * - The vulnerability compounds across multiple reentrant calls within the same transaction tree
 * 
 * This creates a realistic scenario where an administrative function meant to be called once can be exploited multiple times through reentrancy, requiring prior setup and resulting in persistent state corruption.
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
contract NeoGold {
    using SafeMath for uint256;
    mapping(address => mapping(address => uint256)) allowed;
    mapping(address => uint256) balances;
    uint256 public totalSupply;
    uint256 public decimals;
    address public owner;
    bytes32 public symbol;
    bool public fullSupplyUnlocked;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _owner, address indexed spender, uint256 value);

    function NeoGold() 
    {
        totalSupply = 100000000;
        symbol = 'NEOG';
        owner = 0x61DDb6704A84CD906ec8318576465b25aD2100fd;
        balances[owner] = 50000000;
        decimals = 0;
    }
    function unlockSupply() returns(bool)
    {
        require(msg.sender == owner);
        require(!fullSupplyUnlocked);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add external call to notify system about unlock event
        // This creates a reentrancy opportunity before state is finalized
        if (owner.call(bytes4(keccak256("onSupplyUnlock(uint256)")), 50000000)) {
            // External call succeeded, continue with unlock
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[owner] = balances[owner].add(50000000);
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
        Transfer(msg.sender, _to, _value);
        return true;
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

    function() 
    {
        revert();
    }
}