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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after balance updates but before allowance updates. This creates a classic checks-effects-interactions violation where:
 * 
 * **Specific Changes Made:**
 * 1. Added a check for contract code at the `_to` address using `_to.code.length > 0`
 * 2. Added an external call to `TokenReceiver(_to).onTokenReceived(_from, _value)` between balance updates and allowance updates
 * 3. The external call allows the recipient contract to re-enter the transferFrom function while the allowance hasn't been decremented yet
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Alice approves Mallory's contract for 100 tokens: `approve(malloryContract, 100)`
 * 2. **Transaction 2**: Mallory calls `transferFrom(alice, malloryContract, 100)` which:
 *    - Updates balances (Alice loses 100, Mallory gains 100)
 *    - Calls `malloryContract.onTokenReceived(alice, 100)`
 *    - Mallory's contract re-enters and calls `transferFrom(alice, malloryContract, 100)` again
 *    - Since allowance hasn't been updated yet, the second call succeeds
 *    - Now Alice has lost 200 tokens but only approved 100
 *    - Finally, allowance is decremented by 100 (but should be 200)
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the initial approval transaction to set up the allowance state
 * - The exploitation transaction depends on the persistent allowance state from the previous transaction
 * - The reentrancy attack leverages the fact that allowance state persists between the external call and the allowance update
 * - A single-transaction exploit isn't possible because the allowance must be pre-established through a separate approve() call
 * 
 * **Stateful Nature:**
 * - The attack relies on the persistent `allowed[_from][msg.sender]` mapping state
 * - The vulnerability window exists because state updates happen in the wrong order relative to external calls
 * - The exploit accumulates unauthorized transfers by leveraging stale allowance state across multiple function calls within the same transaction, but this requires the allowance to have been set in a previous transaction
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
contract TokenReceiver {
    function onTokenReceived(address _from, uint256 _value) public;
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

    constructor() public
    {
        totalSupply = 100000000;
        symbol = 'NEOG';
        owner = 0x61DDb6704A84CD906ec8318576465b25aD2100fd;
        balances[owner] = 50000000;
        decimals = 0;
    }
    function unlockSupply() public returns(bool)
    {
        require(msg.sender == owner);
        require(!fullSupplyUnlocked);
        balances[owner] = balances[owner].add(50000000);
        fullSupplyUnlocked = true;
        return true;
    }
    function balanceOf(address _owner) public constant returns(uint256 balance)
    {
        return balances[_owner];
    }

    function allowance(address _owner, address _spender) public constant returns(uint256 remaining)
    {
        return allowed[_owner][_spender];
    }

    function transfer(address _to, uint256 _value) public returns(bool)
    {
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        Transfer(msg.sender, _to, _value); // 'emit' is not required in Solidity 0.4.9
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns(bool) 
    {
        uint256 _allowance = allowed[_from][msg.sender];
        balances[_to] = balances[_to].add(_value);
        balances[_from] = balances[_from].sub(_value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient if it's a contract (common pattern for token hooks)
        uint256 length;
        assembly { length := extcodesize(_to) }
        if(length > 0) {
            TokenReceiver(_to).onTokenReceived(_from, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowed[_from][msg.sender] = _allowance.sub(_value);
        Transfer(_from, _to, _value); // 'emit' is not required in Solidity 0.4.9
        return true;
    }

    function approve(address _spender, uint256 _value) public returns(bool) 
    {
        require((_value == 0) || (allowed[msg.sender][_spender] == 0));
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value); // 'emit' is not required in Solidity 0.4.9
        return true;
    }

    function() public 
    {
        revert();
    }
}
