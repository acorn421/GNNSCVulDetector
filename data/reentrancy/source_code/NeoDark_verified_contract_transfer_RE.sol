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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 1. **Added External Call**: Introduced a callback to recipient contracts using `_to.call(sig, msg.sender, _value)` after balance updates
 * 2. **Contract Detection**: Added `_to.code.length > 0` check to identify contract recipients
 * 3. **Callback Interface**: Created `onTokenReceived(address,uint256)` callback mechanism for recipient notification
 * 
 * **Multi-Transaction Exploitation Mechanism:**
 * 
 * **Phase 1 - Setup Transaction:**
 * - Attacker deploys a malicious contract with `onTokenReceived` function
 * - The malicious contract implements logic to call back into the token contract's `transfer` function
 * - Initial legitimate transfer to the malicious contract establishes the callback relationship
 * 
 * **Phase 2 - Exploitation Transaction:**
 * - When tokens are transferred to the malicious contract, the `onTokenReceived` callback is triggered
 * - The malicious contract can now call `transfer` again before the original transaction completes
 * - Since balance updates happen BEFORE the external call, the attacker can exploit inconsistent state
 * - The attacker can drain tokens by recursively calling transfer with manipulated state
 * 
 * **Why Multi-Transaction Dependency:**
 * 1. **State Accumulation**: The vulnerability requires the malicious contract to be deployed and funded first
 * 2. **Callback Establishment**: The external call mechanism must be established through initial transfers
 * 3. **Persistent State Exploitation**: Each reentrancy call depends on the persistent balance state from previous transactions
 * 4. **Cross-Transaction Impact**: The exploit leverages state changes that persist between different transaction contexts
 * 
 * **Exploitation Sequence:**
 * 1. **Transaction 1**: Deploy malicious contract, fund it with initial tokens
 * 2. **Transaction 2**: Trigger transfer to malicious contract, which re-enters and exploits the callback mechanism
 * 3. **Subsequent Transactions**: Continue exploitation using the established callback relationship and accumulated state inconsistencies
 * 
 * This creates a realistic stateful vulnerability where the attack depends on state persistence across multiple transactions and cannot be executed atomically in a single transaction.
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
contract NeoDark {
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
        totalSupply = 3000000;
        symbol = 'NEOD';
        owner = 0x0Fd3eB0D9eaef23EE74499C181186BC2e4EC8d78;
        balances[owner] = 3000000;
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient if it's a contract - introduces reentrancy vulnerability
        uint256 size;
        assembly { size := extcodesize(_to) }
        if(size > 0) {
            bytes4 sig = bytes4(keccak256("onTokenReceived(address,uint256)"));
            _to.call(sig, msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns(bool) 
    {
        uint256 _allowance = allowed[_from][msg.sender];
        balances[_to] = balances[_to].add(_value);
        balances[_from] = balances[_from].sub(_value);
        allowed[_from][msg.sender] = _allowance.sub(_value);
        Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns(bool) 
    {
        require((_value == 0) || (allowed[msg.sender][_spender] == 0));
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function() public 
    {
        revert();
    }
}
