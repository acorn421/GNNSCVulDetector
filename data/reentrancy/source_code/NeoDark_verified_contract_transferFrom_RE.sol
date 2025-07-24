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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient before finalizing the allowance update. This creates a window where balances are updated but allowances haven't been decremented yet, enabling multi-transaction exploitation where attackers can set up allowances in one transaction and exploit through recipient hooks in subsequent transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `_to` address using `_to.call()` with a recipient notification hook
 * 2. Placed the external call AFTER balance updates but BEFORE allowance state finalization
 * 3. Used `_to.code.length > 0` check to only call contracts (realistic pattern)
 * 4. Called `onTokenReceived` method which is a realistic callback interface
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker sets up an allowance using `approve()` for a malicious contract
 * 2. **Transaction 2**: Victim calls `transferFrom()` to transfer tokens to the malicious contract
 * 3. **During Transaction 2**: The malicious contract's `onTokenReceived` callback is triggered
 * 4. **Reentrancy Attack**: The callback can call `transferFrom()` again before the allowance is decremented
 * 5. **State Exploitation**: The contract sees updated balances but unchanged allowances, allowing over-spending
 * 
 * **Why Multi-Transaction is Required:**
 * - The allowance must be pre-established in a separate transaction via `approve()`
 * - The vulnerability exploits the persistent state of allowances across transactions
 * - The attack requires coordination between the initial allowance setup and the callback exploitation
 * - Single transaction exploitation is prevented by the need for pre-existing allowance state
 * 
 * **State Persistence Elements:**
 * - `allowed[_from][msg.sender]` persists between transactions
 * - `balances` modifications accumulate across calls
 * - The vulnerability depends on the temporal gap between balance updates and allowance decrements
 * - Multiple `transferFrom` calls can exploit the same allowance before it's properly decremented
 * 
 * This creates a realistic, stateful reentrancy vulnerability that requires multiple transactions to exploit effectively.
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

    function NeoDark() public 
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
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns(bool) 
    {
        uint256 _allowance = allowed[_from][msg.sender];
        balances[_to] = balances[_to].add(_value);
        balances[_from] = balances[_from].sub(_value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient about the transfer (external call before state finalization)
        uint size;
        assembly { size := extcodesize(_to) }
        if(size > 0) {
            bool success = _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
            // Continue regardless of callback success
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowed[_from][msg.sender] = _allowance.sub(_value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns(bool) 
    {
        require((_value == 0) || (allowed[msg.sender][_spender] == 0));
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function() public 
    {
        revert();
    }
}
