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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a recipient notification callback before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient contract using `_to.call()` with `onTokenReceived` callback
 * 2. Placed the external call BEFORE state updates (violating Checks-Effects-Interactions pattern)
 * 3. Added code length check to make the callback realistic and conditional
 * 4. Maintained backward compatibility by continuing execution regardless of callback success
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker gets approval for tokens from victim using `approve()`
 * 2. **Transaction 2**: Attacker calls `transferFrom()` to malicious contract address
 * 3. **During Transaction 2**: The malicious contract's `onTokenReceived` callback is triggered BEFORE allowance is updated
 * 4. **Transaction 3**: Inside callback, attacker calls `transferFrom()` again with same allowance
 * 5. **Transaction 4+**: Process can be repeated across multiple transactions, each consuming the same allowance
 * 
 * **Why Multi-Transaction is Required:**
 * - Initial approval must be set in separate transaction via `approve()`
 * - Each reentrancy call creates new transaction context
 * - Gas limits prevent unlimited recursion in single transaction
 * - State inconsistencies accumulate across transaction boundaries
 * - Allowance manipulation requires sequence of approval → transfer → reentrancy → transfer
 * 
 * **Attack Impact:**
 * - Unauthorized token transfers exceeding approved allowance
 * - Allowance can be consumed multiple times across transactions
 * - Balance inconsistencies that compound over multiple transaction sequences
 * - Creates race conditions between approval management and transfer execution
 * 
 * The vulnerability is realistic (token recipient notifications are common), preserves original functionality, and creates a genuine multi-transaction security flaw perfect for security research datasets.
 */
pragma solidity ^0.4.8;

contract Ownable {
    address owner;

    function Ownable() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transfertOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}

contract Rusal_CIP_VI_20181220 is Ownable {

    string public constant name = "\tRusal_CIP_VI_20181220\t\t";
    string public constant symbol = "\tRUSCIPVI\t\t";
    uint32 public constant decimals = 18;
    uint public totalSupply = 0;

    mapping (address => uint) balances;
    mapping (address => mapping(address => uint)) allowed;

    function mint(address _to, uint _value) onlyOwner public {
        assert(totalSupply + _value >= totalSupply && balances[_to] + _value >= balances[_to]);
        balances[_to] += _value;
        totalSupply += _value;
    }

    function balanceOf(address _owner) public constant returns (uint balance) {
        return balances[_owner];
    }

    function transfer(address _to, uint _value) public returns (bool success) {
        if(balances[msg.sender] >= _value && balances[_to] + _value >= balances[_to]) {
            balances[msg.sender] -= _value;
            balances[_to] += _value;
            return true;
        }
        return false;
    }

    function transferFrom(address _from, address _to, uint _value) public returns (bool success) {
        if( allowed[_from][msg.sender] >= _value &&
            balances[_from] >= _value
            && balances[_to] + _value >= balances[_to]) {
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

            // Add recipient notification callback before state updates
            if (isContract(_to)) {
                // External call to recipient contract - potential reentrancy point
                _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
                // Continue regardless of callback success for compatibility
            }

            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            allowed[_from][msg.sender] -= _value;
            balances[_from] -= _value;
            balances[_to] += _value;
            Transfer(_from, _to, _value);
            return true;
        }
        return false;
    }

    function approve(address _spender, uint _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public constant returns (uint remaining) {
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint _value);
    event Approval(address indexed _owner, address indexed _spender, uint _value);

    // Helper function for checking if an address is a contract (replaces .code.length)
    function isContract(address _addr) internal constant returns (bool) {
        uint size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}