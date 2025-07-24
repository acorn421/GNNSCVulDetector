/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
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
 * Modified the transfer function to include a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **External Call Injection**: Added a call to `TokenReceiver(_to).onTokenReceived()` between the sender balance deduction and recipient balance increase.
 * 
 * 2. **State Window Creation**: The external call creates a critical window where:
 *    - Sender's balance is already reduced (`balances[msg.sender] -= _value`)
 *    - Recipient's balance is not yet increased (`balances[_to] += _value` happens after the call)
 *    - This inconsistent state persists across transaction boundaries
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker calls `transfer()` to a malicious contract
 *    - **During callback**: Malicious contract's `onTokenReceived()` can call back into the token contract
 *    - **Transaction 2+**: Subsequent reentrancy calls exploit the inconsistent balance state
 *    - The vulnerability requires multiple transactions because the state inconsistency must be accumulated across calls
 * 
 * 4. **Stateful Nature**: The vulnerability depends on:
 *    - Persistent balance state in the `balances` mapping
 *    - Accumulated state changes from previous transaction calls
 *    - The ability to exploit the window between balance deduction and credit across multiple invocations
 * 
 * 5. **Realistic Implementation**: The callback mechanism mimics patterns found in modern token standards (ERC777, ERC1363) making it a realistic vulnerability that could appear in production code.
 * 
 * The vulnerability cannot be exploited in a single transaction because it requires the state changes to persist and be leveraged across multiple function calls, making it a genuine stateful, multi-transaction reentrancy vulnerability.
 */
/*
Implements EIP20 token standard: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md
.*/


pragma solidity ^0.4.18;

contract TokenReceiver {
    function onTokenReceived(address _from, uint256 _value) public;
}

contract EIP20Interface {
    uint256 public totalSupply;
    
    // Fix: declare balances as public so interface methods using it will refer to implementation
    mapping(address => uint256) public balances;

    function balanceOf(address _owner) public view returns (uint256 balance);

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Check if recipient is a contract and call its onTokenReceived hook
        if (isContract(_to)) {
            TokenReceiver(_to).onTokenReceived(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    function isContract(address _addr) internal view returns (bool) {
        uint32 size;
        assembly {
            size := extcodesize(_addr)
        }
        return (size > 0);
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);
    function approve(address _spender, uint256 _value) public returns (bool success);
    function allowance(address _owner, address _spender) public view returns (uint256 remaining);

    event Transfer(address indexed _from, address indexed _to, uint256 _value); 
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract ConunToken is EIP20Interface {
    uint256 constant private MAX_UINT256 = 2**256 - 1;
    mapping (address => mapping (address => uint256)) public allowed;
    string public name;
    uint8 public decimals;
    string public symbol;

    constructor(
        uint256 _initialAmount,
        string _tokenName,
        uint8 _decimalUnits,
        string _tokenSymbol
    ) public {
        balances[msg.sender] = _initialAmount;
        totalSupply = _initialAmount;
        name = _tokenName;
        decimals = _decimalUnits;
        symbol = _tokenSymbol;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowance >= _value);
        balances[_to] += _value;
        balances[_from] -= _value;
        if (allowance < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        Transfer(_from, _to, _value);
        return true;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }   
}
