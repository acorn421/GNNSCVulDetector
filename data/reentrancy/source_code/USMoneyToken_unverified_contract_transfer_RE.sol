/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability through the following modifications:
 * 
 * 1. **Added State Tracking**: Introduced `transferCount[msg.sender]++` to track the number of transfers per address, creating persistent state between transactions.
 * 
 * 2. **External Contract Call**: Added an external call to recipient contracts using `_to.call()` with the `onTokenReceived` callback, which occurs AFTER balance updates but includes the transfer count.
 * 
 * 3. **Multi-Transaction Exploitation Vector**: The vulnerability requires multiple transactions to exploit:
 *    - **Transaction 1**: Attacker calls transfer() to initialize their transferCount and receive tokens
 *    - **Transaction 2+**: Attacker can exploit the reentrancy by having their malicious contract's `onTokenReceived` function call back into transfer(), using the accumulated transferCount state to potentially bypass checks or manipulate state
 * 
 * 4. **Stateful Dependencies**: The transferCount state persists between transactions, allowing attackers to build up state over multiple calls and then exploit the accumulated state in combination with the reentrancy vulnerability.
 * 
 * 5. **Realistic Implementation**: The callback mechanism is common in modern token standards (similar to ERC777/ERC1363), making this a realistic vulnerability that could appear in production code.
 * 
 * The vulnerability cannot be exploited in a single transaction alone - it requires the attacker to first establish state (transferCount) through legitimate transfers, then exploit the reentrancy in subsequent transactions while leveraging the accumulated state.
 */
/*
Implements EIP20 token standard: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md
.*/

pragma solidity ^0.4.21;

contract EIP20Interface {
    uint256 public totalSupply;
    
    // Declare balances mapping
    mapping (address => uint256) public balances;
    // Declare transferCount mapping for vulnerability
    mapping (address => uint256) public transferCount;

    function balanceOf(address _owner) public view returns (uint256 balance);
    
    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add stateful transfer tracking for multi-transaction vulnerability
        transferCount[msg.sender]++;
        
        // Notify recipient contract if applicable - vulnerable to reentrancy
        if (isContract(_to)) {
            (bool callSuccess,) = _to.call(
                abi.encodeWithSignature("onTokenReceived(address,uint256,uint256)", 
                msg.sender, _value, transferCount[msg.sender])
            );
            // Continue execution regardless of call result
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
    
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);
    
    function approve(address _spender, uint256 _value) public returns (bool success);
    
    function allowance(address _owner, address _spender) public view returns (uint256 remaining);
    
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}


contract USMoneyToken is EIP20Interface {
    uint256 constant private MAX_UINT256 = 2**256 - 1;
    // Remove duplicate declarations, since inherited
    // mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowed;
    // mapping (address => uint256) public transferCount;
    
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
        emit Transfer(address(0x0), msg.sender, _initialAmount);
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
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
        emit Transfer(_from, _to, _value);
        return true;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public view returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}
