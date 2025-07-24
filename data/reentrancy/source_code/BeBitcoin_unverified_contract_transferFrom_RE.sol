/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a post-transfer callback mechanism that calls external contracts after balance updates but before allowance updates, creating a multi-transaction reentrancy vulnerability. The vulnerability requires multiple transactions to exploit: 1) Initial transferFrom call with malicious recipient contract, 2) Reentrancy callback that calls transferFrom again during execution, 3) State accumulation through repeated calls. The allowance update happens after the external call, allowing the recipient to re-enter and make additional transfers before the allowance is decremented. This creates a classic reentrancy vulnerability where state is not atomically updated, enabling multiple withdrawals from the same allowance approval across sequential transaction calls.
 */
pragma solidity ^0.4.18;

contract ERC20Token {
    uint256 public totalSupply;
    // Declare mappings and constants to fix undeclared identifiers in base contract
    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowed;
    uint256 constant private MAX_UINT256 = 2**256 - 1;

    function balanceOf(address _owner) public view returns (uint256 balance);
    function transfer(address _to, uint256 _value) public returns (bool success);
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowance >= _value);
        balances[_to] += _value;
        balances[_from] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Post-transfer callback for contract recipients
        if (_to.code.length > 0) {
            // Call recipient contract's onTokenReceived function
            bytes4 sig = bytes4(keccak256("onTokenReceived(address,address,uint256)"));
            _to.call(sig, _from, _to, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (allowance < MAX_UINT256) {
            allowed[_from][msg.sender] -= _value;
        }
        Transfer(_from, _to, _value);
        return true;
    }
    function approve(address _spender, uint256 _value) public returns (bool success);
    function allowance(address _owner, address _spender) public view returns (uint256 remaining);
    event Transfer(address indexed _from, address indexed _to, uint256 _value); 
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract BeBitcoin is ERC20Token {

    uint256 constant private MAX_UINT256 = 2**256 - 1;
    // Already declared in base contract, but redeclaration is fine in 0.4.x
    // mapping (address => uint256) public balances;
    // mapping (address => mapping (address => uint256)) public allowed;

    string public name;
    uint8 public decimals;             
    string public symbol;              

    constructor (
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
