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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient address before state updates. The vulnerability requires multiple transactions to exploit: (1) Initial approval setup, (2) Malicious contract deployment/setup, (3) transferFrom call that triggers reentrancy where the malicious contract can make multiple reentrant calls before state is updated. The external call is positioned before balance and allowance updates, allowing attackers to drain funds by exploiting the unchanged state during reentrant calls. This creates a realistic token transfer notification mechanism that could legitimately exist in production code but introduces a critical security flaw.
 */
pragma solidity ^0.4.18;

contract EIP20Interface {
    uint256 public totalSupply;

    function balanceOf(address _owner) public view returns (uint256 balance);
    function transfer(address _to, uint256 _value) public returns (bool success);
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);
    function approve(address _spender, uint256 _value) public returns (bool success);
    function allowance(address _owner, address _spender) public view returns (uint256 remaining);
    event Transfer(address indexed _from, address indexed _to, uint256 _value); 
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract OFAHCoin is EIP20Interface {
    uint256 constant private MAX_UINT256 = 2**256 - 1;
    mapping (address => uint256) public balances;
    mapping (address => mapping (address => uint256)) public allowed;
    string public name;
    uint8 public decimals = 18;
    string public symbol;

    constructor(
        uint256 _initialAmount,
        string _tokenName,
        string _tokenSymbol
    ) public {
        balances[msg.sender] = _initialAmount;
        totalSupply = _initialAmount * 10 ** uint256(decimals);
        name = _tokenName;
        symbol = _tokenSymbol;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    // ===== Vulnerable transferFrom with Reentrancy =====
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        uint256 allowance = allowed[_from][msg.sender];
        require(balances[_from] >= _value && allowance >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        uint size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            bool callSuccess;
            bytes memory unused;
            (callSuccess, unused) = _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            require(callSuccess, "Token transfer notification failed");
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
