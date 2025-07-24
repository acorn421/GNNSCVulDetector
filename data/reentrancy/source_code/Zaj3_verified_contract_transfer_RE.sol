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
 * Injected a stateful, multi-transaction reentrancy vulnerability by adding an external call to recipient contracts after state changes. The vulnerability requires multiple transactions to exploit: 1) Initial setup where attacker deploys malicious recipient contract, 2) Legitimate user transfers tokens to malicious contract, 3) Malicious contract re-enters during onTokenReceived callback to drain additional tokens. The state changes persist between transactions and the recipient can manipulate balances through recursive calls while the contract state is already modified but before transaction completion.
 */
pragma solidity ^0.4.16;

contract Token{
    uint256 public totalSupply;
    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    function balanceOf(address _owner) public constant returns (uint256 balance);
    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value && balances[_to] + _value > balances[_to]);
        require(_to != 0x0);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Store initial balances for potential cleanup
        uint256 initialSenderBalance = balances[msg.sender];
        uint256 initialRecipientBalance = balances[_to];
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // VULNERABILITY: External call after state changes - allows recipient to re-enter
        if (isContract(_to)) {
            bytes4 selector = bytes4(keccak256("onTokenReceived(address,uint256)"));
            require(_to.call(selector, msg.sender, _value));
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(msg.sender, _to, _value);
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Helper function to check if address is contract
    function isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(addr)
        }
        return size > 0;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);

    function approve(address _spender, uint256 _value) public returns (bool success);  
    function allowance(address _owner, address _spender) public constant returns(uint256 remaining);

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}

contract Zaj3 is Token {

    string public name;
    uint8 public decimals;
    string public symbol;

    constructor() public {
        decimals = 18;
        totalSupply = 1000000 * 10 ** 18;
        balances[msg.sender] = totalSupply;
        name = "Zaj3Token";
        symbol = "Zaj3";
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value && balances[_to] + _value > balances[_to]);
        require(_to != 0x0);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(balances[_from] >= _value && allowed[_from][msg.sender] >= _value);
        balances[_to] += _value;
        balances[_from] -= _value;
        allowed[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balances[msg.sender] >= _value);
        totalSupply -= _value;
        balances[msg.sender] -= _value;
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
}