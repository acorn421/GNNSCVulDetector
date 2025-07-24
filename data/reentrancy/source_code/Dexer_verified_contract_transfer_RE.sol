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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after state changes but before the Transfer event. This creates a classic reentrancy condition where:
 * 
 * 1. **State Changes Before External Call**: The balances mapping is updated before the external call, violating the Checks-Effects-Interactions pattern.
 * 
 * 2. **Multi-Transaction Exploitation Path**:
 *    - Transaction 1: Attacker deploys a malicious contract with `onTokenReceived` callback
 *    - Transaction 2: Attacker initiates transfer to malicious contract, triggering the callback
 *    - During callback: Malicious contract can call transfer again before the first call completes
 *    - The persistent balances state allows multiple withdrawals from the same initial balance
 * 
 * 3. **Stateful Nature**: The vulnerability relies on the persistent balances mapping that survives between transactions and function calls. The attacker can accumulate tokens through repeated reentrant calls within the same transaction, but the setup requires multiple transactions to deploy the attack contract and initiate the vulnerable sequence.
 * 
 * 4. **Realistic Implementation**: The callback pattern is common in modern token contracts for notifying recipients, making this vulnerability realistic and subtle.
 * 
 * The vulnerability requires multi-transaction setup (deploy attack contract, then exploit) and leverages persistent state changes to enable token drainage through reentrancy.
 */
pragma solidity ^0.4.13;
 
contract Dexer {
    string public symbol = "DEX";
    string public name = " Dexer ";
    uint8 public constant decimals = 2;
    uint256 _totalSupply = 300000000;
    address owner = 0x35a887e7327cb08e7a510D71a873b09d5055709D;
    bool setupDone = false;
    
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
 
    mapping(address => uint256) balances;
 
    mapping(address => mapping (address => uint256)) allowed;
 
    function Token(address adr) public {
        owner = adr;        
    }
    
    function SetupToken(string tokenName, string tokenSymbol, uint256 tokenSupply) public {
        if (msg.sender == owner && setupDone == false)
        {
            symbol = tokenSymbol;
            name = tokenName;
            _totalSupply = tokenSupply * 100;
            balances[owner] = _totalSupply;
            setupDone = true;
        }
    }
 
    function totalSupply() public constant returns (uint256) {        
        return _totalSupply;
    }
 
    function balanceOf(address _owner) public constant returns (uint256 balance) {
        return balances[_owner];
    }
 
    function transfer(address _to, uint256 _amount) public returns (bool success) {
        if (balances[msg.sender] >= _amount 
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            balances[msg.sender] -= _amount;
            balances[_to] += _amount;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Notify recipient of transfer via callback
            if (isContract(_to)) {
                _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _amount);
                // Continue regardless of callback success
            }
            
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            Transfer(msg.sender, _to, _amount);
            return true;
        } else {
            return false;
        }
    }
 
    function transferFrom(
        address _from,
        address _to,
        uint256 _amount
    ) public returns (bool success) {
        if (balances[_from] >= _amount
            && allowed[_from][msg.sender] >= _amount
            && _amount > 0
            && balances[_to] + _amount > balances[_to]) {
            balances[_from] -= _amount;
            allowed[_from][msg.sender] -= _amount;
            balances[_to] += _amount;
            Transfer(_from, _to, _amount);
            return true;
        } else {
            return false;
        }
    }
 
    function approve(address _spender, uint256 _amount) public returns (bool success) {
        allowed[msg.sender][_spender] = _amount;
        Approval(msg.sender, _spender, _amount);
        return true;
    }
 
    function allowance(address _owner, address _spender) public constant returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }
    
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}
