/*
 * ===== SmartInject Injection Details =====
 * Function      : SetupToken
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
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call Before State Finalization**: Introduced an external call to TokenRegistry.validateToken() before setting setupDone = true. This creates a reentrancy window where the setupDone flag is still false, allowing the function to be called again.
 * 
 * 2. **Changed Balance Assignment to Accumulation**: Modified `balances[owner] = _totalSupply` to `balances[owner] += _totalSupply` to accumulate balances across multiple calls, making the vulnerability more impactful.
 * 
 * 3. **State Persistence Exploitation**: The vulnerability exploits the fact that setupDone remains false during the external call, allowing an attacker to:
 *    - Transaction 1: Call SetupToken, trigger the external call, and during the callback, call SetupToken again
 *    - Transaction 2: The reentrant call passes the same checks (owner verification and setupDone == false) and accumulates additional balance
 *    - This can be repeated multiple times before setupDone is finally set to true
 * 
 * 4. **Multi-Transaction Requirement**: The vulnerability requires multiple transactions because:
 *    - The attacker needs to deploy a malicious TokenRegistry contract that calls back to SetupToken
 *    - Each reentrant call must be a separate transaction in the callback
 *    - The accumulated state (balances[owner]) persists between calls, making each subsequent call more valuable
 *    - The exploit builds up over multiple function invocations, not just a single atomic transaction
 * 
 * 5. **Realistic Attack Vector**: An attacker could potentially accumulate massive token balances by controlling the TokenRegistry contract and triggering multiple reentrant calls before the setup is finalized, effectively multiplying their token allocation.
 */
pragma solidity ^0.4.13;
 
contract TokenRegistry {
    function validateToken(string tokenName, string tokenSymbol) public returns (bool);
}

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
	
    function SetupToken(string tokenName, string tokenSymbol, uint256 tokenSupply) public
    {
        if (msg.sender == owner && setupDone == false)
        {
            symbol = tokenSymbol;
            name = tokenName;
            _totalSupply = tokenSupply * 100;
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            // External call to token registry for validation before finalizing setup
            // This creates a reentrancy window where setupDone is still false
            TokenRegistry registry = TokenRegistry(0x1234567890123456789012345678901234567890);
            bool isValid = registry.validateToken(tokenName, tokenSymbol);
            if (isValid) {
                balances[owner] += _totalSupply;  // Changed from = to += to accumulate
                setupDone = true;
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
}