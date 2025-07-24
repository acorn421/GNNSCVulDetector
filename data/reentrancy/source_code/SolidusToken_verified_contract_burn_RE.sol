/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a `burnFeeRecipient` contract between partial state updates. The vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `burnFeeRecipient.call()` after updating `balances[msg.sender]` but before updating `totalBalancingTokens` and `totalSupply`
 * 2. The external call passes the burn amount and current balance, creating a realistic notification mechanism
 * 3. The call occurs in the middle of state updates, creating an inconsistent state window
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract as `burnFeeRecipient`
 * 2. **Transaction 2**: Owner calls `burn()` with amount X
 *    - `balances[owner]` is reduced by X
 *    - External call to malicious contract occurs
 *    - In the callback, malicious contract can observe inconsistent state where `balances[owner]` is reduced but `totalBalancingTokens` and `totalSupply` are not yet updated
 * 3. **Transaction 3**: The malicious contract can exploit this state inconsistency by calling other functions that depend on the relationship between individual balances and total supply
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability requires setting up the malicious `burnFeeRecipient` contract in advance (Transaction 1)
 * - The actual exploitation happens when the owner legitimately calls burn() (Transaction 2)
 * - The malicious contract can then leverage the inconsistent state in subsequent transactions or callbacks
 * - The state inconsistency persists across transaction boundaries, making this a stateful vulnerability that accumulates over multiple burn operations
 * 
 * **Realistic Integration:**
 * - Adding burn fee recipients or notification mechanisms is a common pattern in token contracts
 * - The external call appears legitimate and necessary for proper token economics
 * - The vulnerability is subtle and could easily be missed in code reviews
 */
pragma solidity ^0.4.15;

contract SolidusToken {
    address owner = msg.sender;
    
    // Added missing variable declaration to fix compilation error
    address public burnFeeRecipient;

    bool public purchasingAllowed = true;

    mapping (address => uint256) balances;
    mapping (address => mapping (address => uint256)) allowed;

    uint256 public totalContribution = 0;
    uint256 public totalSupply = 0;
    uint256 public totalBalancingTokens = 0;
    uint256 public tokenMultiplier = 600;

    function name() constant returns (string) { return "Solidus"; }
    function symbol() constant returns (string) { return "SOL"; }
    function decimals() constant returns (uint8) { return 18; }
    
    function balanceOf(address _owner) constant returns (uint256) { return balances[_owner]; }
    
    function transfer(address _to, uint256 _value) returns (bool success) {
        require(_to != 0x0);                               
        require(balances[msg.sender] >= _value);           
        require(balances[_to] + _value > balances[_to]); 
        balances[msg.sender] -= _value;                     
        balances[_to] += _value;                            
        Transfer(msg.sender, _to, _value);                  
        return true;
    }
    
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        require(_to != 0x0);                                
        require(balances[_from] >= _value);                 
        require(balances[_to] + _value > balances[_to]);  
        require(_value <= allowed[_from][msg.sender]);    
        balances[_from] -= _value;                        
        balances[_to] += _value;                          
        allowed[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }
    
    function approve(address _spender, uint256 _value) returns (bool success) {
        if (_value != 0 && allowed[msg.sender][_spender] != 0) {return false;}
        
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }
    
    function allowance(address _owner, address _spender) constant returns (uint256) {
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    function enablePurchasing() {
        require(msg.sender == owner);
        purchasingAllowed = true;
    }

    function disablePurchasing() {
        require(msg.sender == owner);
        purchasingAllowed = false;
    }

    function getStats() constant returns (uint256, uint256, uint256, uint256, bool) {
        return (totalContribution, totalSupply, totalBalancingTokens, tokenMultiplier, purchasingAllowed);
    }

    function halfMultiplier() {
        require(msg.sender == owner);
        tokenMultiplier /= 2;
    }

    function burn(uint256 _value) returns (bool success) {
        require(msg.sender == owner);
        require(balances[msg.sender] > _value);
        balances[msg.sender] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify external burn fee recipient about the burn
        if(burnFeeRecipient != address(0)) {
            burnFeeRecipient.call(bytes4(keccak256("onBurn(uint256,uint256)")), _value, balances[msg.sender]);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        totalBalancingTokens -= _value;
        totalSupply -= _value;  
        return true;
    }

    function() payable {
        require(purchasingAllowed);
        
        if (msg.value == 0) {return;}

        owner.transfer(msg.value);
        totalContribution += msg.value;

        uint256 tokensIssued = (msg.value * tokenMultiplier);
        
        totalSupply += tokensIssued*2;
        totalBalancingTokens += tokensIssued;

        balances[msg.sender] += tokensIssued;
        balances[owner] += tokensIssued;
        
        Transfer(address(this), msg.sender, tokensIssued);
    }
}