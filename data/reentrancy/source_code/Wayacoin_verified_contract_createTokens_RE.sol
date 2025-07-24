/*
 * ===== SmartInject Injection Details =====
 * Function      : createTokens
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
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability through the following mechanisms:
 * 
 * 1. **State Accumulation**: Added `accumulatedPurchases` mapping to track cumulative purchases across multiple transactions, creating stateful behavior that persists between calls.
 * 
 * 2. **Progressive Bonus System**: Implemented a bonus multiplier system that activates when accumulated purchases reach 1 ether, incentivizing multiple transactions and creating exploitable state dependencies.
 * 
 * 3. **Vulnerable External Call**: Replaced `owner.transfer()` with `owner.call.value()` and moved it BEFORE state updates, violating the Checks-Effects-Interactions pattern and enabling reentrancy.
 * 
 * 4. **Multi-Transaction Exploitation**: The vulnerability requires multiple transactions to exploit:
 *    - Transaction 1: Make initial purchase to establish state in `accumulatedPurchases`
 *    - Transaction 2+: Continue purchasing to accumulate value and eventually trigger bonus
 *    - During bonus transaction: The external call to owner (if owner is a malicious contract) can re-enter `createTokens()` before balances are updated, allowing double-spending of the bonus multiplier
 * 
 * 5. **Realistic Business Logic**: The progressive bonus system is a realistic feature that could appear in production token sales, making the vulnerability subtle and believable.
 * 
 * The vulnerability is only exploitable across multiple transactions because:
 * - The attacker must first accumulate purchase history through legitimate transactions
 * - The bonus multiplier only activates after reaching the threshold
 * - The reentrancy attack is most effective when the bonus is applied, maximizing token theft
 * - State resets after bonus application, requiring the cycle to restart for repeated exploitation
 */
pragma solidity ^0.4.25;

library SafeMath {
  function mul(uint256 a, uint256 b) internal constant returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal constant returns (uint256) {
    assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  function sub(uint256 a, uint256 b) internal constant returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal constant returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

// ERC20 Token Smart Contract
contract Wayacoin {
    
    string public constant name = "Wayacoin";
    string public constant symbol = "Wya";
    uint8 public constant decimals = 4;
    uint public _totalSupply = 100000000000;
    uint256 public RATE = 1;
    bool public isMinting = true;
    string public constant generatedBy  = "Togen.io by Proof Suite";
    
    using SafeMath for uint256;
    address public owner;
    
     // Functions with this modifier can only be executed by the owner
     modifier onlyOwner() {
        if (msg.sender != owner) {
            revert();
        }
         _;
     }
 
    // Balances for each account
    mapping(address => uint256) balances;
    // Owner of account approves the transfer of an amount to another account
    mapping(address => mapping(address=>uint256)) allowed;

    // Track accumulated purchases to allow bulk discounts
    mapping(address => uint256) accumulatedPurchases;
    mapping(address => uint256) firstPurchaseTime;

    // Its a payable function works as a token factory.
    function () payable{
        createTokens();
    }

    // Constructor
    constructor() public {
        owner = 0xd38e13b0443a925f9fc5c812bb160ba825fe7ce9; 
        balances[owner] = _totalSupply;
    }

    //allows owner to burn tokens that are not sold in a crowdsale
    function burnTokens(uint256 _value) onlyOwner {
         require(balances[msg.sender] >= _value && _value > 0 );
         _totalSupply = _totalSupply.sub(_value);
         balances[msg.sender] = balances[msg.sender].sub(_value);
    }

    // This function creates Tokens  
     function createTokens() payable {
        if(isMinting == true){
            require(msg.value > 0);
            uint256  tokens = msg.value.div(100000000000000).mul(RATE);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Track accumulated purchases to allow bulk discounts
            if(accumulatedPurchases[msg.sender] == 0) {
                firstPurchaseTime[msg.sender] = now;
            }
            accumulatedPurchases[msg.sender] = accumulatedPurchases[msg.sender].add(msg.value);
            
            // Apply progressive bonus for accumulated purchases
            uint256 bonusMultiplier = 1;
            if(accumulatedPurchases[msg.sender] >= 1 ether) {
                bonusMultiplier = 2; // 100% bonus for large accumulated purchases
            }
            
            tokens = tokens.mul(bonusMultiplier);
            
            // External call to owner before state updates for bonus calculation
            bool success = owner.call.value(msg.value)("");
            require(success);
            
            // Update balances after external call (vulnerable to reentrancy)
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balances[msg.sender] = balances[msg.sender].add(tokens);
            _totalSupply = _totalSupply.add(tokens);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Reset accumulated purchases if bonus was applied
            if(bonusMultiplier > 1) {
                accumulatedPurchases[msg.sender] = 0;
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }
        else{
            revert();
        }
    }

    function endCrowdsale() onlyOwner {
        isMinting = false;
    }

    function changeCrowdsaleRate(uint256 _value) onlyOwner {
        RATE = _value;
    }

    function totalSupply() constant returns(uint256){
        return _totalSupply;
    }
    // What is the balance of a particular account?
    function balanceOf(address _owner) constant returns(uint256){
        return balances[_owner];
    }

     // Transfer the balance from owner's account to another account   
    function transfer(address _to, uint256 _value)  returns(bool) {
        require(balances[msg.sender] >= _value && _value > 0 );
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        Transfer(msg.sender, _to, _value);
        return true;
    }

    // Send _value amount of tokens from address _from to address _to
    // The transferFrom method is used for a withdraw workflow, allowing contracts to send
    // tokens on your behalf, for example to "deposit" to a contract address and/or to charge
    // fees in sub-currencies; the command should fail unless the _from account has
    // deliberately authorized the sender of the message via some mechanism; we propose
    // these standardized APIs for approval:
    function transferFrom(address _from, address _to, uint256 _value)  returns(bool) {
        require(allowed[_from][msg.sender] >= _value && balances[_from] >= _value && _value > 0);
        balances[_from] = balances[_from].sub(_value);
        balances[_to] = balances[_to].add(_value);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        Transfer(_from, _to, _value);
        return true;
    }

    // Allow _spender to withdraw from your account, multiple times, up to the _value amount.
    // If this function is called again it overwrites the current allowance with _value.
    function approve(address _spender, uint256 _value) returns(bool){
        allowed[msg.sender][_spender] = _value; 
        Approval(msg.sender, _spender, _value);
        return true;
    }

    // Returns the amount which _spender is still allowed to withdraw from _owner
    function allowance(address _owner, address _spender) constant returns(uint256){
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
