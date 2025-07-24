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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Call Before State Update**: Introduced a call to `_to.call()` to notify recipient contracts, positioned BEFORE the critical allowance update.
 * 
 * 2. **Violated Checks-Effects-Interactions Pattern**: The allowance state update (`allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value)`) now occurs AFTER the external call, creating a reentrancy window.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker calls `transferFrom()` with a malicious contract as `_to`
 *    - The external call triggers the malicious contract's `onTokenReceived` function
 *    - The malicious contract can re-enter `transferFrom()` with the same allowance (since it hasn't been decremented yet)
 *    - This allows consuming the same allowance multiple times across different transactions
 *    - **Transaction 2+**: Subsequent calls continue to exploit the same allowance until it's finally decremented
 * 
 * 4. **Stateful Nature**: The vulnerability depends on the persistent state of the `allowed` mapping between transactions. The attacker can accumulate multiple transfers using the same allowance across multiple transaction calls.
 * 
 * 5. **Realistic Implementation**: The callback mechanism is a common pattern in modern token contracts (similar to ERC777 hooks), making this injection realistic and subtle.
 * 
 * The vulnerability requires multiple transactions because:
 * - The first transaction establishes the reentrancy condition
 * - Subsequent reentrant calls exploit the unchanged allowance state
 * - The stateful nature of allowances persists between transactions, enabling repeated exploitation
 * - A single transaction alone cannot demonstrate the full impact - the attacker needs to accumulate multiple transfers over time
 */
pragma solidity ^0.4.25;

library SafeMath {
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

// ERC20 Token Smart Contract
contract HOTCOIN {
    
    string public constant name = "HOTCOIN";
    string public constant symbol = "HOT";
    uint8 public constant decimals = 18;
    uint public _totalSupply = 9000000000;
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

    // Its a payable function works as a token factory.
    function () payable {
        createTokens();
    }

    // Constructor
    constructor() public {
        owner = 0xaffdE113872B3fe922DB4F20634f0258ae75fa78; 
        balances[owner] = _totalSupply;
    }

    //allows owner to burn tokens that are not sold in a crowdsale
    function burnTokens(uint256 _value) onlyOwner public {
         require(balances[msg.sender] >= _value && _value > 0 );
         _totalSupply = _totalSupply.sub(_value);
         balances[msg.sender] = balances[msg.sender].sub(_value);
    }

    // This function creates Tokens  
     function createTokens() payable public {
        if(isMinting == true){
            require(msg.value > 0);
            uint256  tokens = msg.value.div(100000000000000).mul(RATE);
            balances[msg.sender] = balances[msg.sender].add(tokens);
            _totalSupply = _totalSupply.add(tokens);
            owner.transfer(msg.value);
        }
        else{
            revert();
        }
    }

    function endCrowdsale() onlyOwner public {
        isMinting = false;
    }

    function changeCrowdsaleRate(uint256 _value) onlyOwner public {
        RATE = _value;
    }
    
    function totalSupply() public view returns(uint256){
        return _totalSupply;
    }
    // What is the balance of a particular account?
    function balanceOf(address _owner) public view returns(uint256){
        return balances[_owner];
    }

     // Transfer the balance from owner's account to another account   
    function transfer(address _to, uint256 _value) public returns(bool) {
        require(balances[msg.sender] >= _value && _value > 0 );
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
    
    // Send _value amount of tokens from address _from to address _to
    // The transferFrom method is used for a withdraw workflow, allowing contracts to send
    // tokens on your behalf, for example to "deposit" to a contract address and/or to charge
    // fees in sub-currencies; the command should fail unless the _from account has
    // deliberately authorized the sender of the message via some mechanism; we propose
    // these standardized APIs for approval:
    function transferFrom(address _from, address _to, uint256 _value) public returns(bool) {
        require(allowed[_from][msg.sender] >= _value && balances[_from] >= _value && _value > 0);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Transfer tokens first
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_from] = balances[_from].sub(_value);
        balances[_to] = balances[_to].add(_value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract if it's a contract address
        uint256 size;
        assembly { size := extcodesize(_to) }
        if(size > 0) {
            // External call to recipient contract before updating allowance
            _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            // Continue execution regardless of call success
        }
        
        // Update allowance AFTER external call - this creates the reentrancy vulnerability
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value);
        return true;
    }

    // Allow _spender to withdraw from your account, multiple times, up to the _value amount.
    // If this function is called again it overwrites the current allowance with _value.
    function approve(address _spender, uint256 _value) public returns(bool){
        allowed[msg.sender][_spender] = _value; 
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    // Returns the amount which _spender is still allowed to withdraw from _owner
    function allowance(address _owner, address _spender) public view returns(uint256){
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
