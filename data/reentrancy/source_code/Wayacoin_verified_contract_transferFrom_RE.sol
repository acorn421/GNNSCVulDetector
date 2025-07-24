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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **External Call Injection**: Added a call to recipient contract's onTokenReceived function to notify about incoming tokens
 * 2. **State Update Ordering**: Moved critical state updates (balances[_from] and allowed[_from][msg.sender]) to occur AFTER the external call
 * 3. **Partial State Commitment**: The recipient's balance is updated BEFORE the external call, creating inconsistent state
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * Transaction 1: Attacker calls transferFrom() with malicious contract as _to
 * - Victim's tokens are marked as "sent" (balances[_to] increased)
 * - External call triggers attacker's onTokenReceived function
 * - During callback, attacker can call transferFrom() again because:
 *   - allowed[_from][msg.sender] hasn't been decremented yet
 *   - balances[_from] hasn't been decremented yet
 * - This creates recursive calls where each call increases balances[_to] but doesn't decrease balances[_from] until the end
 * 
 * Transaction 2+: Attacker can continue exploiting if they have accumulated allowances
 * - Each successful reentrancy call builds upon previous state changes
 * - The attacker can drain tokens by repeatedly calling transferFrom with the same allowance
 * - Multiple transactions allow the attacker to reset and repeat the attack pattern
 * 
 * **Why Multi-Transaction:**
 * - The vulnerability requires building up state across multiple calls
 * - Each reentrancy call modifies the persistent state (balances mapping)
 * - The attacker needs multiple transactions to fully exploit all available allowances
 * - The attack can be spread across different blocks to avoid single-transaction gas limits
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

    // Its a payable function works as a token factory.
    function () payable{
        createTokens();
    }

    // Constructor
    constructor() public {
        owner = 0xD38E13B0443A925F9Fc5C812Bb160ba825fe7CE9; 
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
            balances[msg.sender] = balances[msg.sender].add(tokens);
            _totalSupply = _totalSupply.add(tokens);
            owner.transfer(msg.value);
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
        emit Transfer(msg.sender, _to, _value);
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Update recipient balance first
        balances[_to] = balances[_to].add(_value);

        // Check via extcodesize (Solidity <0.5.0 inline assembly version)
        uint256 size;
        assembly { size := extcodesize(_to) }
        if(size > 0) {
            _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, msg.sender, _value));
        }
        // State updates happen AFTER external call - VULNERABLE
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_from] = balances[_from].sub(_value);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value);
        return true;
    }

    // Allow _spender to withdraw from your account, multiple times, up to the _value amount.
    // If this function is called again it overwrites the current allowance with _value.
    function approve(address _spender, uint256 _value) returns(bool){
        allowed[msg.sender][_spender] = _value; 
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    // Returns the amount which _spender is still allowed to withdraw from _owner
    function allowance(address _owner, address _spender) constant returns(uint256){
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
