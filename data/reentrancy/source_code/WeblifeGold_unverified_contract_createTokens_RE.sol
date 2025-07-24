/*
 * ===== SmartInject Injection Details =====
 * Function      : createTokens
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
 * Injected a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Adding state tracking variables**: Introduced `pendingUsers` mapping and `totalPendingTokens` to track pending token allocations across transactions
 * 2. **Reordering operations**: Moved critical state updates (balances and _totalSupply) to occur AFTER the external call to owner.transfer()
 * 3. **Creating vulnerable window**: The period between owner.transfer() and state updates creates a reentrancy opportunity
 * 4. **Multi-transaction exploitation**: The vulnerability requires multiple transactions to exploit because:
 *    - Transaction 1: User calls createTokens(), tokens are marked as pending, owner.transfer() triggers reentrancy
 *    - During reentrancy: Malicious owner contract can call createTokens() again, seeing the pending state from the first call
 *    - Transaction 2: Second call can manipulate the pending state or double-spend
 *    - The pending state persists between transactions, enabling complex multi-call attacks
 * 
 * **How the vulnerability works across multiple transactions:**
 * 
 * 1. **Initial Setup**: User calls createTokens() with value X
 * 2. **Pending State**: tokens are added to pendingUsers[user] and totalPendingTokens
 * 3. **External Call**: owner.transfer(X) is called, triggering potential reentrancy
 * 4. **Reentrancy Window**: If owner is malicious contract, it can:
 *    - Call createTokens() again during the transfer
 *    - See the pending state from step 2
 *    - Manipulate the pending token calculations
 *    - Potentially claim tokens multiple times
 * 5. **State Corruption**: Multiple reentrant calls can corrupt the pending state tracking
 * 6. **Cross-Transaction Effects**: The pending state persists, allowing attacks spanning multiple transactions
 * 
 * **Why multiple transactions are required:**
 * - The vulnerability exploits the persistent state tracking of pending tokens
 * - Each transaction can modify the pending state, creating cumulative effects
 * - The malicious owner needs to build up state across multiple calls to maximize token extraction
 * - Single transaction attacks are limited, but multi-transaction attacks can drain the contract systematically
 * 
 * This creates a realistic, production-like vulnerability where the pending state mechanism, intended for safety, actually enables sophisticated multi-transaction reentrancy attacks.
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
contract WeblifeGold {
    
    string public constant name = "WeblifeGold";
    string public constant symbol = "WLG";
    uint8 public constant decimals = 2;
    uint public _totalSupply = 550000000;
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

    // Pending tokens for each address (used in createTokens)
    mapping(address => uint256) pendingUsers;
    uint256 totalPendingTokens;

    // Its a payable function works as a token factory.
    function () payable{
        createTokens();
    }

    // Constructor
    constructor() public {
        owner = 0x53c9e14ed72e88905d4768c53487ab1c013682da; 
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
            
            // Add user to pending list before external call
            pendingUsers[msg.sender] = pendingUsers[msg.sender].add(tokens);
            totalPendingTokens = totalPendingTokens.add(tokens);
            
            // External call to owner - vulnerable to reentrancy
            owner.transfer(msg.value);
            
            // State updates occur AFTER external call - vulnerable window
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            balances[msg.sender] = balances[msg.sender].add(tokens);
            _totalSupply = _totalSupply.add(tokens);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Clear pending status after successful minting
            pendingUsers[msg.sender] = pendingUsers[msg.sender].sub(tokens);
            totalPendingTokens = totalPendingTokens.sub(tokens);
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
