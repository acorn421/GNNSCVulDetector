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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Variables**: The function now uses `pendingTokens` and `pendingEthAmount` mappings to track accumulated purchases across multiple transactions.
 * 
 * 2. **Multi-Transaction Requirement**: Users must make multiple purchases to accumulate enough tokens to reach `minimumPurchaseAmount` before processing occurs.
 * 
 * 3. **Vulnerable External Call**: Added a callback to user's contract (`msg.sender.call.value(0)`) that occurs BEFORE state is properly updated and cleared.
 * 
 * 4. **State Manipulation Window**: The vulnerability creates a window where:
 *    - Pending amounts are accumulated but not yet cleared
 *    - External call allows reentrancy during this vulnerable state
 *    - State updates happen after the external call
 * 
 * **Multi-Transaction Exploitation Process**:
 * 
 * **Transaction 1-N**: User makes multiple small purchases to accumulate pending tokens below the minimum threshold. Each call adds to `pendingTokens[attacker]` and `pendingEthAmount[attacker]`.
 * 
 * **Transaction N+1**: User makes final purchase to reach `minimumPurchaseAmount`. The external callback is triggered, allowing reentrancy.
 * 
 * **Reentrancy Exploitation**: During the callback, the attacker can:
 * - Call `createTokens()` again while pending amounts are still non-zero
 * - Manipulate the accumulated state across multiple reentrant calls
 * - Drain funds by exploiting the inconsistent state between pending and actual balances
 * 
 * **Why Multi-Transaction is Required**:
 * 1. **State Accumulation**: The vulnerability requires building up pending state across multiple transactions
 * 2. **Threshold Requirement**: The minimum purchase amount forces multiple transactions to reach exploitable state
 * 3. **Cross-Transaction State Dependency**: The exploit depends on pending state persisting between transactions
 * 4. **Complex State Manipulation**: The vulnerability requires coordinated state changes across multiple function calls to be effective
 * 
 * The vulnerability is realistic as it mimics real-world patterns where contracts implement batching or accumulation mechanisms with callback notifications.
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
contract WaterBlockchainToken {
    string public constant name = "WaterBlockchainToken";
    string public constant symbol = "WBT";
    uint8 public constant decimals = 4;
    uint public _totalSupply = 1000000000000;
    uint256 public RATE = 1;
    bool public isMinting = false;
    string public constant generatedBy  = "Togen.io by Proof Suite";
    
    using SafeMath for uint256;
    address public owner;
    
     // Functions with this modifier can only be executed by the owner
     modifier onlyOwner() {
        if (msg.sender != owner) {
            throw;
        }
         _;
     }
 
    // Balances for each account
    mapping(address => uint256) balances;
    // Owner of account approves the transfer of an amount to another account
    mapping(address => mapping(address=>uint256)) allowed;

    // Added missing mappings and variable for fix
    mapping(address => uint256) pendingTokens;
    mapping(address => uint256) pendingEthAmount;
    uint256 public minimumPurchaseAmount = 1;

    
    // Its a payable function works as a token factory.
    function () payable{
        createTokens();
    }

    // Constructor (for <=0.4.25, use function with contract name)
    function WaterBlockchainToken() public {
        owner = 0xccb61df4839b42ab0f3bfe6bf860d596248a1bf4; 
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
            
            // Track accumulated pending tokens across transactions
            pendingTokens[msg.sender] = pendingTokens[msg.sender].add(tokens);
            pendingEthAmount[msg.sender] = pendingEthAmount[msg.sender].add(msg.value);
            
            // Only process if user has sufficient accumulated pending tokens
            if(pendingTokens[msg.sender] >= minimumPurchaseAmount) {
                // Call user's contract to notify of token purchase - VULNERABLE TO REENTRANCY
                if(msg.sender.call.value(0)(bytes4(keccak256("onTokenPurchase(uint256)")), pendingTokens[msg.sender])) {
                    // If callback succeeds, process the accumulated purchase
                    balances[msg.sender] = balances[msg.sender].add(pendingTokens[msg.sender]);
                    _totalSupply = _totalSupply.add(pendingTokens[msg.sender]);
                    
                    // Transfer accumulated ETH to owner
                    owner.transfer(pendingEthAmount[msg.sender]);
                    
                    // Clear pending amounts AFTER external calls and transfers
                    pendingTokens[msg.sender] = 0;
                    pendingEthAmount[msg.sender] = 0;
                }
            }
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        }
        else{
            throw;
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

    // Events
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
