/*
 * ===== SmartInject Injection Details =====
 * Function      : createTokens
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a multi-transaction timestamp dependence vulnerability through a time-based bonus system. The vulnerability allows manipulation of block.timestamp across multiple transactions to accumulate progressive bonuses:
 * 
 * **Key Changes Made:**
 * 1. **State Variables Added** (assumed to be added to contract):
 *    - `mapping(address => uint256) lastPurchaseTime` - tracks last purchase timestamp per user
 *    - `mapping(address => uint256) consecutiveBonusCount` - tracks consecutive bonus achievements
 * 
 * 2. **Timestamp-Dependent Logic**:
 *    - Uses `block.timestamp` for bonus calculations
 *    - Implements progressive bonus system based on time differences between purchases
 *    - Requires 5+ minute intervals between purchases for 2x bonus
 *    - Compound 6x bonus after 3 consecutive time-based purchases
 * 
 * **Multi-Transaction Exploitation:**
 * This vulnerability requires multiple transactions to exploit because:
 * 
 * 1. **State Accumulation**: The `consecutiveBonusCount` must be built up over multiple transactions
 * 2. **Time-Based Conditions**: Each transaction must meet timing requirements relative to previous ones
 * 3. **Progressive Rewards**: Maximum exploitation (6x tokens) only achievable after 3+ qualifying transactions
 * 
 * **Exploitation Scenario:**
 * 1. **Transaction 1**: User makes initial purchase, establishes `lastPurchaseTime`
 * 2. **Transaction 2**: After 5+ minutes (or timestamp manipulation), user gets 2x bonus and `consecutiveBonusCount = 1`
 * 3. **Transaction 3**: Another 5+ minute interval, user gets 2x bonus and `consecutiveBonusCount = 2`
 * 4. **Transaction 4**: Final qualifying purchase triggers 6x total multiplier (2x time bonus * 3x consecutive bonus)
 * 
 * **Vulnerability Details:**
 * - Miners can manipulate `block.timestamp` within reasonable bounds (900 seconds drift tolerance)
 * - Attackers can time transactions precisely using mempool monitoring
 * - State persistence between transactions enables cumulative exploitation
 * - The vulnerability compounds over time, making later transactions more profitable
 * 
 * This creates a realistic timestamp dependence vulnerability that requires careful timing and state accumulation across multiple transactions to achieve maximum exploitation.
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

    // Needed for bonus logic
    mapping(address => uint256) public lastPurchaseTime;
    mapping(address => uint256) public consecutiveBonusCount;
    
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
    function WeblifeGold() public {
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
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            
            // Time-based bonus system with timestamp dependence
            uint256 bonusMultiplier = 1;
            uint256 currentTime = block.timestamp;
            
            // Store timestamp for bonus calculation across transactions
            if(lastPurchaseTime[msg.sender] == 0) {
                lastPurchaseTime[msg.sender] = currentTime;
            }
            
            // Progressive bonus based on time difference between purchases
            uint256 timeDiff = currentTime - lastPurchaseTime[msg.sender];
            if(timeDiff >= 300) { // 5 minutes in seconds
                bonusMultiplier = 2; // Double tokens for "patient" investors
                consecutiveBonusCount[msg.sender] = consecutiveBonusCount[msg.sender] + 1;
            }
            
            // Compound bonus for multiple consecutive time-based purchases
            if(consecutiveBonusCount[msg.sender] >= 3) {
                bonusMultiplier = bonusMultiplier * 3; // 6x multiplier total
            }
            
            uint256 tokens = msg.value.div(100000000000000).mul(RATE).mul(bonusMultiplier);
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            balances[msg.sender] = balances[msg.sender].add(tokens);
            _totalSupply = _totalSupply.add(tokens);
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
            
            // Update timestamp for next purchase calculation
            lastPurchaseTime[msg.sender] = currentTime;
            
            // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
            owner.transfer(msg.value);
        } else {
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
// The transferFrom method is used for a withdraw workflow, allowing contracts to send tokens on your behalf, for example to "deposit" to a contract address and/or to charge fees in sub-currencies; the command should fail unless the _from account has deliberately authorized the sender of the message via some mechanism; we propose these standardized APIs for approval:
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

// Required ERC20 events
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
