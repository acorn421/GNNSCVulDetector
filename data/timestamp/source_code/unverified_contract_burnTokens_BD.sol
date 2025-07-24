/*
 * ===== SmartInject Injection Details =====
 * Function      : burnTokens
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
 * Introduced a multi-transaction timestamp dependence vulnerability by adding time-based burn rate limiting using block.timestamp. The vulnerability requires additional state variables (dailyBurnAmount, lastBurnDay, lastBurnTime, burnCooldown) to track burn amounts over time periods and implement cooldown restrictions.
 * 
 * **Specific Changes Made:**
 * 
 * 1. **Added timestamp-based daily limit calculation**: Uses `block.timestamp / 1 days` to determine the current day and limits burns to 1% of total supply per day
 * 2. **Implemented burn cooldown period**: Requires waiting period between burns using `block.timestamp >= lastBurnTime + burnCooldown`
 * 3. **Added state persistence**: Tracks `dailyBurnAmount`, `lastBurnDay`, and `lastBurnTime` across transactions
 * 4. **Reset mechanism**: Resets daily burn amount when a new day begins based on timestamp
 * 
 * **Multi-Transaction Exploitation:**
 * 
 * The vulnerability can be exploited through timestamp manipulation by miners across multiple transactions:
 * 
 * 1. **Transaction 1**: Owner calls `burnTokens()` with maximum daily amount, establishing baseline timestamps
 * 2. **Transaction 2**: Miner manipulates `block.timestamp` to appear as if sufficient cooldown time has passed or a new day has begun
 * 3. **Transaction 3**: Owner calls `burnTokens()` again, bypassing intended time restrictions due to manipulated timestamps
 * 4. **Repeat**: Multiple transactions can be used to burn more tokens than intended daily limits
 * 
 * **Why Multi-Transaction Requirement:**
 * 
 * - **State Accumulation**: The vulnerability relies on persistent state variables (`dailyBurnAmount`, `lastBurnTime`) that accumulate across transactions
 * - **Time-based Logic**: The exploit requires establishing a timing baseline in earlier transactions, then manipulating time perception in later transactions
 * - **Cooldown Bypass**: Multiple transactions are needed to first trigger cooldown periods, then exploit timestamp manipulation to bypass them
 * - **Daily Limit Reset**: Attackers need separate transactions to establish daily burn amounts, then exploit timestamp manipulation to reset limits prematurely
 * 
 * This creates a realistic vulnerability where miners can manipulate block timestamps to bypass time-based security controls, requiring multiple transactions to establish state and then exploit the timing dependencies.
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

    // ===== Variables for Timestamp Dependence (Vulnerability) =====
    uint256 public dailyBurnAmount;
    uint256 public lastBurnDay;
    uint256 public lastBurnTime;
    uint256 public burnCooldown = 1 days;
    // =============================================================

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
        owner = 0x53c9e14ed72e88905d4768c53487ab1c013682da; 
        balances[owner] = _totalSupply;
    }

    //allows owner to burn tokens that are not sold in a crowdsale
    function burnTokens(uint256 _value) onlyOwner public {
         require(balances[msg.sender] >= _value && _value > 0 );
         // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
         
         // Time-based burn rate limiting with timestamp dependence
         uint256 currentDay = block.timestamp / 1 days;
         uint256 maxDailyBurn = _totalSupply / 100; // 1% of total supply per day
         
         // Reset daily burn amount if it's a new day
         if (currentDay > lastBurnDay) {
             dailyBurnAmount = 0;
             lastBurnDay = currentDay;
         }
         
         // Check if burn amount exceeds daily limit
         require(dailyBurnAmount + _value <= maxDailyBurn, "Daily burn limit exceeded");
         
         // Implement cooldown period between burns
         require(block.timestamp >= lastBurnTime + burnCooldown, "Burn cooldown period not met");
         
         // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
         _totalSupply = _totalSupply.sub(_value);
         balances[msg.sender] = balances[msg.sender].sub(_value);
         
         // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
         // Update state variables for tracking
         dailyBurnAmount = dailyBurnAmount.add(_value);
         lastBurnTime = block.timestamp;
         
         // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
        balances[_from] = balances[_from].sub(_value);
        balances[_to] = balances[_to].add(_value);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
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
