/*
 * ===== SmartInject Injection Details =====
 * Function      : _buyTokens
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability through time-based rate adjustments and cumulative purchase bonuses. The vulnerability requires:
 * 
 * 1. **State Variables** (assumed to be added to contract):
 *    - `uint256 lastRateUpdate` - tracks when rate was last updated
 *    - `mapping(address => uint256) userFirstPurchase` - tracks first purchase timestamp per user
 * 
 * 2. **Multi-Transaction Exploitation**:
 *    - **Transaction 1**: Initial purchase establishes `lastRateUpdate` and `userFirstPurchase[user]` timestamps
 *    - **Wait Period**: Attacker waits for time to pass (minimum 5-10 minutes)
 *    - **Transaction 2+**: Subsequent purchases exploit both increased rate and cumulative bonuses
 * 
 * 3. **Vulnerability Mechanics**:
 *    - Rate increases by 10 tokens per wei every 5 minutes since last update
 *    - Users get 5% bonus per 10-minute interval since their first purchase
 *    - Attackers can manipulate timing by controlling when rate updates occur
 *    - Multiple users can coordinate to maximize rate increases before making large purchases
 * 
 * 4. **Realistic Exploitation**:
 *    - Attacker makes small initial purchase to set timestamps
 *    - Waits for favorable timing (when rate is about to increase)
 *    - Makes large purchase to benefit from inflated rates and bonuses
 *    - Can coordinate with multiple accounts to amplify rate increases
 * 
 * This creates a genuine multi-transaction vulnerability where the exploit value accumulates over time and requires strategic timing across multiple transactions to maximize token acquisition.
 */
pragma solidity ^0.4.24;
// ----------------------------------------------------------------------------
// Safe maths
// ----------------------------------------------------------------------------
library SafeMath {
    function add(uint a, uint b) internal pure returns (uint c) {
        c = a + b;
        require(c >= a);
    }
    function sub(uint a, uint b) internal pure returns (uint c) {
        require(b <= a);
        c = a - b;
    }
    function mul(uint a, uint b) internal pure returns (uint c) {
        c = a * b;
        require(a == 0 || c / a == b);
    }
    function div(uint a, uint b) internal pure returns (uint c) {
        require(b > 0);
        c = a / b;
    }
}

// ----------------------------------------------------------------------------
// ERC Token Standard #20 Interface
// ----------------------------------------------------------------------------
contract ERC20Interface {
    function totalSupply() public constant returns (uint);
    function balanceOf(address tokenOwner) public constant returns (uint balance);
    event Transfer(address indexed from, address indexed to, uint tokens);
    event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
}

contract TicHTUContract is ERC20Interface{
    using SafeMath for uint;
    
    string public symbol;
    string public name;
    uint8 public decimals;
    uint _totalSupply;
    uint256 public rate;
    address owner;
    mapping(address => uint) balances;
    mapping(address => mapping(address => uint)) allowed;
    event TokenPurchase(address indexed purchaser, address indexed beneficiary, uint256 value, uint256 amount);
    
    // ===== ADDED MISSING STATE VARIABLES =====
    uint256 public lastRateUpdate;
    mapping(address => uint256) public userFirstPurchase;
    // =========================================
    
    // ------------------------------------------------------------------------
    // Constructor
	// @_owner: owner's address where to keep donations
    // ------------------------------------------------------------------------
    constructor() public{
        symbol = "HTU";
        name = "HONTUBE";
        decimals = 18;
        rate = 500; //OBL per wei
        owner = msg.sender;
        _totalSupply = totalSupply();
        balances[this] = _totalSupply;
        emit Transfer(address(0),this,_totalSupply);
    }
    
    function totalSupply() public constant returns (uint){
       return 25000000000 * 10**uint(decimals); //25 billion
    }
    
    // ------------------------------------------------------------------------
    // Get the token balance for account `tokenOwner`
    // ------------------------------------------------------------------------
    function balanceOf(address tokenOwner) public constant returns (uint balance) {
        return balances[tokenOwner];
    }
    
    // ------------------------------------------------------------------------
    // Transfers the tokens from contracts balance of OBL's
    // ------------------------------------------------------------------------
    function _transfer(address _to, uint _tokens) internal returns (bool success){
        require(_to != 0x0);

        require(balances[_to] + _tokens >= balances[_to]);
        balances[this] = balances[this].sub(_tokens);
        balances[_to] = balances[_to].add(_tokens);
        emit Transfer(this,_to,_tokens);
        return true;
    }

    // ------------------------------------------------------------------------
    // payable function to receive ethers
    // ------------------------------------------------------------------------
    function () external payable{
        _buyTokens(msg.sender);
    }
    // ------------------------------------------------------------------------
    // verifies, calculates and sends tokens to beneficiary
    // ------------------------------------------------------------------------
    function _buyTokens(address _beneficiary) public payable{
        
        uint256 weiAmount = msg.value;
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-based rate adjustment with accumulated state
        if (lastRateUpdate == 0) {
            lastRateUpdate = block.timestamp;
        }
        
        // Update rate based on time elapsed since last update
        uint256 timeElapsed = block.timestamp - lastRateUpdate;
        if (timeElapsed >= 300) { // 5 minutes
            uint256 rateMultiplier = timeElapsed / 300;
            rate = rate + (rateMultiplier * 10); // Increase rate by 10 per 5-minute interval
            lastRateUpdate = block.timestamp;
        }
        
        // Store purchase timestamp for cumulative bonus calculation
        if (userFirstPurchase[_beneficiary] == 0) {
            userFirstPurchase[_beneficiary] = block.timestamp;
        }
        
        // Calculate base tokens
        uint256 tokens = _getTokenAmount(weiAmount);
        
        // Apply cumulative time-based bonus for repeat purchases
        uint256 timeSinceFirstPurchase = block.timestamp - userFirstPurchase[_beneficiary];
        if (timeSinceFirstPurchase >= 600) { // 10 minutes
            uint256 bonusMultiplier = timeSinceFirstPurchase / 600;
            tokens = tokens + (tokens * bonusMultiplier * 5 / 100); // 5% bonus per 10-minute interval
        }
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        
        _preValidatePurchase(_beneficiary, weiAmount, tokens);

        _processPurchase(_beneficiary, tokens);
        emit TokenPurchase(this, _beneficiary, weiAmount, tokens);

        _forwardFunds();
    }
	// ------------------------------------------------------------------------
    // verifies the (sender address, amount of ethers)
	// Checks if balance does not exceeds 650 OBL
    // ------------------------------------------------------------------------
    function _preValidatePurchase(address _beneficiary, uint256 _weiAmount, uint256 tokens) view internal {
        require(_beneficiary != address(0x0));
        require(_weiAmount != 0);
    }
	// ------------------------------------------------------------------------
    // calculates amount of tokens given weiAmount
    // ------------------------------------------------------------------------
    function _getTokenAmount(uint256 _weiAmount) view internal returns (uint256) {
        return _weiAmount.mul(rate);
    }
    
    // ------------------------------------------------------------------------
    // calculates amount of tokens given weiAmount
    // ------------------------------------------------------------------------
    function _changeRate(uint256 _rate){
        rate = _rate;
    }
	// ------------------------------------------------------------------------
    // calls ERC20's transfer function to send tokens to beneficiary
    // ------------------------------------------------------------------------
    function _deliverTokens(address _beneficiary, uint256 _tokenAmount) internal {
        _transfer(_beneficiary,_tokenAmount);
    }
	// ------------------------------------------------------------------------
    // deliver tokens to the beneficiary
    // ------------------------------------------------------------------------
    function _processPurchase(address _beneficiary, uint256 _tokenAmount) internal {
        _deliverTokens(_beneficiary, _tokenAmount);
    }
	// ------------------------------------------------------------------------
    // forward donations to the owner
    // ------------------------------------------------------------------------
    function _forwardFunds() internal {
        owner.transfer(msg.value);
    }
}
