/*
 * ===== SmartInject Injection Details =====
 * Function      : _changeRate
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding external calls to rate validator contracts before updating the rate state. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external calls to `IRateValidator` contracts via `onRateChange()` callback
 * 2. External calls occur BEFORE the rate state update (violating CEI pattern)
 * 3. Added state tracking variables (`rateChangeCount`, `lastRateUpdate`) that persist between transactions
 * 4. Created a loop that calls multiple external validator contracts
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Attacker deploys malicious validator contract and gets it added to `rateValidators` array
 * 2. **Transaction 2**: Attacker calls `_changeRate()` with target rate
 * 3. **During Transaction 2**: External call to malicious validator triggers reentrancy back to `_changeRate()` with different rate
 * 4. **State Manipulation**: Multiple rate changes occur within single transaction due to reentrancy, but each change increments `rateChangeCount`
 * 5. **Transaction 3+**: Subsequent token purchases use the final manipulated rate while state counters reflect multiple changes
 * 
 * **Why Multiple Transactions Are Required:**
 * - Setup phase requires validator registration in separate transaction
 * - State accumulation (`rateChangeCount`) builds up across multiple rate changes
 * - The vulnerability leverages persistent state between function calls
 * - Token purchases in later transactions use the manipulated rate state
 * - The attack requires coordination between validator deployment, rate manipulation, and token purchase transactions
 * 
 * **State Persistence Impact:**
 * - Rate changes affect all future token purchases via `_getTokenAmount()`
 * - `rateChangeCount` persists and can be used to track manipulation attempts
 * - Multiple rate validators can be called in sequence, each potentially causing reentrancy
 * - The vulnerability creates a chain of stateful operations across multiple transactions
 * 
 * This creates a realistic, production-like vulnerability where external oracle/validator integration introduces reentrancy risks that require multiple transactions to fully exploit.
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

interface IRateValidator {
    function onRateChange(uint256 newRate, uint256 oldRate) external;
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

    IRateValidator[] public rateValidators;
    uint public rateChangeCount;
    uint public lastRateUpdate;
    
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
        
        // calculate OBL tokens to be delivered
        uint256 tokens = _getTokenAmount(weiAmount);
        
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
    function _changeRate(uint256 _rate) public {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify external rate validators before updating rate
        if(rateValidators.length > 0) {
            for(uint i = 0; i < rateValidators.length; i++) {
                IRateValidator(rateValidators[i]).onRateChange(_rate, rate);
            }
        }
        
        rate = _rate;
        rateChangeCount++;
        lastRateUpdate = now;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
