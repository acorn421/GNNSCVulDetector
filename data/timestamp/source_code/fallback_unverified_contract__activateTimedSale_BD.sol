/*
 * ===== SmartInject Injection Details =====
 * Function      : _activateTimedSale
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection adds a timed sale functionality that is vulnerable to timestamp dependence attacks. The vulnerability is stateful and requires multiple transactions to exploit: 1) First, the owner activates a timed sale using _activateTimedSale(), 2) Users purchase tokens during the sale using _buyTokensTimedSale(), 3) Users can claim refunds using _claimRefund() within 24 hours. The vulnerability allows miners to manipulate block timestamps to extend sale periods, manipulate bonus calculations, and exploit the 24-hour refund window. The state persists across transactions through saleStartTime, saleEndTime, lastPurchaseTime mapping, and other state variables.
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

    // State variables for timed sale functionality
    uint256 public saleStartTime;
    uint256 public saleEndTime;
    uint256 public bonusRate;
    bool public timedSaleActive;
    mapping(address => uint256) public lastPurchaseTime;
    
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

    // ------------------------------------------------------------------------
    // Activates timed sale with bonus rate - vulnerable to timestamp manipulation
    // ------------------------------------------------------------------------
    function _activateTimedSale(uint256 _durationInSeconds, uint256 _bonusRate) public {
        require(msg.sender == owner);
        saleStartTime = now; // Vulnerable: relies on block timestamp
        saleEndTime = now + _durationInSeconds; // Vulnerable: relies on block timestamp
        bonusRate = _bonusRate;
        timedSaleActive = true;
    }

    // ------------------------------------------------------------------------
    // Purchase tokens during timed sale - vulnerable to timestamp manipulation
    // ------------------------------------------------------------------------
    function _buyTokensTimedSale(address _beneficiary) public payable {
        require(timedSaleActive);
        require(now >= saleStartTime && now <= saleEndTime); // Vulnerable: timestamp dependence
        
        uint256 weiAmount = msg.value;
        uint256 baseTokens = _getTokenAmount(weiAmount);
        
        // Time-based bonus calculation - vulnerable to timestamp manipulation
        uint256 timeElapsed = now - saleStartTime;
        uint256 saleDuration = saleEndTime - saleStartTime;
        uint256 bonusMultiplier = bonusRate.mul(saleDuration.sub(timeElapsed)).div(saleDuration);
        
        uint256 bonusTokens = baseTokens.mul(bonusMultiplier).div(100);
        uint256 totalTokens = baseTokens.add(bonusTokens);
        
        _preValidatePurchase(_beneficiary, weiAmount, totalTokens);
        _processPurchase(_beneficiary, totalTokens);
        
        lastPurchaseTime[_beneficiary] = now; // Vulnerable: stores timestamp
        
        emit TokenPurchase(this, _beneficiary, weiAmount, totalTokens);
        _forwardFunds();
    }

    // ------------------------------------------------------------------------
    // Claims refund if sale ended within last 24 hours - multi-transaction vulnerability
    // ------------------------------------------------------------------------
    function _claimRefund() public {
        require(!timedSaleActive || now > saleEndTime); // Vulnerable: timestamp dependence
        require(lastPurchaseTime[msg.sender] > 0);
        require(now - lastPurchaseTime[msg.sender] <= 24 hours); // Vulnerable: 24 hour window using timestamp
        
        uint256 userBalance = balances[msg.sender];
        require(userBalance > 0);
        
        // Calculate refund amount based on time since purchase - vulnerable to manipulation
        uint256 timeSincePurchase = now - lastPurchaseTime[msg.sender];
        uint256 refundPercentage = 100 - (timeSincePurchase.mul(100).div(24 hours));
        uint256 refundAmount = userBalance.mul(refundPercentage).div(100);
        
        // Reset user's purchase time and balance
        lastPurchaseTime[msg.sender] = 0;
        balances[msg.sender] = 0;
        balances[this] = balances[this].add(userBalance);
        
        // Send refund - vulnerable to timing attacks
        msg.sender.transfer(refundAmount);
        
        emit Transfer(msg.sender, this, userBalance);
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
