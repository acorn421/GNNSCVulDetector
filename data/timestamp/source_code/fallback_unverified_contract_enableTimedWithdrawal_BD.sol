/*
 * ===== SmartInject Injection Details =====
 * Function      : enableTimedWithdrawal
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue that requires multiple transactions to exploit. First, an attacker must call enableTimedWithdrawal() to request a withdrawal, which stores the current timestamp. Then, they must wait for the WITHDRAWAL_DELAY period before calling executeTimedWithdrawal(). However, miners can manipulate the timestamp in the second transaction to bypass the delay, allowing premature withdrawal. This is a stateful vulnerability because it requires the withdrawal request state to persist between transactions, and the exploitation depends on the accumulated state from the first transaction.
 */
// Tarka Pre-Sale token smart contract.
// Developed by Phenom.Team <info@phenom.team>

pragma solidity ^0.4.15;

/**
 *   @title SafeMath
 *   @dev Math operations with safety checks that throw on error
 */
library SafeMath {
    function mul(uint256 a, uint256 b) internal constant returns (uint256) {
        uint256 c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function div(uint256 a, uint256 b) internal constant returns(uint256) {
        assert(b > 0);
        uint256 c = a / b;
        assert(a == b * c + a % b);
        return c;
    }

    function sub(uint256 a, uint256 b) internal constant returns(uint256) {
        assert(b <= a);
        return a - b;
    }

    function add(uint256 a, uint256 b) internal constant returns(uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}

contract PreSalePTARK {
    using SafeMath for uint256;
    //Owner address
    address public owner;
    //Public variables of the token
    string public name  = "Tarka Pre-Sale Token";
    string public symbol = "PTARK";
    uint8 public decimals = 18;
    uint256 public totalSupply = 0;
    mapping (address => uint256) public balances;
    // Events Log
    event Transfer(address _from, address _to, uint256 amount); 
    event Burned(address _from, uint256 amount);
    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Mapping to track withdrawal requests
    mapping (address => uint256) public withdrawalRequests;
    // Mapping to track when withdrawal was requested
    mapping (address => uint256) public withdrawalRequestTime;
    // Minimum time that must pass before withdrawal (24 hours)
    uint256 public constant WITHDRAWAL_DELAY = 24 hours;
    
    event WithdrawalRequested(address indexed investor, uint256 amount, uint256 requestTime);
    event WithdrawalExecuted(address indexed investor, uint256 amount);
    
    /**
     * @dev Request a timed withdrawal of tokens
     * @param _amount Amount of tokens to withdraw
     */
    function enableTimedWithdrawal(uint256 _amount) external {
        require(balances[msg.sender] >= _amount);
        require(_amount > 0);
        
        // Store the withdrawal request
        withdrawalRequests[msg.sender] = _amount;
        withdrawalRequestTime[msg.sender] = now; // Vulnerable to timestamp manipulation
        
        WithdrawalRequested(msg.sender, _amount, now);
    }
    
    /**
     * @dev Execute a previously requested withdrawal
     */
    function executeTimedWithdrawal() external {
        require(withdrawalRequests[msg.sender] > 0);
        require(balances[msg.sender] >= withdrawalRequests[msg.sender]);
        
        // Vulnerable check - miners can manipulate timestamp
        require(now >= withdrawalRequestTime[msg.sender] + WITHDRAWAL_DELAY);
        
        uint256 amount = withdrawalRequests[msg.sender];
        
        // Clear the withdrawal request
        withdrawalRequests[msg.sender] = 0;
        withdrawalRequestTime[msg.sender] = 0;
        
        // Burn the tokens (simulate withdrawal)
        balances[msg.sender] = balances[msg.sender].sub(amount);
        totalSupply = totalSupply.sub(amount);
        
        WithdrawalExecuted(msg.sender, amount);
        Burned(msg.sender, amount);
    }
    // === END FALLBACK INJECTION ===

    // Modifiers
    // Allows execution by the contract owner only
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }  

   /**
    *   @dev Contract constructor function sets owner address
    */
    function PreSalePTARK() {
        owner = msg.sender;
    }

   /**
    *   @dev Allows owner to transfer ownership of contract
    *   @param _newOwner      newOwner address
    */
    function transferOwnership(address _newOwner) external onlyOwner {
        require(_newOwner != address(0));
        owner = _newOwner;
    }

   /**
    *   @dev Get balance of investor
    *   @param _investor     investor's address
    *   @return              balance of investor
    */
    function balanceOf(address _investor) public constant returns(uint256) {
        return balances[_investor];
    }

   /**
    *   @dev Mint tokens
    *   @param _investor     beneficiary address the tokens will be issued to
    *   @param _mintedAmount number of tokens to issue
    */
    function mintTokens(address _investor, uint256 _mintedAmount) external onlyOwner {
        require(_mintedAmount > 0);
        balances[_investor] = balances[_investor].add(_mintedAmount);
        totalSupply = totalSupply.add(_mintedAmount);
        Transfer(this, _investor, _mintedAmount);
        
    }

   /**
    *   @dev Burn Tokens
    *   @param _investor     token holder address which the tokens will be burnt
    */
    function burnTokens(address _investor) external onlyOwner {   
        require(balances[_investor] > 0);
        uint256 tokens = balances[_investor];
        balances[_investor] = 0;
        totalSupply = totalSupply.sub(tokens);
        Burned(_investor, tokens);
    }
}
