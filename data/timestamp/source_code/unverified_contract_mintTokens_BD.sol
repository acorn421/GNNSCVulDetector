/*
 * ===== SmartInject Injection Details =====
 * Function      : mintTokens
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by implementing a time-based minting cooldown system with progressive bonuses. The vulnerability requires adding a new state variable `mapping(address => uint256) public lastMintTime` to track the last minting timestamp for each investor.
 * 
 * **Key Changes Made:**
 * 1. Added time-based cooldown logic using `block.timestamp` for critical access control
 * 2. Implemented progressive bonus system that increases minting amounts based on time elapsed
 * 3. State variable `lastMintTime` persists between transactions to track timing
 * 4. Critical minting logic now depends on manipulatable block timestamps
 * 
 * **Multi-Transaction Exploitation:**
 * The vulnerability requires multiple transactions to exploit because:
 * 1. **State Accumulation**: The `lastMintTime` mapping must be initialized in the first transaction
 * 2. **Timing Manipulation**: Miners can manipulate `block.timestamp` across multiple blocks to:
 *    - Bypass cooldown periods prematurely
 *    - Artificially increase bonus multipliers
 *    - Coordinate timing across multiple minting operations
 * 
 * **Exploitation Scenarios:**
 * 1. **Cooldown Bypass**: Miner creates first mint transaction, then manipulates timestamp in subsequent block to bypass the 1-hour cooldown
 * 2. **Bonus Manipulation**: Miner can set timestamps to maximize bonus multipliers, potentially getting 2x, 3x, or higher minting amounts
 * 3. **Coordinated Attacks**: Multiple mint operations across different blocks with carefully manipulated timestamps to maximize token generation
 * 
 * **Why Multi-Transaction Required:**
 * - Initial mint establishes the baseline timestamp in contract state
 * - Subsequent mints depend on this stored state for cooldown/bonus calculations
 * - Timestamp manipulation requires miner control across multiple blocks
 * - The vulnerability compounds with each additional mint operation
 * 
 * This creates a realistic timestamp dependence vulnerability commonly seen in DeFi protocols with time-based restrictions.
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
    // Add lastMintTime mapping to store the last mint timestamp for each investor
    mapping(address => uint256) public lastMintTime;
    // Events Log
    event Transfer(address _from, address _to, uint256 amount); 
    event Burned(address _from, uint256 amount);
    // Modifiers
    // Allows execution by the contract owner only
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }  

   /**
    *   @dev Contract constructor function sets owner address
    */
    constructor() public {
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
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
        require(_mintedAmount > 0);
        
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Time-based minting cooldown - vulnerability: uses block.timestamp for critical logic
        if (lastMintTime[_investor] == 0) {
            lastMintTime[_investor] = block.timestamp;
        } else {
            // 1 hour cooldown period
            require(block.timestamp >= lastMintTime[_investor] + 3600);
        }
        
        // Progressive minting bonus based on time elapsed - increases vulnerability
        uint256 timeElapsed = block.timestamp - lastMintTime[_investor];
        uint256 bonusMultiplier = 1;
        
        // Bonus increases every 24 hours (86400 seconds)
        if (timeElapsed >= 86400) {
            bonusMultiplier = 1 + (timeElapsed / 86400);
        }
        
        uint256 finalAmount = _mintedAmount.mul(bonusMultiplier);
        
        balances[_investor] = balances[_investor].add(finalAmount);
        totalSupply = totalSupply.add(finalAmount);
        lastMintTime[_investor] = block.timestamp;
        
        Transfer(this, _investor, finalAmount);
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
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
