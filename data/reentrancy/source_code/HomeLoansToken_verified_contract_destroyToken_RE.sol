/*
 * ===== SmartInject Injection Details =====
 * Function      : destroyToken
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added persistent state tracking**: `pendingDestruction` mapping stores destruction amounts across transactions
 * 2. **Added external call mechanism**: `complianceChecker` address allows external contract interaction
 * 3. **Violated Checks-Effects-Interactions pattern**: External call (`validateDestruction`) occurs before state updates
 * 4. **Created reentrancy window**: During the external call, the contract can be re-entered while `pendingDestruction` contains accumulated values
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Owner calls `destroyToken(1000)` - sets `pendingDestruction[owner] = 1000`
 * 2. **Transaction 2**: Owner calls `destroyToken(2000)` - sets `pendingDestruction[owner] = 3000` (accumulated)
 * 3. **Transaction 3**: During `validateDestruction` call, malicious compliance checker re-enters `destroyToken(500)`
 * 4. **Reentrancy Impact**: The re-entrant call sees `pendingDestruction[owner] = 3000` and can manipulate state based on accumulated pending destructions
 * 
 * **Why Multi-Transaction Required:**
 * - The vulnerability leverages the persistent `pendingDestruction` state that accumulates across multiple calls
 * - Each transaction can increase the pending amount, creating larger attack surfaces
 * - The malicious compliance checker needs multiple transactions to build up significant pending destruction amounts
 * - Single-transaction exploitation would be limited by the owner's balance, but accumulated pending destructions across multiple transactions can exceed safe limits
 * 
 * **Realistic Integration:**
 * - Compliance checking is a common requirement in financial tokens
 * - The external call pattern mimics real-world regulatory validation
 * - The pending destruction tracking simulates batch processing scenarios
 * - The vulnerability appears subtle and could easily be missed in code review
 */
pragma solidity ^0.4.21;

contract owned {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        if (newOwner != address(0)) {
            owner = newOwner;
        }
    }
}

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns(uint256) {
        uint256 c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }
    function div(uint256 a, uint256 b) internal pure returns(uint256) {
        // assert(b > 0); // Solidity automatically throws when dividing by 0
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold
        return c;
    }
    function sub(uint256 a, uint256 b) internal pure returns(uint256) {
        assert(b <= a);
        return a - b;
    }
    function add(uint256 a, uint256 b) internal pure returns(uint256) {
        uint256 c = a + b;
        assert(c >= a);
        return c;
    }
}

// Interface for compliance checker contract
interface IComplianceChecker {
    function validateDestruction(address _owner, uint256 destroyAmount) external returns (bool);
}

contract HomeLoansToken is owned {
    using SafeMath for uint256;

    string public name;
    string public symbol;
    uint public decimals;
    uint256 public totalSupply;
  
    /// @dev Fix for the ERC20 short address attack http://vessenes.com/the-erc20-short-address-attack-explained/
    /// @param size payload size
    modifier onlyPayloadSize(uint size) {
        require(msg.data.length >= size + 4);
        _;
    }

    /* This creates an array with all balances */
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowed;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint value);

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Add state variable to track pending destructions
    mapping(address => uint256) public pendingDestruction;
    address public complianceChecker;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    constructor(
        uint256 initialSupply,
        string tokenName,
        uint decimalUnits,
        string tokenSymbol
    ) public {
        owner = msg.sender;
        totalSupply = initialSupply.mul(10 ** decimalUnits);
        balanceOf[msg.sender] = totalSupply; // Give the creator half initial tokens
        name = tokenName; // Set the name for display purposes
        symbol = tokenSymbol; // Set the symbol for display purposes
        decimals = decimalUnits; // Amount of decimals for display purposes
    }

    /// @dev Tranfer tokens to address
    /// @param _to dest address
    /// @param _value tokens amount
    /// @return transfer result
    function transfer(address _to, uint256 _value) public onlyPayloadSize(2 * 32) returns(bool success) {
        require(_to != address(0));
        require(_value <= balanceOf[msg.sender]);

        // SafeMath.sub will throw if there is not enough balance.
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);
        Transfer(msg.sender, _to, _value);
        return true;
    }

    /// @dev Tranfer tokens from one address to other
    /// @param _from source address
    /// @param _to dest address
    /// @param _value tokens amount
    /// @return transfer result
    function transferFrom(address _from, address _to, uint256 _value) public onlyPayloadSize(2 * 32) returns(bool success) {
        require(_to != address(0));
        require(_value <= balanceOf[_from]);
        require(_value <= allowed[_from][msg.sender]);
        balanceOf[_from] = balanceOf[_from].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        Transfer(_from, _to, _value);
        return true;
    }

    /// @dev Destroy Tokens
    ///@param destroyAmount Count Token
    function destroyToken(uint256 destroyAmount) public onlyOwner {
        destroyAmount = destroyAmount.mul(10 ** decimals);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Store pending destruction amount for multi-transaction processing
        pendingDestruction[owner] = pendingDestruction[owner].add(destroyAmount);
        // External call to compliance checker before state updates
        if (complianceChecker != address(0)) {
            // Vulnerable: External call before state changes
            bool approved = IComplianceChecker(complianceChecker).validateDestruction(owner, destroyAmount);
            require(approved, "Destruction not approved");
        }
        // State updates happen after external call - VULNERABLE TO REENTRANCY
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[owner] = balanceOf[owner].sub(destroyAmount);
        totalSupply = totalSupply.sub(destroyAmount);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Clear pending destruction after successful completion
        pendingDestruction[owner] = pendingDestruction[owner].sub(destroyAmount);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    /// @dev Approve transfer
    /// @param _spender holder address
    /// @param _value tokens amount
    /// @return result
    function approve(address _spender, uint _value) public returns(bool success) {
        require((_value == 0) || (allowed[msg.sender][_spender] == 0));
        allowed[msg.sender][_spender] = _value;
        Approval(msg.sender, _spender, _value);
        return true;
    }

    /// @dev Token allowance
    /// @param _owner holder address
    /// @param _spender spender address
    /// @return remain amount
    function allowance(address _owner, address _spender) public view returns(uint remaining) {
        return allowed[_owner][_spender];
    }

    /// @dev Withdraw all owner
    function withdraw() public onlyOwner {
        msg.sender.transfer(address(this).balance);
    }
}