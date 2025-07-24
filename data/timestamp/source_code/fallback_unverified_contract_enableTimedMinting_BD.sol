/*
 * ===== SmartInject Injection Details =====
 * Function      : enableTimedMinting
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
 * This vulnerability involves timestamp dependence where the minting functionality relies on block.timestamp (now) to determine the current minting period. The vulnerability is stateful and multi-transaction because: 1) The contract state tracks currentPeriodMinted and lastMintPeriod across transactions, 2) An attacker (miner) can manipulate timestamps across multiple blocks to reset the minting period counter and exceed the intended minting limits, 3) The exploit requires multiple transactions: first to enable timed minting, then multiple minting calls with manipulated timestamps to exceed limits, 4) The vulnerability persists in contract state between transactions through the period tracking variables.
 */
pragma solidity ^0.4.25;

/******************************************/
/*     Netkiller Standard safe token      */
/******************************************/
/* Author netkiller <netkiller@msn.com>   */
/* Home http://www.netkiller.cn           */
/* Version 2018-09-30                     */
/******************************************/

/**
 * @title SafeMath
 * @dev Math operations with safety checks that revert on error
 */
library SafeMath {

  /**
  * @dev Multiplies two numbers, reverts on overflow.
  */
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }

    uint256 c = a * b;
    require(c / a == b);

    return c;
  }

  /**
  * @dev Integer division of two numbers truncating the quotient, reverts on division by zero.
  */
  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b > 0);
    uint256 c = a / b;
    return c;
  }

  /**
  * @dev Subtracts two numbers, reverts on overflow (i.e. if subtrahend is greater than minuend).
  */
  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b <= a);
    uint256 c = a - b;

    return c;
  }

  /**
  * @dev Adds two numbers, reverts on overflow.
  */
  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    require(c >= a);

    return c;
  }

  /**
  * @dev Divides two numbers and returns the remainder (unsigned integer modulo),
  * reverts when dividing by zero.
  */
  function mod(uint256 a, uint256 b) internal pure returns (uint256) {
    require(b != 0);
    return a % b;
  }
}

contract Ownable {
    
    address public owner;
    
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    
    constructor() public {
        owner = msg.sender;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
    
    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0));
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

}

contract NetkillerToken is Ownable{
    
    using SafeMath for uint256;
    
    string public name;
    string public symbol;
    uint public decimals;
    uint256 public totalSupply;
    
    // This creates an array with all balances
    mapping (address => uint256) internal balances;
    mapping (address => mapping (address => uint256)) internal allowed;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Timed minting functionality - enables token minting with timestamp-based restrictions
    bool public timedMintingEnabled = false;
    uint256 public mintingStartTime;
    uint256 public mintingEndTime;
    uint256 public maxMintPerPeriod;
    uint256 public currentPeriodMinted;
    uint256 public lastMintPeriod;
    uint256 public constant MINTING_PERIOD = 1 hours;
    
    // Enable timed minting with specific parameters
    function enableTimedMinting(uint256 _startTime, uint256 _endTime, uint256 _maxPerPeriod) public onlyOwner {
        require(_startTime < _endTime);
        require(_maxPerPeriod > 0);
        
        mintingStartTime = _startTime;
        mintingEndTime = _endTime;
        maxMintPerPeriod = _maxPerPeriod;
        timedMintingEnabled = true;
        lastMintPeriod = 0;
        currentPeriodMinted = 0;
    }
    
    // Mint tokens with timestamp-based restrictions
    function mintTokens(uint256 _amount) public onlyOwner {
        require(timedMintingEnabled);
        require(now >= mintingStartTime && now <= mintingEndTime);
        require(_amount > 0);
        
        // Calculate current period based on timestamp
        uint256 currentPeriod = (now - mintingStartTime) / MINTING_PERIOD;
        
        // Reset counter if we're in a new period
        if (currentPeriod != lastMintPeriod) {
            currentPeriodMinted = 0;
            lastMintPeriod = currentPeriod;
        }
        
        // Check if minting would exceed period limit
        require(currentPeriodMinted + _amount <= maxMintPerPeriod);
        
        // Mint tokens
        totalSupply = totalSupply.add(_amount);
        balances[owner] = balances[owner].add(_amount);
        currentPeriodMinted = currentPeriodMinted.add(_amount);
        
        emit Transfer(address(0), owner, _amount);
    }
    
    // Disable timed minting
    function disableTimedMinting() public onlyOwner {
        timedMintingEnabled = false;
    }
    // === END FALLBACK INJECTION ===

    constructor(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol,
        uint decimalUnits
    ) public {
        owner = msg.sender;
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol; 
        decimals = decimalUnits;
        totalSupply = initialSupply * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balances[msg.sender] = totalSupply;                // Give the creator all initial token
    }

    function balanceOf(address _address) view public returns (uint256 balance) {
        return balances[_address];
    }
    
    /* Internal transfer, only can be called by this contract */
    function _transfer(address _from, address _to, uint256 _value) internal {
        require (_to != address(0));                        // Prevent transfer to 0x0 address. Use burn() instead
        require (balances[_from] >= _value);                // Check if the sender has enough
        require (balances[_to] + _value > balances[_to]);   // Check for overflows
        balances[_from] = balances[_from].sub(_value);      // Subtract from the sender
        balances[_to] = balances[_to].add(_value);          // Add the same to the recipient
        emit Transfer(_from, _to, _value);
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        _transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= balances[_from]);
        require(_value <= allowed[_from][msg.sender]);     // Check allowance
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowed[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }
    function allowance(address _owner, address _spender) view public returns (uint256 remaining) {
        return allowed[_owner][_spender];
    }

    function airdrop(address[] _to, uint256 _value) onlyOwner public returns (bool success) {
        
        require(_value > 0 && balanceOf(msg.sender) >= _value.mul(_to.length));
        
        for (uint i=0; i<_to.length; i++) {
            _transfer(msg.sender, _to[i], _value);
        }
        return true;
    }
    
    function batchTransfer(address[] _to, uint256[] _value) onlyOwner public returns (bool success) {
        require(_to.length == _value.length);

        uint256 amount = 0;
        for(uint n=0;n<_value.length;n++){
            amount = amount.add(_value[n]);
        }
        
        require(amount > 0 && balanceOf(msg.sender) >= amount);
        
        for (uint i=0; i<_to.length; i++) {
            transfer(_to[i], _value[i]);
        }
        return true;
    }
}