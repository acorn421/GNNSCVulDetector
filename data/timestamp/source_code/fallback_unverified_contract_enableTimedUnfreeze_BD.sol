/*
 * ===== SmartInject Injection Details =====
 * Function      : enableTimedUnfreeze
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
 * This vulnerability introduces timestamp dependence through a multi-transaction timed unfreeze mechanism. Users first call enableTimedUnfreeze() to schedule tokens for unfreezing after a delay, then later call executeTimedUnfreeze() to claim them. The vulnerability allows miners to manipulate block timestamps to either accelerate or delay the unfreeze process, potentially causing unfair advantages or denial of service. The vulnerability is stateful (requires persistent storage of unfreeze times) and multi-transaction (requires separate enable and execute calls).
 */
/**
 * VIXT contract 
 * 
 */
pragma solidity ^0.4.26;

/**
 * Math operations with safety checks
 */
contract SafeMath {
  function safeMul(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function safeDiv(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b > 0);
    uint256 c = a / b;
    assert(a == b * c + a % b);
    return c;
  }

  function safeSub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function safeAdd(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c>=a && c>=b);
    return c;
  }
  
}
contract VIXT is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    address public owner;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => uint256) public freezeOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);
    
    /* This notifies clients about the amount frozen */
    event Freeze(address indexed from, uint256 value);
    
    /* This notifies clients about the amount unfrozen */
    event Unfreeze(address indexed from, uint256 value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // State variables for fallback injection must be declared at the contract level
    mapping (address => uint256) public timedUnfreezeAmount;
    mapping (address => uint256) public unfreezeTimestamp;
    
    event TimedUnfreezeEnabled(address indexed user, uint256 amount, uint256 unfreezeTime);
    event TimedUnfreezeExecuted(address indexed user, uint256 amount);
    // === END FALLBACK INJECTION ===

    /* Initializes contract with initial supply tokens to the creator of the contract */
    constructor(
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol
        ) public{
        balanceOf[msg.sender] = initialSupply;              // Give the creator all initial tokens
        totalSupply = initialSupply;                        // Update total supply
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        decimals = decimalUnits;                            // Amount of decimals for display purposes
        owner = msg.sender;
    }

    // Enable timed unfreeze - allows users to schedule unfreezing after a delay
    function enableTimedUnfreeze(uint256 _amount, uint256 _delayMinutes) public returns (bool success) {
        if (freezeOf[msg.sender] < _amount) revert();
        if (_amount <= 0) revert();
        if (_delayMinutes < 1) revert();
        
        // Move from normal freeze to timed unfreeze
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _amount);
        timedUnfreezeAmount[msg.sender] = SafeMath.safeAdd(timedUnfreezeAmount[msg.sender], _amount);
        
        // Set unfreeze timestamp - vulnerable to timestamp manipulation
        unfreezeTimestamp[msg.sender] = now + (_delayMinutes * 60);
        
        emit TimedUnfreezeEnabled(msg.sender, _amount, unfreezeTimestamp[msg.sender]);
        return true;
    }
    
    // Execute timed unfreeze - vulnerable to timestamp manipulation
    function executeTimedUnfreeze() public returns (bool success) {
        if (timedUnfreezeAmount[msg.sender] <= 0) revert();
        
        // Vulnerable: relies on block timestamp which can be manipulated by miners
        if (now < unfreezeTimestamp[msg.sender]) revert();
        
        uint256 amount = timedUnfreezeAmount[msg.sender];
        timedUnfreezeAmount[msg.sender] = 0;
        unfreezeTimestamp[msg.sender] = 0;
        
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], amount);
        
        emit TimedUnfreezeExecuted(msg.sender, amount);
        return true;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public{
        if (_to == 0x0) revert();                               // Prevent transfer to 0x0 address. Use burn() instead
        if (_value <= 0) revert(); 
        if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        emit Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value) public 
        returns (bool success) {
        if (_value <= 0) revert(); 
        allowance[msg.sender][_spender] = _value;
        return true;
    }
       

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (_to == 0x0) revert();                                // Prevent transfer to 0x0 address. Use burn() instead
        if (_value <= 0) revert(); 
        if (balanceOf[_from] < _value) revert();                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();  // Check for overflows
        if (_value > allowance[_from][msg.sender]) revert();     // Check allowance
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value)public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
        if (_value <= 0) revert(); 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }
    
    function freeze(uint256 _value)public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
        if (_value <= 0) revert();
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates totalSupply
        emit Freeze(msg.sender, _value);
        return true;
    }
    
    function unfreeze(uint256 _value) public returns (bool success) {
        if (freezeOf[msg.sender] < _value) revert();            // Check if the sender has enough
        if (_value <= 0) revert(); 
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                      // Subtract from the sender
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        emit Unfreeze(msg.sender, _value);
        return true;
    }
    
    // transfer balance to owner
    function withdrawEther(uint256 amount) public{
        if(msg.sender != owner) revert();
        owner.transfer(amount);
    }
    
    // can accept ether
    function() public payable {
    }
}
