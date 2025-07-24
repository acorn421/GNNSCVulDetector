/*
 * ===== SmartInject Injection Details =====
 * Function      : activateTimedBonus
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
 * This vulnerability introduces a stateful, multi-transaction timestamp dependence vulnerability. The exploitation requires multiple steps: 1) Owner activates timed bonus, 2) Malicious miner can manipulate timestamps to extend bonus periods or claim bonuses at advantageous times, 3) Users claim bonuses based on manipulated timestamps. The vulnerability persists across multiple transactions through state variables (bonusActivationTime, bonusEndTime, lastBonusClaim) and allows miners to manipulate the timing of bonus activations and claims.
 */
pragma solidity ^0.4.8;

/**
 * Math operations with safety checks
 */
contract SafeMath {
  function safeMul(uint256 a, uint256 b) internal returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function safeDiv(uint256 a, uint256 b) internal returns (uint256) {
    assert(b > 0);
    uint256 c = a / b;
    assert(a == b * c + a % b);
    return c;
  }

  function safeSub(uint256 a, uint256 b) internal returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function safeAdd(uint256 a, uint256 b) internal returns (uint256) {
    uint256 c = a + b;
    assert(c>=a && c>=b);
    return c;
  }

  function assert(bool assertion) internal {
    if (!assertion) {
      revert();
    }
  }
}
contract CCC is SafeMath{
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
	address public owner;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);
	

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Timed bonus system state variables
    uint256 public bonusActivationTime;
    uint256 public bonusEndTime;
    uint256 public bonusMultiplier;
    bool public bonusActive;
    mapping(address => uint256) public lastBonusClaim;
    // === END TIMED BONUS STATE ===

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function CCC() public {
        balanceOf[msg.sender] = 250000000 * 10 ** 18;              // Give the creator all initial tokens
        totalSupply = 250000000 * 10 ** 18;                        // Update total supply
        name = "CryptoCocktailCoin";                                   // Set the name for display purposes
        symbol = "CCC";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
		owner = msg.sender;
    }

    // Activate a timed bonus period for token holders
    function activateTimedBonus(uint256 _duration, uint256 _multiplier) public {
        if (msg.sender != owner) revert();
        if (_duration <= 0) revert();
        if (_multiplier <= 100) revert(); // Multiplier should be > 100 for bonus
        bonusActivationTime = now; // Vulnerable to timestamp manipulation
        bonusEndTime = now + _duration; // Vulnerable to timestamp manipulation
        bonusMultiplier = _multiplier;
        bonusActive = true;
    }

    // Claim bonus tokens based on current holdings and time
    function claimTimedBonus() public {
        if (!bonusActive) revert();
        if (now < bonusActivationTime) revert(); // Vulnerable to timestamp manipulation
        if (now > bonusEndTime) revert(); // Vulnerable to timestamp manipulation
        if (lastBonusClaim[msg.sender] >= bonusActivationTime) revert(); // Already claimed this bonus period
        uint256 userBalance = balanceOf[msg.sender];
        if (userBalance <= 0) revert();
        // Calculate bonus based on time elapsed and multiplier
        uint256 timeElapsed = now - bonusActivationTime; // Vulnerable to timestamp manipulation
        uint256 bonusTokens = safeMul(userBalance, bonusMultiplier) / 10000; // Percentage based bonus
        // Adjust bonus based on how early the claim is made
        if (timeElapsed < (bonusEndTime - bonusActivationTime) / 2) {
            bonusTokens = safeMul(bonusTokens, 150) / 100; // 50% extra for early claims
        }
        balanceOf[msg.sender] = safeAdd(balanceOf[msg.sender], bonusTokens);
        totalSupply = safeAdd(totalSupply, bonusTokens);
        lastBonusClaim[msg.sender] = now; // Vulnerable to timestamp manipulation
        emit Transfer(address(0), msg.sender, bonusTokens);
    }
    // Deactivate bonus period (only owner)
    function deactivateTimedBonus() public {
        if (msg.sender != owner) revert();
        bonusActive = false;
        bonusActivationTime = 0;
        bonusEndTime = 0;
        bonusMultiplier = 0;
    }
    // === END FALLBACK INJECTION ===

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
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

    function burn(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
		if (_value <= 0) revert(); 
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }
}
