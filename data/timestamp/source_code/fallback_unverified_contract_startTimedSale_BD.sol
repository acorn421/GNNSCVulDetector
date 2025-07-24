/*
 * ===== SmartInject Injection Details =====
 * Function      : startTimedSale
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 8 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction timestamp dependence vulnerability through a timed token sale system. The vulnerability requires multiple transactions to exploit: 1) The sale must be started by the owner, 2) Attackers must purchase tokens during manipulated timestamps, 3) They can claim early buyer bonuses based on timestamp calculations. The vulnerability allows miners to manipulate block timestamps to appear as early buyers and claim bonuses they shouldn't be eligible for. The state persists across transactions through purchaseTimestamps and purchaseAmounts mappings, making this a classic stateful vulnerability that cannot be exploited in a single transaction.
 */
pragma solidity ^0.4.19;

/**
 * Math operations with safety checks
 */
contract SafeMath {
    function safeAdd(uint256 x, uint256 y) internal returns(uint256) {
      uint256 z = x + y;
      assert((z >= x) && (z >= y));
      return z;
    }

    function safeSubtract(uint256 x, uint256 y) internal returns(uint256) {
      assert(x >= y);
      uint256 z = x - y;
      return z;
    }

    function safeMult(uint256 x, uint256 y) internal returns(uint256) {
      uint256 z = x * y;
      assert((x == 0)||(z/x == y));
      return z;
    }

  function assert(bool assertion) internal {
    if (!assertion) {
      throw;
    }
  }
}
contract HELP is SafeMath{
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
    // Timed sale state variables
    uint256 public saleStartTime;
    uint256 public saleEndTime;
    uint256 public salePrice; // tokens per wei
    bool public saleActive;
    mapping(address => uint256) public purchaseTimestamps;
    mapping(address => uint256) public purchaseAmounts;
    
    event SaleStarted(uint256 startTime, uint256 endTime, uint256 price);
    event TokensPurchased(address buyer, uint256 amount, uint256 timestamp);
    event SaleEnded();

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function HELP(
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol
        ) {
        balanceOf[msg.sender] = initialSupply;              // Give the creator all initial tokens
        totalSupply = initialSupply;                        // Update total supply
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        decimals = decimalUnits;                            // Amount of decimals for display purposes
        owner = msg.sender;
    }

    // Start a timed token sale - vulnerable to timestamp manipulation
    function startTimedSale(uint256 _duration, uint256 _price) {
        if(msg.sender != owner) throw;
        if(saleActive) throw;
        if(_duration <= 0) throw;
        if(_price <= 0) throw;
        
        saleStartTime = now; // Vulnerable: uses block.timestamp
        saleEndTime = now + _duration; // Vulnerable: timestamp dependent
        salePrice = _price;
        saleActive = true;
        
        SaleStarted(saleStartTime, saleEndTime, salePrice);
    }
    
    // Purchase tokens during sale - stateful vulnerability requiring multiple transactions
    function purchaseTokens() payable {
        if(!saleActive) throw;
        if(msg.value <= 0) throw;
        if(now < saleStartTime) throw; // Vulnerable: timestamp check
        if(now > saleEndTime) throw;   // Vulnerable: timestamp check
        
        uint256 tokensToTransfer = SafeMath.safeMult(msg.value, salePrice);
        if(balanceOf[owner] < tokensToTransfer) throw;
        
        // Store purchase info for potential early buyer bonuses
        purchaseTimestamps[msg.sender] = now; // Vulnerable: stores timestamp
        purchaseAmounts[msg.sender] = SafeMath.safeAdd(purchaseAmounts[msg.sender], tokensToTransfer);
        
        balanceOf[owner] = SafeMath.safeSubtract(balanceOf[owner], tokensToTransfer);
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], tokensToTransfer);
        
        TokensPurchased(msg.sender, tokensToTransfer, now);
        Transfer(owner, msg.sender, tokensToTransfer);
    }
    
    // Claim early buyer bonus - exploitable through timestamp manipulation
    function claimEarlyBuyerBonus() {
        if(!saleActive) throw;
        if(purchaseAmounts[msg.sender] <= 0) throw;
        if(purchaseTimestamps[msg.sender] <= 0) throw;
        
        // Vulnerable: bonus calculation depends on timestamp difference
        uint256 timeSinceStart = SafeMath.safeSubtract(now, saleStartTime);
        uint256 saleWindowQuarter = SafeMath.safeSubtract(saleEndTime, saleStartTime) / 4;
        
        // Early buyers (first quarter) get 10% bonus
        if(timeSinceStart <= saleWindowQuarter && purchaseTimestamps[msg.sender] <= saleStartTime + saleWindowQuarter) {
            uint256 bonusTokens = purchaseAmounts[msg.sender] / 10; // 10% bonus
            if(balanceOf[owner] >= bonusTokens) {
                balanceOf[owner] = SafeMath.safeSubtract(balanceOf[owner], bonusTokens);
                balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], bonusTokens);
                Transfer(owner, msg.sender, bonusTokens);
                
                // Reset to prevent double claiming
                purchaseAmounts[msg.sender] = 0;
                purchaseTimestamps[msg.sender] = 0;
            }
        }
    }
    
    // End sale manually or automatically - timestamp dependent
    function endSale() {
        if(msg.sender != owner && now <= saleEndTime) throw; // Owner can end early, or auto-end after time
        if(!saleActive) throw;
        
        saleActive = false;
        SaleEnded();
    }
    // === END FALLBACK INJECTION ===

    /* Send tokens */
    function transfer(address _to, uint256 _value) {
        if (_to == 0x0) throw;                               // Prevent transfer to 0x0 address. Use burn() instead
        if (_value <= 0) throw;
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] = SafeMath.safeSubtract(balanceOf[msg.sender], _value);                     // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        returns (bool success) {
        if (_value <= 0) throw;
        allowance[msg.sender][_spender] = _value;
        return true;
    }


    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (_to == 0x0) throw;                                // Prevent transfer to 0x0 address. Use burn() instead
        if (_value <= 0) throw;
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;     // Check allowance
        balanceOf[_from] = SafeMath.safeSubtract(balanceOf[_from], _value);                           // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSubtract(allowance[_from][msg.sender], _value);
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
        if (_value <= 0) throw;
        balanceOf[msg.sender] = SafeMath.safeSubtract(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSubtract(totalSupply,_value);                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function freeze(uint256 _value) returns (bool success) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
        if (_value <= 0) throw;
        balanceOf[msg.sender] = SafeMath.safeSubtract(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates totalSupply
        Freeze(msg.sender, _value);
        return true;
    }

    function unfreeze(uint256 _value) returns (bool success) {
        if (freezeOf[msg.sender] < _value) throw;            // Check if the sender has enough
        if (_value <= 0) throw;
        freezeOf[msg.sender] = SafeMath.safeSubtract(freezeOf[msg.sender], _value);                      // Subtract from the sender
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        Unfreeze(msg.sender, _value);
        return true;
    }
    
    // transfer balance to owner
    function withdrawEther(uint256 amount) {
        if(msg.sender != owner)throw;
        owner.transfer(amount);
    }
    
    // can accept ether
    function() payable {
    }
}
