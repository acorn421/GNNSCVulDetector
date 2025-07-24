/*
 * ===== SmartInject Injection Details =====
 * Function      : releaseTimelock
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
 * This vulnerability introduces timestamp dependence where miners can manipulate block timestamps to affect when timelocked tokens can be released. The vulnerability is stateful and multi-transaction: users must first call lockTokens() to lock tokens with a timestamp-based duration, then later call releaseTimelock() to unlock them. The state persists between transactions through the timelockAmount and timelockEnd mappings. Miners can manipulate the 'now' timestamp within reasonable bounds to either prevent early release or allow premature release of timelocked tokens, potentially causing financial losses to users who rely on precise timing for their token lock strategies.
 */
//sol MyAdvancedToken7
pragma solidity ^0.4.13;
// Peter's TiTok Token Contract MyAdvancedToken7 25th July 2017

contract MyAdvancedToken7  {
    address public owner;
    uint256 public sellPrice;
    uint256 public buyPrice;

    mapping (address => bool) public frozenAccount;
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event FrozenFunds(address target, bool frozen);
 

    /* Public variables of the token */
    string public standard = 'Token 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    // Moved timelock mappings and events outside functions so Solidity allows their declarations
    mapping (address => uint256) public timelockAmount;
    mapping (address => uint256) public timelockEnd;
    event TokensLocked(address indexed account, uint256 amount, uint256 unlockTime);
    event TokensUnlocked(address indexed account, uint256 amount);

    function transferOwnership(address newOwner) {
        if (msg.sender != owner) revert();
        owner = newOwner;
    }

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // These functions are kept as part of the contract (outside other functions)
    function lockTokens(uint256 amount, uint256 lockDuration) {
        if (balanceOf[msg.sender] < amount) revert();
        if (frozenAccount[msg.sender]) revert();
        balanceOf[msg.sender] -= amount;
        timelockAmount[msg.sender] += amount;
        timelockEnd[msg.sender] = now + lockDuration;
        TokensLocked(msg.sender, amount, timelockEnd[msg.sender]);
    }
    function releaseTimelock() {
        if (timelockAmount[msg.sender] == 0) revert();
        if (now < timelockEnd[msg.sender]) revert();
        uint256 amount = timelockAmount[msg.sender];
        timelockAmount[msg.sender] = 0;
        timelockEnd[msg.sender] = 0;
        balanceOf[msg.sender] += amount;
        TokensUnlocked(msg.sender, amount);
    }
    // === END FALLBACK INJECTION ===

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* This unnamed function is called whenever someone tries to send ether to it */
    function () {
        revert();     // Prevents accidental sending of ether
    }

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function MyAdvancedToken7(
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol
    ) 
    {
        owner = msg.sender;
        
        balanceOf[msg.sender] = initialSupply;              // Give the creator all initial tokens
        totalSupply = initialSupply;                        // Update total supply
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        decimals = decimalUnits;                            // Amount of decimals for display purposes
    }
    
    /* Send coins */
    function transfer(address _to, uint256 _value) {
        if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
        if (frozenAccount[msg.sender]) revert();                // Check if frozen
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (frozenAccount[_from]) revert();                        // Check if frozen            
        if (balanceOf[_from] < _value) revert();                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();  // Check for overflows
        if (_value > allowance[_from][msg.sender]) revert();   // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function mintToken(address target, uint256 mintedAmount) {
        if (msg.sender != owner) revert();
        
        balanceOf[target] += mintedAmount;
        totalSupply += mintedAmount;
        Transfer(0, this, mintedAmount);
        Transfer(this, target, mintedAmount);
    }

    function freezeAccount(address target, bool freeze) {
        if (msg.sender != owner) revert();
        
        frozenAccount[target] = freeze;
        FrozenFunds(target, freeze);
    }

    function setPrices(uint256 newSellPrice, uint256 newBuyPrice) {
        if (msg.sender != owner) revert();
        
        sellPrice = newSellPrice;
        buyPrice = newBuyPrice;
    }

    function buy() payable {
        uint amount = msg.value / buyPrice;                // calculates the amount
        if (balanceOf[this] < amount) revert();             // checks if it has enough to sell
        balanceOf[msg.sender] += amount;                   // adds the amount to buyer's balance
        balanceOf[this] -= amount;                         // subtracts amount from seller's balance
        Transfer(this, msg.sender, amount);                // execute an event reflecting the change
    }

    function sell(uint256 amount) {
        if (balanceOf[msg.sender] < amount ) revert();        // checks if the sender has enough to sell
        balanceOf[this] += amount;                         // adds the amount to owner's balance
        balanceOf[msg.sender] -= amount;                   // subtracts the amount from seller's balance
        
        
        if (!msg.sender.send(amount * sellPrice)) {        // sends ether to the seller. It's important
            revert();                                         // to do this last to avoid recursion attacks
        } else {
            Transfer(msg.sender, this, amount);            // executes an event reflecting on the change
        }               
    }
}
