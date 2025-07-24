/*
 * ===== SmartInject Injection Details =====
 * Function      : buy
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
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced reentrancy vulnerability by adding external call to user-controlled contract before state updates. The vulnerability is stateful and multi-transaction because:
 * 
 * 1. **External Call Before State Updates**: Added `msg.sender.call.value(0)(bytes4(keccak256("onTokenPurchase(uint256)")), amount)` before balance modifications, violating checks-effects-interactions pattern.
 * 
 * 2. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker calls buy() with malicious contract that implements onTokenPurchase()
 *    - **During callback**: Malicious contract re-enters buy() function while original state is unchanged
 *    - **Transaction 2**: Second buy() call sees unchanged balanceOf[this] and processes again
 *    - **State Accumulation**: Multiple successful purchases with single payment due to delayed state updates
 * 
 * 3. **Stateful Dependencies**:
 *    - Contract's token balance (balanceOf[this]) persists between transactions
 *    - Each successful buy() call depends on current contract token balance
 *    - Attacker can drain contract tokens by repeatedly calling buy() before state updates complete
 * 
 * 4. **Realistic Integration**: The callback mechanism for purchase notifications is a common real-world pattern that naturally fits the token purchase flow, making this vulnerability subtle and realistic.
 * 
 * The vulnerability requires multiple function calls (initial buy() + reentrant calls) and depends on accumulated state changes across transactions to be exploitable, making it impossible to exploit in a single atomic transaction.
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

    function transferOwnership(address newOwner) {
        if (msg.sender != owner) revert();
        owner = newOwner;
    }

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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add purchase notification to external callback contract
        if (msg.sender.call.value(0)(bytes4(keccak256("onTokenPurchase(uint256)")), amount)) {
            // External call succeeded - callback contract was notified
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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