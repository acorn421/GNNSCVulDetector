/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call**: Inserted a callback mechanism that invokes `ITokenReceiver(_to).onTokenReceived(_from, _value)` on the recipient address if it's a contract
 * 2. **Violated Checks-Effects-Interactions Pattern**: The external call now occurs AFTER balance updates but BEFORE allowance decrement
 * 3. **Added Contract Code Check**: Used `_to.code.length > 0` to detect if recipient is a contract
 * 4. **Added Try-Catch Block**: Wrapped the external call in try-catch to prevent reverting the entire transaction if callback fails
 * 
 * **How the Multi-Transaction Reentrancy Vulnerability Works:**
 * 
 * **Setup Phase (Transaction 1):**
 * - Attacker deploys a malicious contract that implements `ITokenReceiver`
 * - Attacker obtains approval from victim to spend tokens via `approve()`
 * - State: Allowance is set, ready for exploitation
 * 
 * **Exploitation Phase (Transaction 2):**
 * - Attacker calls `transferFrom(victim, maliciousContract, amount)`
 * - Function executes: checks pass, balances are updated
 * - External call to `maliciousContract.onTokenReceived()` is made
 * - **Critical Window**: Balances are updated but allowance is NOT yet decremented
 * - Malicious contract's `onTokenReceived()` callback calls `transferFrom()` again
 * - Second call succeeds because allowance hasn't been decremented yet
 * - This creates a recursive loop where multiple transfers can occur with the same allowance
 * 
 * **Persistence Phase (Transaction 3+):**
 * - If the recursive calls are limited (e.g., by gas), the attacker can continue exploitation in subsequent transactions
 * - The allowance might be partially decremented but not fully consumed
 * - Attacker can repeat the process until allowance is fully drained
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * 
 * 1. **State Accumulation**: The vulnerability exploits the persistent state of allowances across transactions
 * 2. **Gas Limitations**: Deep recursive calls will eventually hit gas limits, requiring multiple transactions to fully exploit
 * 3. **Allowance Mechanism**: The allowance system itself creates a stateful relationship that persists between transactions
 * 4. **Progressive Exploitation**: Each transaction can partially exploit the allowance, with the remaining allowance available for future transactions
 * 
 * **Exploitation Sequence:**
 * ```
 * Transaction 1: approve(attacker, 1000 tokens)
 * Transaction 2: transferFrom() -> triggers reentrancy -> multiple transfers with same allowance
 * Transaction 3: transferFrom() -> exploits remaining allowance from previous incomplete exploitation
 * Transaction N: Continue until allowance is fully drained
 * ```
 * 
 * **Multi-Transaction Nature:**
 * - Cannot be fully exploited in a single transaction due to gas limits on recursive calls
 * - Requires sequential transactions to fully drain the allowance
 * - Each transaction leaves the contract in a partially exploited state that enables further exploitation
 * - The vulnerability spans multiple blocks and transactions, making it a true multi-transaction attack
 */
//sol MyAdvancedToken7
pragma solidity ^0.4.13;
// Peter's TiTok Token Contract MyAdvancedToken7 25th July 2017

interface ITokenReceiver {
    function onTokenReceived(address _from, uint256 _value) external;
}

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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract about the transfer (introduces reentrancy vulnerability)
        if (isContract(_to)) {
            ITokenReceiver(_to).onTokenReceived(_from, _value);
        }
        
        allowance[_from][msg.sender] -= _value;              // Allowance updated AFTER external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(_from, _to, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
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