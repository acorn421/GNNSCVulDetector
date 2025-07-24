/*
 * ===== SmartInject Injection Details =====
 * Function      : mintToken
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a stateful, multi-transaction reentrancy flaw by adding an external call to the target contract AFTER state modifications. The exploit requires multiple transactions:
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Setup Transaction**: Attacker deploys a malicious contract with onTokensMinted callback
 * 2. **Initial Grant**: Owner grants minting privileges to the malicious contract or attacker becomes owner through another vulnerability
 * 3. **Reentrancy Attack**: When mintToken is called on the malicious contract, it receives the callback and can re-enter mintToken, exploiting the fact that state was already modified
 * 
 * **State Persistence & Multi-Transaction Nature:**
 * - The vulnerability requires the attacker to first become owner or have owner privileges (Transaction 1)
 * - Then deploy a malicious contract with the callback (Transaction 2)
 * - Finally trigger the reentrancy by calling mintToken on the malicious contract (Transaction 3)
 * - Each re-entrant call multiplies the minted tokens because balanceOf and totalSupply are updated before the external call
 * - The inflated balances persist across all transactions, creating a compounding effect
 * 
 * **Why Multiple Transactions Are Required:**
 * - Setup Phase: Attacker needs to establish owner privileges and deploy malicious contract
 * - Exploitation Phase: The callback mechanism only triggers during the external call, requiring the initial state changes to be committed
 * - State Accumulation: Each reentrancy cycle builds upon the previous state modifications, requiring multiple function calls to achieve significant token inflation
 * 
 * The vulnerability is realistic as notification callbacks are common in token contracts, and the state-before-external-call pattern is a subtle but dangerous violation of the Checks-Effects-Interactions principle.
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
    constructor(
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
        emit Transfer(msg.sender, _to, _value);              // Notify anyone listening that this transfer took place
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
        emit Transfer(_from, _to, _value);
        return true;
    }

    function mintToken(address target, uint256 mintedAmount) {
        if (msg.sender != owner) revert();
        
        balanceOf[target] += mintedAmount;
        totalSupply += mintedAmount;
        emit Transfer(0, this, mintedAmount);
        emit Transfer(this, target, mintedAmount);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify the recipient about the minting
        if (extcodesize(target) > 0) {
            bytes4 selector = bytes4(keccak256("onTokensMinted(uint256)"));
            target.call(selector, mintedAmount);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function freezeAccount(address target, bool freeze) {
        if (msg.sender != owner) revert();
        
        frozenAccount[target] = freeze;
        emit FrozenFunds(target, freeze);
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
        emit Transfer(this, msg.sender, amount);           // execute an event reflecting the change
    }

    function sell(uint256 amount) {
        if (balanceOf[msg.sender] < amount ) revert();        // checks if the sender has enough to sell
        balanceOf[this] += amount;                         // adds the amount to owner's balance
        balanceOf[msg.sender] -= amount;                   // subtracts the amount from seller's balance
        
        
        if (!msg.sender.send(amount * sellPrice)) {        // sends ether to the seller. It's important
            revert();                                         // to do this last to avoid recursion attacks
        } else {
            emit Transfer(msg.sender, this, amount);            // executes an event reflecting on the change
        }               
    }

    // extcodesize utility function for Solidity 0.4.x
    function extcodesize(address _addr) internal view returns (uint size) {
        assembly {
            size := extcodesize(_addr)
        }
    }
}
