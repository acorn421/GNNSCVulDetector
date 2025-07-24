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
 * **STATEFUL, MULTI-TRANSACTION Reentrancy Vulnerability Injection**
 * 
 * **1. Changes Made:**
 * - Added an external call using `msg.sender.call.value(0)()` before state updates
 * - The call invokes `onTokenPurchase(uint256)` callback on the buyer's contract
 * - External call occurs after balance validation but before state modifications
 * - Maintains original function logic and signature
 * 
 * **2. Multi-Transaction Exploitation Pattern:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys malicious contract with `onTokenPurchase()` callback
 * - Attacker calls `buy()` with sufficient ETH
 * - During callback, attacker's contract can observe contract state before updates
 * - Attacker notes current `balanceOf[this]` and `balanceOf[attacker]` values
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls `buy()` again with same amount
 * - When callback is triggered, attacker's contract can:
 *   - Call `buy()` recursively while state is inconsistent
 *   - The recursive call sees original `balanceOf[this]` (not yet decremented)
 *   - Multiple token purchases occur with single ETH payment
 *   - Each recursive call passes balance check but uses stale state
 * 
 * **Transaction 3+ (Continued Exploitation):**
 * - Attacker can repeat the pattern across multiple transactions
 * - Each transaction exploits the accumulated inconsistent state
 * - Contract balance drains while attacker accumulates tokens
 * 
 * **3. Why Multi-Transaction Dependency is Critical:**
 * 
 * **State Persistence:** The vulnerability relies on the contract's balance state persisting between transactions, allowing the attacker to setup conditions in one transaction and exploit them in subsequent calls.
 * 
 * **Accumulated Effect:** Each successful exploitation changes the contract's state (`balanceOf` mappings, ETH balance), making future exploitations more profitable as the attacker's balance grows.
 * 
 * **Cross-Transaction Reentrancy:** The external call enables the attacker to re-enter the contract during state transitions, but the full exploitation requires multiple transactions to:
 * - Observe state inconsistencies
 * - Build up accumulated balances
 * - Drain the contract systematically
 * 
 * **Realistic Vulnerability Pattern:** This mirrors real-world reentrancy attacks where callbacks are used for legitimate purposes (notifications, hooks) but create windows for exploitation across multiple transaction contexts.
 */
pragma solidity ^0.4.6;
contract owned {
    address public owner;

    function owned() {
        owner = msg.sender;
    }

    modifier onlyOwner {
        if (msg.sender != owner) throw;
        _;
    }

    function transferOwnership(address newOwner) onlyOwner {
        owner = newOwner;
    }
}

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract BuyerToken is owned {
    /* Public variables of the token */
    string public standard = 'Token 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    uint256 public buyPrice;
    address public project_wallet;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function token(
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
    }
    
    function defineProjectWallet(address target) onlyOwner {
        project_wallet = target;
    }
    
    /* Mint coins */
    function mintToken(address target, uint256 mintedAmount) onlyOwner {
        balanceOf[target] += mintedAmount;
        totalSupply += mintedAmount;
        Transfer(0, this, mintedAmount);
        Transfer(this, target, mintedAmount);
    }
    
    /* Distroy coins */
    function distroyToken(uint256 burnAmount) onlyOwner {
        balanceOf[this] -= burnAmount;
        totalSupply -= burnAmount;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) {
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        tokenRecipient spender = tokenRecipient(_spender);
        return true;
    }

    /* Approve and then comunicate the approved contract in a single tx */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        returns (bool success) {    
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;   // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }
    
    function setPrices(uint256 newBuyPrice) onlyOwner {
        buyPrice = newBuyPrice;
    }

    function buy() payable {
        uint amount = msg.value / buyPrice;                // calculates the amount
        if (balanceOf[this] < amount) throw;               // checks if it has enough to sell
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add callback to notify buyer about purchase - introduces external call
        if (msg.sender.call.value(0)(bytes4(keccak256("onTokenPurchase(uint256)")), amount)) {
            // Callback succeeded - continue with purchase
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] += amount;                   // adds the amount to buyer's balance
        balanceOf[this] -= amount;                         // subtracts amount from seller's balance
        Transfer(this, msg.sender, amount);                // execute an event reflecting the change
    }
    
    function moveFunds() onlyOwner {
        if (!project_wallet.send(this.balance)) throw;
    }


    /* This unnamed function is called whenever someone tries to send ether to it */
    function () {
        throw;     // Prevents accidental sending of ether
    }
}