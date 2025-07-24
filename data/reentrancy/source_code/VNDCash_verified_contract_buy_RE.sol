/*
 * ===== SmartInject Injection Details =====
 * Function      : buy
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the buyer's contract after state updates but before the Transfer event. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `msg.sender` using low-level `call()` function
 * 2. The call happens after balance updates but before the Transfer event
 * 3. Added a contract code length check to only call contracts (realistic defensive programming)
 * 4. Used a callback pattern (`onTokensPurchased`) that appears legitimate
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Attacker deploys a malicious contract with `onTokensPurchased()` callback
 * 2. **Transaction 2**: Attacker calls `buy()` with ETH, triggering the external call during execution
 * 3. **During Callback**: The malicious contract can call other functions like `transfer()` or `approve()` while the buy transaction is still executing
 * 4. **Transaction 3+**: Attacker exploits the inconsistent state created by the reentrancy across multiple subsequent transactions
 * 
 * **Why Multiple Transactions Are Required:**
 * - The attacker must first deploy a malicious contract (Transaction 1)
 * - The reentrancy window only exists during the `buy()` execution (Transaction 2)
 * - The attacker needs separate transactions to set up the exploit and then leverage the created inconsistent state
 * - The vulnerability exploits the persistent state changes (`balanceOf` mappings) that remain between transactions
 * - Full exploitation requires coordinated calls across multiple transactions to drain funds or manipulate token distribution
 * 
 * **Stateful Nature:**
 * - The `balanceOf` mappings persist between transactions and are modified during the vulnerable window
 * - The contract's token balance and user balances create persistent state that can be manipulated
 * - The reentrancy creates a window where state is inconsistent across multiple transactions
 * 
 * This creates a realistic, production-like vulnerability where the external call appears to be legitimate functionality (notifying the buyer), but opens a critical reentrancy attack vector that requires sophisticated multi-transaction exploitation.
 */
pragma solidity ^0.4.2;
contract owned {
    address public owner;

    function owned() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        if (msg.sender != owner) throw;
        _;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract token {
    /* Public variables of the token */
    string public standard = 'Token 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);
    event FundTransfer(address backer, uint amount, bool isContribution);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function token(
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol
        ) public {
        balanceOf[msg.sender] = initialSupply;              // Give the creator all initial tokens
        totalSupply = initialSupply;                        // Update total supply
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        decimals = decimalUnits;                            // Amount of decimals for display purposes
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* Approve and then communicate the approved contract in a single tx */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {    
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;   // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    /* This unnamed function is called whenever someone tries to send ether to it */
    function () public {
        throw;     // Prevents accidental sending of ether
    }
}

contract VNDCash is owned, token {

    uint256 public sellPrice;
    uint256 public buyPrice;
    uint256 public buyRate; // price one token per ether

    mapping (address => bool) public frozenAccount;

    /* This generates a public event on the blockchain that will notify clients */
    event FrozenFunds(address target, bool frozen);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function VNDCash(
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol
    ) token (initialSupply, tokenName, decimalUnits, tokenSymbol) public {}

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        if (frozenAccount[msg.sender]) throw;                // Check if frozen
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }


    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (frozenAccount[_from]) throw;                        // Check if frozen            
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;   // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function mintToken(address target, uint256 mintedAmount) onlyOwner public {
        balanceOf[target] += mintedAmount;
        totalSupply += mintedAmount;
        Transfer(0, this, mintedAmount);
        Transfer(this, target, mintedAmount);
    }

    function freezeAccount(address target, bool freeze) onlyOwner public {
        frozenAccount[target] = freeze;
        FrozenFunds(target, freeze);
    }

    function setBuyRate(uint256 newBuyRate) onlyOwner public {
        buyRate = newBuyRate;
    }

    function buy() public payable {
        uint256 amount = msg.value * buyRate;              // calculates the amount
        if (balanceOf[this] < amount) throw;               // checks if it has enough to sell
        balanceOf[msg.sender] += amount;                   // adds the amount to buyer's balance
        balanceOf[this] -= amount;                         // subtracts amount from seller's balance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify buyer's contract about the purchase (external call before complete state finalization)
        if (isContract(msg.sender)) {
            bool success = msg.sender.call(bytes4(keccak256("onTokensPurchased(uint256)")), amount);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(this, msg.sender, amount);                // execute an event reflecting the change
    }
    
    function withDraw(uint256 amountEther) onlyOwner public {
        FundTransfer(owner, amountEther, false);
    }
    
    // Helper function for contract detection (since code property not available in 0.4.2)
    function isContract(address _addr) internal view returns(bool) {
        uint length;
        assembly {
            length := extcodesize(_addr)
        }
        return length > 0;
    }
}
