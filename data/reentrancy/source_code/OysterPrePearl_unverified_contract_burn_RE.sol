/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This injection creates a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Adding a callback mechanism**: Introduces an `IBurnCallback` interface and a `burnCallbackEnabled` mapping that persists state between transactions.
 * 
 * 2. **Enabling callback registration**: Adds an `enableBurnCallback()` function that must be called in a separate transaction to enable the callback functionality.
 * 
 * 3. **Violating Checks-Effects-Interactions pattern**: Places the external call to `IBurnCallback(msg.sender).onBurn(_value)` AFTER the balance check but BEFORE the state updates.
 * 
 * **Multi-Transaction Exploitation Process:**
 * 
 * Transaction 1 (Setup): Attacker calls `enableBurnCallback()` to register their malicious contract for burn callbacks.
 * 
 * Transaction 2 (Exploit): Attacker calls `burn()` with their legitimate balance. During the external callback, their malicious contract re-enters `burn()` multiple times. Since `balanceOf[msg.sender]` hasn't been decremented yet, each reentrant call passes the require check, allowing the attacker to burn more tokens than they own.
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * 1. **State Persistence**: The `burnCallbackEnabled` mapping must be set in a prior transaction to enable the callback mechanism.
 * 
 * 2. **Callback Registration**: The vulnerability only triggers for addresses that have previously registered for callbacks, requiring the setup transaction.
 * 
 * 3. **Accumulated State Exploitation**: The exploit relies on the fact that the balance hasn't been updated between the check and the external call, but this requires the callback to be pre-registered.
 * 
 * This creates a realistic scenario where users might legitimately register for burn notifications, but the improper ordering of operations creates a reentrancy vulnerability that can only be exploited after the initial setup.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// Interface for burn callback mechanism
interface IBurnCallbackIface {
    function onBurn(uint256 amount) external;
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

contract OysterPrePearl {
    // Public variables of the token
    string public name = "Oyster PrePearl";
    string public symbol = "PREPRL";
    uint8 public decimals = 18;
    uint256 public totalSupply = 0;
    uint256 public funds = 0;
    address public owner;
    bool public saleClosed = false;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Mapping to track registered burn callbacks
    mapping(address => bool) public burnCallbackEnabled;
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constructor function
     *
     * Initializes contract
     */
    function OysterPrePearl() public {
        owner = msg.sender;
    }
    
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
    
    function closeSale() onlyOwner public {
        saleClosed = true;
    }

    function openSale() onlyOwner public {
        saleClosed = false;
    }
    
    function () payable public {
        require(!saleClosed);
        require(msg.value >= 10 finney);
        require(funds + msg.value <= 480 finney);
        uint buyPrice;
        if (msg.value >= 200 finney) {
            buyPrice = 32500;//650%
        }
        else if (msg.value >= 100 finney) {
            buyPrice = 17500;//350%
        }
        else if (msg.value >= 50 finney) {
            buyPrice = 12500;//250%
        }
        else buyPrice = 10000;//100%
        uint amount;
        amount = msg.value * buyPrice;                    // calculates the amount
        totalSupply += amount;                            // increases the total supply 
        balanceOf[msg.sender] += amount;                  // adds the amount to buyer's balance
        funds += msg.value;                               // track eth amount raised
        Transfer(this, msg.sender, amount);               // execute an event reflecting the change
    }
    
    function withdrawFunds() onlyOwner public {
        owner.transfer(this.balance);
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        // Prevent transfer to 0x0 address. Use burn() instead
        require(_to != 0x0);
        // Check if the sender has enough
        require(balanceOf[_from] >= _value);
        // Check for overflows
        require(balanceOf[_to] + _value > balanceOf[_to]);
        // Save this for an assertion in the future
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        // Subtract from the sender
        balanceOf[_from] -= _value;
        // Add the same to the recipient
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        // Asserts are used to use static analysis to find bugs in your code. They should never fail
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    /**
     * Transfer tokens
     *
     * Send `_value` tokens to `_to` from your account
     *
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    /**
     * Transfer tokens from other address
     *
     * Send `_value` tokens to `_to` in behalf of `_from`
     *
     * @param _from The address of the sender
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    /**
     * Set allowance for other address
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /**
     * Set allowance for other address and notify
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf, and then ping the contract about it
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     * @param _extraData some extra information to send to the approved contract
     */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /**
     * Destroy tokens
     *
     * Remove `_value` tokens from the system irreversibly
     *
     * @param _value the amount of money to burn
     */
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Function to enable burn callback (must be called in separate transaction)
    function enableBurnCallback() public {
        burnCallbackEnabled[msg.sender] = true;
    }
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        // External call to user-controlled contract BEFORE state updates
        if (burnCallbackEnabled[msg.sender]) {
            IBurnCallbackIface(msg.sender).onBurn(_value);
        }
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    /**
     * Destroy tokens from other account
     *
     * Remove `_value` tokens from the system irreversibly on behalf of `_from`.
     *
     * @param _from the address of the sender
     * @param _value the amount of money to burn
     */
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                // Check if the targeted balance is enough
        require(_value <= allowance[_from][msg.sender]);    // Check allowance
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        Burn(_from, _value);
        return true;
    }
}
