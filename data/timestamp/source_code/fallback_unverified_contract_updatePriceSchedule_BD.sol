/*
 * ===== SmartInject Injection Details =====
 * Function      : updatePriceSchedule
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
 * This vulnerability introduces timestamp dependence where the contract relies on 'now' (block.timestamp) to determine when a price schedule should be activated. The vulnerability is stateful and multi-transaction because: 1) Owner first calls updatePriceSchedule() to set a future activation time, 2) Later, activatePriceSchedule() is called to apply the changes when the time has elapsed. Miners can manipulate the block timestamp to activate the price schedule earlier than intended, potentially allowing them to exploit favorable pricing conditions. The state persists between transactions through priceScheduleExpiry, pendingPriceMultiplier, and priceScheduleActive variables.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

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

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // Price schedule management
    uint256 public priceScheduleExpiry = 0;
    uint256 public pendingPriceMultiplier = 0;
    bool public priceScheduleActive = false;
    // === END FALLBACK INJECTION ===

    /**
     * Constructor function
     *
     * Initializes contract
     */
    function OysterPrePearl() public {
        owner = msg.sender;
    }
    
    // === FALLBACK INJECTION: Timestamp Dependence ===
    /**
     * Update price schedule for future token purchases
     * 
     * @param _multiplier The new price multiplier (in basis points)
     * @param _delayHours Hours from now when the new price takes effect
     */
    function updatePriceSchedule(uint256 _multiplier, uint256 _delayHours) onlyOwner public {
        require(_multiplier > 0);
        require(_delayHours > 0);
        
        // Set the expiry time based on current block timestamp
        priceScheduleExpiry = now + (_delayHours * 1 hours);
        pendingPriceMultiplier = _multiplier;
        priceScheduleActive = true;
    }
    
    /**
     * Activate the pending price schedule if time has elapsed
     */
    function activatePriceSchedule() public {
        require(priceScheduleActive);
        require(now >= priceScheduleExpiry);
        
        // The vulnerability: miners can manipulate 'now' to activate early
        // This requires multiple transactions: first updatePriceSchedule, then activatePriceSchedule
        priceScheduleActive = false;
        // Apply the new pricing logic (simplified for demonstration)
        funds = funds * pendingPriceMultiplier / 10000;
        pendingPriceMultiplier = 0;
        priceScheduleExpiry = 0;
    }
    // === END FALLBACK INJECTION ===

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
    
    function () payable {
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
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

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
