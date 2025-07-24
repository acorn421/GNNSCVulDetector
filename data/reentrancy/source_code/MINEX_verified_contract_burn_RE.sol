/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability through a batch burn processing system. The vulnerability requires multiple burn transactions to accumulate pending burns until they exceed a threshold, at which point an external validation call is made before updating totalSupply. This creates a reentrancy window where the external validator can call back into the contract while totalSupply hasn't been updated yet, but individual balances have been reduced across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. Added state tracking with `pendingBurns[msg.sender]` to accumulate burn amounts across transactions
 * 2. Introduced external contract calls to `burnHandler` and `burnValidator` 
 * 3. Created a threshold-based batch processing system that triggers after multiple burns
 * 4. Placed the external `validateBurn` call before the critical `totalSupply` update
 * 5. This creates a reentrancy window where accumulated state from multiple transactions can be exploited
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1-N**: Attacker makes multiple burn calls below the threshold, accumulating pending burns while reducing their balance
 * 2. **Transaction N+1**: Final burn call exceeds threshold, triggers batch processing
 * 3. **During validateBurn call**: Malicious validator re-enters burn function, seeing outdated totalSupply but updated balances
 * 4. **Exploitation**: The reentrant call can manipulate the burn process using the accumulated state differences
 * 
 * **Why Multiple Transactions Are Required:**
 * - The vulnerability only activates when `pendingBurns[msg.sender] >= burnThreshold`
 * - This requires accumulating burns across multiple transactions
 * - Each transaction modifies balance immediately but defers totalSupply updates
 * - The exploit relies on the state inconsistency that builds up over multiple transactions
 * - Single transaction cannot create the necessary state accumulation for the reentrancy window
 */
pragma solidity ^0.4.13;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

interface BurnHandler {
    function onBurnRequested(address from, uint256 value) external;
}

interface BurnValidator {
    function validateBurn(address from, uint256 value) external;
}

contract MINEX {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // Burn processing variables
    mapping(address => uint256) public pendingBurns;
    address public burnHandler;
    address public burnValidator;
    uint256 public burnThreshold = 0;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor() public {
        balanceOf[msg.sender] = 2999029096950000;              // Give the creator all initial tokens
        totalSupply = 2999029096950000;                        // Update total supply
        name = 'MINEX';                                   // Set the name for display purposes
        symbol = 'MINEX';                               // Set the symbol for display purposes
        decimals = 8;                            // Amount of decimals for display purposes
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);                               // Prevent transfer to 0x0 address. Use burn() instead
        require(balanceOf[_from] >= _value);                // Check if the sender has enough
        require(balanceOf[_to] + _value > balanceOf[_to]); // Check for overflows
        balanceOf[_from] -= _value;                         // Subtract from the sender
        balanceOf[_to] += _value;                           // Add the same to the recipient
        Transfer(_from, _to, _value);
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
    function approve(address _spender, uint256 _value)
        public returns (bool success) {
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
        public returns (bool success) {
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Add to pending burns for batch processing
        pendingBurns[msg.sender] += _value;
        
        // Immediately update balance to prevent double spending
        balanceOf[msg.sender] -= _value;
        
        // Notify external burn handler (potential callback)
        if (burnHandler != address(0)) {
            BurnHandler(burnHandler).onBurnRequested(msg.sender, _value);
        }
        
        // If accumulated pending burns exceed threshold, process batch
        if (pendingBurns[msg.sender] >= burnThreshold) {
            uint256 burnAmount = pendingBurns[msg.sender];
            
            // External call before state update - VULNERABLE TO REENTRANCY
            if (burnValidator != address(0)) {
                BurnValidator(burnValidator).validateBurn(msg.sender, burnAmount);
            }
            
            // State update after external call - REENTRANCY VULNERABILITY
            totalSupply -= burnAmount;
            pendingBurns[msg.sender] = 0;
            
            Burn(msg.sender, burnAmount);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }

    /**
     * Destroy tokens from other ccount
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
