/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * **Stateful Multi-Transaction Reentrancy Vulnerability Injection:**
 * 
 * **1. Specific Changes Made:**
 * - Added `pendingBurns` mapping to track accumulated burn operations across transactions
 * - Introduced `burnNotificationService` address and `IBurnNotifier` interface call
 * - Added external call `onBurnComplete()` after state updates but before cleanup
 * - Moved `pendingBurns` reset to after the external call, creating a reentrancy window
 * 
 * **2. Multi-Transaction Exploitation Process:**
 * - **Transaction 1**: User calls `burn(100)` - pendingBurns[user] becomes 100, balance reduced, external call made
 * - **Transaction 2**: Through callback, `burn(50)` called again - pendingBurns[user] becomes 150, balance reduced again
 * - **Transaction 3**: Another recursive call `burn(30)` - pendingBurns[user] becomes 180, balance reduced further
 * - **Cleanup**: Eventually pendingBurns reset to 0, but multiple burns occurred with accumulated state
 * 
 * **3. Why Multi-Transaction Requirement:**
 * - The `pendingBurns` state persists across reentrancy calls, accumulating values
 * - Each recursive call constitutes a separate transaction context within the call stack
 * - The vulnerability requires the accumulated state (`pendingBurns`) to build up across multiple calls
 * - Cannot be exploited in a single atomic transaction - requires the callback mechanism to trigger subsequent calls
 * - The notification service must be set up in a prior transaction to enable the attack vector
 * 
 * **4. Realistic Integration:**
 * - Burn notification services are common in DeFi for tracking token destruction
 * - The `pendingBurns` tracking appears to be a legitimate feature for burn analytics
 * - The vulnerability follows the classic pattern of external calls after state changes
 * - The accumulated state makes this particularly dangerous as it can drain more tokens than the user's balance through multiple recursive calls
 * 
 * **5. Exploitation Impact:**
 * - Attacker can burn more tokens than their balance by exploiting the accumulated `pendingBurns` state
 * - Multiple recursive calls allow bypassing balance checks through state manipulation
 * - Total supply can be reduced beyond what should be possible from a single user's balance
 */
pragma solidity >=0.4.22 <0.6.0;

contract owned {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

// Added interface for IBurnNotifier
interface IBurnNotifier {
    function onBurnComplete(address burner, uint256 value, uint256 pendingBurns) external;
}

contract DalyVenturesShares {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    mapping (address => bool) public frozenAccount;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);
    
    // This generates a public event on the blockchain that will notify clients
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    // Added missing state variable burnNotificationService
    address public burnNotificationService;

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor() public {
        totalSupply = 100000000 * 10 ** uint256(18);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                    // Give the creator all initial tokens
        name = "Daly Ventures Shares";                                       // Set the name for display purposes
        symbol = "DVS";                                   // Set the symbol for display purposes
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        // Prevent transfer to 0x0 address. Use burn() instead
        require(_to != address(0x0));
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
        emit Transfer(_from, _to, _value);
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
    function transfer(address _to, uint256 _value) public returns (bool success) {
        _transfer(msg.sender, _to, _value);
        return true;
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
        emit Approval(msg.sender, _spender, _value);
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
    function approveAndCall(address _spender, uint256 _value, bytes memory _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, address(this), _extraData);
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
    // Add pending burn tracking
    mapping(address => uint256) public pendingBurns;
    
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        
        // Track pending burn operations
        pendingBurns[msg.sender] += _value;
        
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        
        // External call to burn notification service after state changes
        if (burnNotificationService != address(0)) {
            IBurnNotifier(burnNotificationService).onBurnComplete(msg.sender, _value, pendingBurns[msg.sender]);
        }
        
        // Reset pending burns only after external call
        pendingBurns[msg.sender] = 0;
        
        emit Burn(msg.sender, _value);
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
        emit Burn(_from, _value);
        return true;
    }
}
