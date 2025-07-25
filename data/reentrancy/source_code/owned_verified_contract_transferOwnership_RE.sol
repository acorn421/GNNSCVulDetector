/*
 * ===== SmartInject Injection Details =====
 * Function      : transferOwnership
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
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This injection creates a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Adding Pending State Mechanism**: Introduces `pendingTransfers` mapping and `pendingOwner` variable that persist between transactions, creating intermediate states during ownership transitions.
 * 
 * 2. **External Call Before State Finalization**: The external call to `notifyOwnershipPending()` occurs before the ownership is fully transferred, violating the Checks-Effects-Interactions (CEI) pattern.
 * 
 * 3. **Multi-Transaction Exploitation Path**:
 *    - **Transaction 1**: Attacker calls transferOwnership, triggering the external call during the pending state
 *    - **During Reentry**: The reentrancy callback can exploit the intermediate state where `pendingOwner` is set but `owner` hasn't changed yet
 *    - **Transaction 2**: Attacker can manipulate the pending state or exploit race conditions in subsequent calls
 * 
 * 4. **State Persistence**: The pending state variables maintain their values across transactions, allowing the vulnerability to be exploited over multiple calls rather than in a single atomic transaction.
 * 
 * 5. **Realistic Attack Vector**: An attacker can deploy a malicious contract that implements the callback function to reenter during the notification call, potentially manipulating the ownership transfer process or exploiting the intermediate state where access controls might be inconsistent.
 * 
 * The vulnerability is only exploitable across multiple transactions because the attacker needs to:
 * - Set up the initial pending state in one transaction
 * - Exploit the intermediate state during reentrancy
 * - Potentially complete the attack in subsequent transactions by manipulating the pending state flags
 */
pragma solidity ^0.4.16;

contract owned {
    address public owner;

    function owned() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => bool) public pendingTransfers;
    address public pendingOwner;
    
    function transferOwnership(address newOwner) onlyOwner public {
        // Mark as pending transfer to prevent double execution
        require(!pendingTransfers[newOwner], "Transfer already pending");
        
        // Set pending state first
        pendingTransfers[newOwner] = true;
        pendingOwner = newOwner;
        
        // External call to notify new owner before state finalization
        // This allows reentrancy during the ownership transition period
        if (newOwner.call(bytes4(keccak256("notifyOwnershipPending(address,address)")), owner, newOwner)) {
            // State change occurs after external call - CEI violation
            owner = newOwner;
            pendingTransfers[newOwner] = false;
            pendingOwner = address(0);
        } else {
            // If notification fails, keep pending state for retry
            // This creates a window where pendingOwner != owner
            revert("Ownership notification failed");
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract Har {
    string public constant _myTokeName = 'Cards';//change here
    string public constant _mySymbol = 'CARDS';//change here
    uint public constant _myinitialSupply = 21000000;//leave it
    uint8 public constant _myDecimal = 0;//leave it
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function Cards(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        decimals = _myDecimal;
        totalSupply = _myinitialSupply * (10 ** uint256(_myDecimal));  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = _myTokeName;                                   // Set the name for display purposes
        symbol = _mySymbol;                               // Set the symbol for display purposes
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