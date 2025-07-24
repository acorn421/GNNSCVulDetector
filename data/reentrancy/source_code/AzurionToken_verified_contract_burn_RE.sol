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
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback mechanism after partial state updates. The vulnerability requires:
 * 
 * 1. **Initial State Setup**: The attacker needs to first set up a malicious burn notification contract and get it registered with the token contract (requires Transaction 1)
 * 
 * 2. **Exploitation Phase**: When the owner calls burn(), the function:
 *    - Checks balance requirement
 *    - Reduces balanceOf[msg.sender] 
 *    - Makes external call to burnNotificationContract.onBurn()
 *    - VULNERABILITY: The malicious contract can re-enter burn() before totalSupply is updated
 * 
 * 3. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: Setup malicious notification contract
 *    - Transaction 2: Owner calls burn() → triggers callback → malicious contract calls burn() again
 *    - The reentrant call sees inconsistent state where balanceOf is reduced but totalSupply isn't updated yet
 *    - This allows burning more tokens than should be possible, creating a totalSupply/balance mismatch
 * 
 * 4. **State Persistence**: The vulnerability relies on persistent state changes to balanceOf that carry over between the initial call and reentrant call, making it impossible to exploit in a single transaction.
 * 
 * The attack requires multiple transactions because:
 * - The malicious contract must be deployed and registered first
 * - The actual exploitation requires the owner to initiate a burn transaction
 * - The reentrant call leverages state changes from the initial transaction
 * - The vulnerability creates persistent state inconsistencies that accumulate across calls
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

    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

interface IBurnNotification {
    function onBurn(address from, uint256 amount) external;
}

contract AzurionToken is owned {
    mapping (address => uint256) public balanceOf;
    mapping (address => bool) public frozenAccount;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply;
    string public constant name = "Azurion";
    string public constant symbol = "AZU";
    uint8 public constant decimals = 18;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);
    event FrozenFunds(address target, bool frozen);

    address public burnNotificationContract;

    function AzurionToken(uint256 initialSupply, address centralMinter) public {
        if(centralMinter != 0 ) owner = centralMinter;
        balanceOf[msg.sender] = initialSupply;
        totalSupply = initialSupply;
    }

    /* Internal transfer, only can be called by this contract */
    function _transfer(address _from, address _to, uint _value) internal {
        require (_to != 0x0);                               
        require (balanceOf[_from] > _value);                
        require (balanceOf[_to] + _value > balanceOf[_to]); 
        require(!frozenAccount[_from]);                     
        require(!frozenAccount[_to]);                       
        balanceOf[_from] -= _value;                         
        balanceOf[_to] += _value;                           
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

    function mintToken(address target, uint256 mintedAmount) onlyOwner public {
        balanceOf[target] += mintedAmount;
        totalSupply += mintedAmount;
        Transfer(0, owner, mintedAmount);
        Transfer(owner, target, mintedAmount);
    }

    /// @param target Address to be frozen
    /// @param freeze either to freeze it or not
    function freezeAccount(address target, bool freeze) onlyOwner public {
        frozenAccount[target] = freeze;
        FrozenFunds(target, freeze);
    }

    /**
   * Set allowance for other address
   *
   * Allows `_spender` to spend no more than `_value` tokens in your behalf
   *
   * @param _spender The address authorized to spend
   * @param _value the max amount they can spend
   */
    function approve(address _spender, uint256 _value) public returns (bool success) {
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
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
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
    function burn(uint256 _value) onlyOwner public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // VULNERABILITY: External call before all state updates are complete
        if(burnNotificationContract != address(0)) {
            IBurnNotification(burnNotificationContract).onBurn(msg.sender, _value);
        }
        
        totalSupply -= _value;                      // Updates totalSupply AFTER external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(msg.sender, _value);
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
    function burnFrom(address _from, uint256 _value) onlyOwner public returns (bool success) {
        require(balanceOf[_from] >= _value);                // Check if the targeted balance is enough
        require(_value <= allowance[_from][msg.sender]);    // Check allowance
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        Burn(_from, _value);
        return true;
    }

    function () public {
        revert();
    }
}
