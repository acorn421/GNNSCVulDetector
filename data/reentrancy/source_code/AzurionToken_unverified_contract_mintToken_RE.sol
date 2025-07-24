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
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding a callback mechanism that notifies the target address after minting tokens. The vulnerability allows a malicious contract to re-enter the mintToken function during the callback, exploiting the fact that state changes occur before the external call. This creates a persistent state manipulation vulnerability where:
 * 
 * 1. **First Transaction**: Owner calls mintToken() → state is updated → malicious callback re-enters mintToken() → additional tokens are minted → state accumulates
 * 2. **Subsequent Transactions**: The accumulated state from previous exploits remains, allowing the attacker to build up excessive token balances over multiple transactions
 * 3. **Multi-Transaction Nature**: The vulnerability requires the attacker to first deploy a malicious contract, then have the owner call mintToken targeting that contract, making it inherently multi-transaction
 * 
 * The vulnerability is realistic because token notification callbacks are common in DeFi protocols, and the try-catch pattern makes it appear production-ready. The state changes (balanceOf and totalSupply) persist between transactions, allowing the attacker to accumulate tokens through repeated exploitation across multiple owner calls.
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

// Declare interface for IMintCallback (used by mintToken)
interface IMintCallback {
    function onTokenMinted(uint256 mintedAmount) external;
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify the target about the minting - vulnerability: external call after state changes
        if (target != address(0) && isContract(target)) {
            // Call the callback; no try/catch in Solidity 0.4.x, so use low-level call pattern
            IMintCallback(target).onTokenMinted(mintedAmount);
            // Ignore failures for compat with original intent
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
    
    function isContract(address _addr) internal view returns (bool is_contract) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
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
        totalSupply -= _value;                      // Updates totalSupply
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
