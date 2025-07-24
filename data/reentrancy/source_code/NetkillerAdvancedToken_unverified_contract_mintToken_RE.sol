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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Added a callback mechanism that introduces a stateful, multi-transaction reentrancy vulnerability. The external call to `target.call()` occurs after all state modifications are complete, but the accumulated state changes across multiple transactions enable exploitation. 
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `target.call()` at the end of the function
 * 2. The call invokes `onTokenMint(uint256)` on the recipient if it's a contract
 * 3. State updates occur before the external call, creating a race condition
 * 4. No reentrancy guard protection exists
 * 
 * **Multi-Transaction Exploitation Path:**
 * 1. **Transaction 1**: Owner calls `mintToken(maliciousContract, 1000)` 
 *    - `balanceOf[maliciousContract]` increases by 1000
 *    - `totalSupply` increases by 1000
 *    - External call to `maliciousContract.onTokenMint(1000)` executes
 *    - Malicious contract can read the updated state and prepare for re-entry
 * 
 * 2. **Transaction 2**: During the callback, malicious contract calls owner's mintToken again
 *    - Since state was already updated in Transaction 1, the malicious contract has legitimate balance
 *    - It can use its balance to perform operations that trigger another mint
 *    - The accumulated state from previous transactions enables new exploitation vectors
 * 
 * 3. **Transaction 3+**: Pattern repeats with exponentially growing balances
 *    - Each transaction builds on the state changes from previous ones
 *    - Total supply grows beyond intended limits
 *    - The vulnerability requires this sequence of transactions to be effective
 * 
 * **Why Multi-Transaction is Required:**
 * - Single transaction reentrancy would be limited by gas constraints
 * - The accumulated state changes across transactions enable escalating exploitation
 * - Each transaction legitimately updates state, making subsequent attacks more powerful
 * - The pattern mimics real-world attacks where state accumulation is key to the exploit's success
 * 
 * This creates a realistic vulnerability where the external call provides an attack vector, but the real damage comes from the stateful nature of token balances persisting across multiple transactions, allowing for compound exploitation."
 */
pragma solidity ^0.4.20;

/******************************************/
/*       Netkiller ADVANCED TOKEN         */
/******************************************/
/* Author netkiller <netkiller@msn.com>   */
/* Home http://www.netkiller.cn           */
/* Version 2018-03-05                     */
/******************************************/

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract NetkillerAdvancedToken {
    address public owner;
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;
    
    uint256 public sellPrice;
    uint256 public buyPrice;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    
    mapping (address => bool) public frozenAccount;

    /* This generates a public event on the blockchain that will notify clients */
    event FrozenFunds(address target, bool frozen);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        owner = msg.sender;
        totalSupply = initialSupply * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
 
    /* Internal transfer, only can be called by this contract */
    function _transfer(address _from, address _to, uint _value) internal {
        require (_to != 0x0);                               // Prevent transfer to 0x0 address. Use burn() instead
        require (balanceOf[_from] >= _value);               // Check if the sender has enough
        require (balanceOf[_to] + _value > balanceOf[_to]); // Check for overflows
        require(!frozenAccount[_from]);                     // Check if sender is frozen
        require(!frozenAccount[_to]);                       // Check if recipient is frozen
        balanceOf[_from] -= _value;                         // Subtract from the sender
        balanceOf[_to] += _value;                           // Add the same to the recipient
        emit Transfer(_from, _to, _value);
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
    function burn(uint256 _value) onlyOwner public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        emit Burn(msg.sender, _value);
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
    function burnFrom(address _from, uint256 _value) onlyOwner public returns (bool success) {
        require(balanceOf[_from] >= _value);                // Check if the targeted balance is enough
        require(_value <= allowance[_from][msg.sender]);    // Check allowance
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        emit Burn(_from, _value);
        return true;
    }

    /// @notice Create `mintedAmount` tokens and send it to `target`
    /// @param target Address to receive the tokens
    /// @param mintedAmount the amount of tokens it will receive
    function mintToken(address target, uint256 mintedAmount) onlyOwner public {
        balanceOf[target] += mintedAmount;
        totalSupply += mintedAmount;
        emit Transfer(0, this, mintedAmount);
        emit Transfer(this, target, mintedAmount);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient of token minting (introduces reentrancy vulnerability)
        if (target.delegatecall.gas(2300)(bytes4(0))) {} // dummy to use delegatecall and silence warnings
        if (extcodesize(target) > 0) {
            target.call(abi.encodeWithSignature("onTokenMint(uint256)", mintedAmount));
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function extcodesize(address _addr) internal view returns (uint size) {
        assembly {
            size := extcodesize(_addr)
        }
    }

    /// @notice `freeze? Prevent | Allow` `target` from sending & receiving tokens
    /// @param target Address to be frozen
    /// @param freeze either to freeze it or not
    function freezeAccount(address target, bool freeze) onlyOwner public {
        frozenAccount[target] = freeze;
        emit FrozenFunds(target, freeze);
    }

    /// @notice Allow users to buy tokens for `newBuyPrice` eth and sell tokens for `newSellPrice` eth
    /// @param newSellPrice Price the users can sell to the contract
    /// @param newBuyPrice Price users can buy from the contract
    function setPrices(uint256 newSellPrice, uint256 newBuyPrice) onlyOwner public {
        sellPrice = newSellPrice;
        buyPrice = newBuyPrice;
    }

    /// @notice Buy tokens from contract by sending ether
    function buy() payable public {
        uint amount = msg.value / buyPrice;               // calculates the amount
        _transfer(this, msg.sender, amount);              // makes the transfers
    }

    /// @notice Sell `amount` tokens to contract
    /// @param amount amount of tokens to be sold
    function sell(uint256 amount) public {
        require(this.balance >= amount * sellPrice);      // checks if the contract has enough ether to buy
        _transfer(msg.sender, this, amount);              // makes the transfers
        msg.sender.transfer(amount * sellPrice);          // sends ether to the seller. It's important to do this last to avoid recursion attacks
    }
    
  function transfer(address _to, uint256 _value, bytes _data) public returns (bool) {
    require(_to != address(this));
    transfer(_to, _value);
    require(_to.call(_data));
    return true;
  }

  function transferFrom(address _from, address _to, uint256 _value, bytes _data) public returns (bool) {
    require(_to != address(this));
    transferFrom(_from, _to, _value);
    require(_to.call(_data));
    return true;
  }

  function approve(address _spender, uint256 _value, bytes _data) public returns (bool) {
    require(_spender != address(this));
    approve(_spender, _value);
    require(_spender.call(_data));
    return true;
  }
    
}
