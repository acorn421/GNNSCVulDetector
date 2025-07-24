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
 * **STATEFUL MULTI-TRANSACTION REENTRANCY VULNERABILITY INJECTION**
 * 
 * **1. SPECIFIC CHANGES MADE:**
 * - Added external call to target address after state updates using `target.call(abi.encodeWithSignature("onTokenMinted(uint256)", mintedAmount))`
 * - Added check for contract code existence with `target.code.length > 0`
 * - Added error handling that doesn't revert on failure, maintaining the vulnerable state
 * - The external call occurs AFTER critical state changes (balanceOf and totalSupply updates)
 * 
 * **2. MULTI-TRANSACTION EXPLOITATION SCENARIO:**
 * The vulnerability requires a sequence of transactions to exploit:
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract with `onTokenMinted(uint256)` function
 * - Owner calls `mintToken(attackerContract, 1000)` 
 * - State updates: `balanceOf[attackerContract] += 1000`, `totalSupply += 1000`
 * - External call triggers `attackerContract.onTokenMinted(1000)`
 * 
 * **Transaction 2 (Reentrancy Exploitation):**
 * - Inside `onTokenMinted()`, the attacker's contract calls back to `mintToken()` again
 * - Since state was already updated in Transaction 1, the attacker now has 1000 tokens
 * - The reentrant call adds another 1000 tokens: `balanceOf[attackerContract] += 1000`
 * - This creates a situation where the attacker receives more tokens than intended
 * 
 * **Transaction 3 (State Accumulation):**
 * - The attacker can continue this pattern across multiple transactions
 * - Each transaction builds upon the persistent state changes from previous transactions
 * - The accumulated balance grows beyond what should be possible
 * 
 * **3. WHY MULTI-TRANSACTION REQUIREMENT:**
 * - **State Persistence**: The `balanceOf` and `totalSupply` state changes persist between transactions
 * - **Accumulated Exploitation**: Each reentrant call builds upon the previous state changes
 * - **Cross-Transaction Dependencies**: The vulnerability depends on the accumulated state from previous mint operations
 * - **Realistic Attack Pattern**: Real-world reentrancy attacks often involve multiple transactions where each transaction sets up state for the next exploitation
 * 
 * **4. VULNERABILITY MECHANICS:**
 * - The external call happens after state modifications, creating a classic reentrancy pattern
 * - The persistent state changes between transactions enable incremental exploitation
 * - The attacker can orchestrate multiple transactions to maximize the exploitation
 * - Each transaction in the sequence leverages the modified state from previous transactions
 * 
 * This creates a genuine stateful, multi-transaction reentrancy vulnerability that requires careful orchestration across multiple transactions to fully exploit.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

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

// Helper for extcodesize
library ExtCode {
    function extcodesize(address _addr) internal view returns (uint256 size) { assembly { size := extcodesize(_addr) } }
}

contract PaulyCoin is owned {
    using ExtCode for address;
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
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
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
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
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    /**
     * Transfer tokens from other address
     *
     * Send `_value` tokens to `_to` on behalf of `_from`
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
      emit Transfer(0, owner, mintedAmount);
      emit Transfer(owner, target, mintedAmount);
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      
      // Notify the recipient about the minting - VULNERABLE TO REENTRANCY
      if (target.extcodesize() > 0) {
          bool success = target.call(abi.encodeWithSignature("onTokenMinted(uint256)", mintedAmount));
          if (!success) {
              // If notification fails, don't revert - just continue
              // This creates a window where state is updated but external call can re-enter
          }
      }
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    /**
     * Set allowance for other address
     *
     * Allows `_spender` to spend no more than `_value` tokens on your behalf
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
     * Allows `_spender` to spend no more than `_value` tokens on your behalf, and then ping the contract about it
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
