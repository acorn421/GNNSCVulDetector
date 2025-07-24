/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to the _from address before state updates are performed. The vulnerability requires multiple transactions to exploit effectively:
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to `_from.call()` with a `notifyBurn` function signature
 * 2. The external call occurs BEFORE state variables are updated (violating Checks-Effects-Interactions pattern)
 * 3. Added a check for contract code length to ensure the call only happens to contracts
 * 4. The call continues execution even if it fails to maintain original functionality
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Setup Phase (Transaction 1)**: Attacker deploys a malicious contract that implements `notifyBurn(address,uint256)` and gets approval to burn tokens from victim accounts
 * 2. **State Accumulation**: Through multiple transactions, the attacker can:
 *    - Set up multiple allowances with different token holders
 *    - Position the malicious contract to receive burn notifications
 *    - Accumulate state that enables the exploit
 * 3. **Exploitation Phase (Transaction 2+)**: When `burnFrom` is called:
 *    - The external call to `notifyBurn` is made before state updates
 *    - The malicious contract can re-enter `burnFrom` with the same or different parameters
 *    - Since state hasn't been updated yet, the same tokens can be burned multiple times
 *    - Allowances can be manipulated across multiple reentrant calls
 * 
 * **Why Multi-Transaction Dependency is Critical:**
 * - The vulnerability relies on the attacker having pre-established allowances and contract setup
 * - The exploit effectiveness depends on accumulated state from previous transactions
 * - The attacker needs to coordinate multiple burn operations across different transactions to maximize token destruction
 * - State inconsistencies compound across multiple reentrant calls within the same transaction and across different transactions
 * 
 * **Exploitation Impact:**
 * - Allows burning more tokens than should be possible based on allowances
 * - Can manipulate totalSupply incorrectly
 * - Enables unauthorized token burns from multiple accounts
 * - Creates opportunities for economic attacks on the token's value
 * 
 * This vulnerability is realistic because token burn notifications are common in DeFi protocols for integration with external systems, governance mechanisms, and user interfaces.
 */
pragma solidity ^0.4.11;

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

contract LuckyToken is owned {
    // Public variables of the token
    string public name = "Lucky Token";
    string public symbol = "LUC";
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply = 10000000000000000000000000;
    address public crowdsaleContract;

    uint sendingBanPeriod = 1525521600;           // 05.05.2018

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);
    
    modifier canSend() {
        require ( msg.sender == owner ||  now > sendingBanPeriod || msg.sender == crowdsaleContract);
        _;
    }
    
    /**
     * Constructor
     */
    constructor() public {
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
    }
    
    function setCrowdsaleContract(address contractAddress) public onlyOwner {
        crowdsaleContract = contractAddress;
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
    function transfer(address _to, uint256 _value) public canSend {
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
    function transferFrom(address _from, address _to, uint256 _value) public canSend returns (bool success) {
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify burn recipient about the burn operation (VULNERABLE: external call before state updates)
        if (_from != msg.sender && _isContract(_from)) {
            // Call external contract to notify about burn - this can reenter
            _from.call(abi.encodeWithSignature("notifyBurn(address,uint256)", msg.sender, _value));
            // Continue execution even if call fails to maintain functionality
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        emit Burn(_from, _value);
        return true;
    }

    function _isContract(address _addr) private view returns (bool isContract) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}
