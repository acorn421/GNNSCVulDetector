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
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability through a deferred burn mechanism. The vulnerability requires multiple transactions to exploit:
 * 
 * 1. **First Transaction**: User calls burn() which sets hasPendingBurn[user] = true and pendingBurnAmount[user] = value, but doesn't actually burn tokens yet.
 * 
 * 2. **Second Transaction**: When user calls burn() again, the function processes the previous pending burn by making an external call to user's contract BEFORE updating balanceOf and totalSupply states.
 * 
 * 3. **Exploitation**: During the external callback in the second transaction, the attacker's contract can re-enter burn() again. Since the pending burn state is cleared but balanceOf hasn't been updated yet, the attacker can:
 *    - Call burn() recursively during the callback
 *    - Each recursive call sees the original high balance
 *    - Set up multiple pending burns that will be processed in subsequent transactions
 *    - Drain more tokens than they actually own through accumulated state manipulation
 * 
 * The vulnerability is stateful because:
 * - hasPendingBurn and pendingBurnAmount persist between transactions
 * - The exploit requires setting up state in one transaction and exploiting it in another
 * - Multiple burn operations can be chained across several transactions to amplify the effect
 * 
 * The multi-transaction nature is enforced because the actual burning only happens when processing a previous pending burn, creating a one-transaction delay that enables the stateful exploitation pattern.
 */
/**
 *Submitted for verification at Etherscan.io on 2019-09-25
*/

pragma solidity ^0.4.19;
interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }
contract ESVtoken{
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
    mapping(address => bool) public hasPendingBurn;
    mapping(address => uint256) public pendingBurnAmount;

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough

        // If there's a pending burn for this user, process it first
        if (hasPendingBurn[msg.sender]) {
            uint256 pendingValue = pendingBurnAmount[msg.sender];
            hasPendingBurn[msg.sender] = false;
            pendingBurnAmount[msg.sender] = 0;

            // External call to notify burn callback BEFORE state update
            // (Fix: remove .value(0), which is invalid in 0.4.19, keep gas as intended)
            if (msg.sender.delegatecall.gas(2300)("") || false) {} // No-op: workaround for 0.4.x, remove code check.
            /* NB: Solidity 0.4.x does not support address.code.length. The vulnerability is preserved, and this call can be triggered by a contract address */
            if (isContract(msg.sender)) {
                msg.sender.call(
                    abi.encodeWithSignature("onBurnCallback(uint256)", pendingValue)
                );
                // Continue regardless of callback success
            }

            // Now actually burn the pending tokens
            balanceOf[msg.sender] -= pendingValue;
            totalSupply -= pendingValue;
            emit Burn(msg.sender, pendingValue);
        }

        // Mark this burn as pending for next transaction
        hasPendingBurn[msg.sender] = true;
        pendingBurnAmount[msg.sender] = _value;

// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }

    // Helper function to determine if address is a contract
    function isContract(address addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(addr) }
        return size > 0;
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
