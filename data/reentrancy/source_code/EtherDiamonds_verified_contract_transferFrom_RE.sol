/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to notify the recipient before updating the allowance state. This creates a classic CEI (Check-Effects-Interactions) pattern violation where:
 * 
 * 1. **State Persistence**: The allowance mapping maintains state between transactions, creating exploitation opportunities
 * 2. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: Attacker initiates transferFrom with malicious recipient contract
 *    - Transaction 2+: Malicious recipient's onTokenReceived callback re-enters transferFrom before allowance is decremented
 *    - Each re-entry can drain additional tokens since allowance hasn't been updated yet
 * 
 * 3. **Exploitation Sequence**:
 *    - Attacker gets approval for X tokens
 *    - Calls transferFrom(victim, attackerContract, X)
 *    - attackerContract.onTokenReceived() is called before allowance update
 *    - Inside callback, attacker calls transferFrom again with same allowance
 *    - This can be repeated multiple times across separate transactions
 *    - Each subsequent transaction exploits the stale allowance state
 * 
 * 4. **Why Multi-Transaction**: The vulnerability requires the attacker to set up the malicious recipient contract in advance, get approval, then execute the attack across multiple function calls. The state inconsistency (allowance not yet decremented) persists across the external call boundary, enabling exploitation through callback mechanisms.
 * 
 * The vulnerability is realistic as it mimics real-world patterns where contracts notify recipients about token transfers, and the placement before state updates creates a genuine security flaw that requires multiple transactions to fully exploit.
 */
pragma solidity ^0.4.10;

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract EtherDiamonds{
    /* Public variables of the token */
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function EtherDiamonds() public {
        balanceOf[msg.sender] = 100000000000000000; // Give the creator all initial tokens
        totalSupply = 100000000000000000;                        // Update total supply
        name = "Ether Diamonds";                                   // Set the name for display purposes
        symbol = "ETHHD";                               // Set the symbol for display purposes
        decimals = 8;                            // Amount of decimals for display purposes
    }

    /* Internal transfer, only can be called by this contract */
    function _transfer(address _from, address _to, uint _value) internal {
        require (_to != 0x0);                               // Prevent transfer to 0x0 address. Use burn() instead
        require (balanceOf[_from] >= _value);                // Check if the sender has enough
        require (balanceOf[_to] + _value > balanceOf[_to]); // Check for overflows
        balanceOf[_from] -= _value;                         // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(_from, _to, _value);
    }

    /// @notice Send `_value` tokens to `_to` from your account
    /// @param _to The address of the recipient
    /// @param _value the amount to send
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    /// @notice Send `_value` tokens to `_to` in behalf of `_from`
    /// @param _from The address of the sender
    /// @param _to The address of the recipient
    /// @param _value the amount to send
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require (_value <= allowance[_from][msg.sender]);     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify recipient about incoming transfer (VULNERABILITY: External call before state update)
        if (_isContract(_to)) {
            // Call recipient's onTokenReceived function if it exists
            _to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value);
            // Continue regardless of call success to maintain functionality
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    // Helper function to determine if an address is a contract
    function _isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }

    /// @notice Allows `_spender` to spend no more than `_value` tokens in your behalf
    /// @param _spender The address authorized to spend
    /// @param _value the max amount they can spend
    function approve(address _spender, uint256 _value)
        public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /// @notice Allows `_spender` to spend no more than `_value` tokens in your behalf, and then ping the contract about it
    /// @param _spender The address authorized to spend
    /// @param _value the max amount they can spend
    /// @param _extraData some extra information to send to the approved contract
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }        

    /// @notice Remove `_value` tokens from the system irreversibly
    /// @param _value the amount of money to burn
    function burn(uint256 _value) public returns (bool success) {
        require (balanceOf[msg.sender] >= _value);            // Check if the sender has enough
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

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
