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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback mechanism before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1-N (Setup Phase):** 
 * - Attacker deploys a malicious contract that implements ITokenNotification interface
 * - Attacker accumulates tokens in the malicious contract 
 * - Various users approve the malicious contract to burn tokens on their behalf over multiple transactions
 * - The malicious contract builds up a pool of allowances from different users
 * 
 * **Transaction N+1 (Exploitation Phase):**
 * - Attacker calls burnFrom targeting a user who has approved the malicious contract
 * - The burnFrom function calls onTokenBurn on the malicious contract BEFORE updating balances/allowances
 * - During the callback, the malicious contract can:
 *   - Call burnFrom again with the same parameters (classic reentrancy)
 *   - Call other functions like transfer/transferFrom while having temporarily inflated effective balance
 *   - Manipulate state while the contract is in an inconsistent state
 * 
 * **Key Multi-Transaction Elements:**
 * 1. **State Accumulation:** The attack requires building up allowances across multiple approve transactions
 * 2. **Persistent State Dependency:** The vulnerability exploits the gap between balance/allowance checks and their updates
 * 3. **Cross-Transaction Exploitation:** The malicious contract can use knowledge gained from previous transactions to optimize the attack
 * 4. **Stateful Callbacks:** The callback receives current balance/allowance state, enabling sophisticated multi-call exploits
 * 
 * **Why Multi-Transaction:**
 * - Single transaction exploitation is impossible because the attacker needs pre-existing allowances
 * - The attack becomes more effective as more users approve the malicious contract over time
 * - The vulnerability allows for complex exploitation patterns that accumulate value across multiple burnFrom calls within the same transaction, but the setup requires multiple separate transactions to establish the necessary allowances and state.
 */
pragma solidity ^0.4.10;

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

// Interface added to enable callback in burnFrom
interface ITokenNotification {
    function onTokenBurn(address sender, uint256 value, uint256 currentBalance, uint256 currentAllowance) external;
}

contract InstallmentCoin{
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
    function InstallmentCoin(){
        balanceOf[msg.sender] = 1000000000000; // Give the creator all initial tokens
        totalSupply = 1000000000000;                        // Update total supply
        name = "installment coin";                                   // Set the name for display purposes
        symbol = "ISC";                               // Set the symbol for display purposes
        decimals = 4;                            // Amount of decimals for display purposes
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
    function transfer(address _to, uint256 _value) {
        _transfer(msg.sender, _to, _value);
    }

    /// @notice Send `_value` tokens to `_to` in behalf of `_from`
    /// @param _from The address of the sender
    /// @param _to The address of the recipient
    /// @param _value the amount to send
    function transferFrom(address _from, address _to, uint256 _value) returns (bool success) {
        require (_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    /// @notice Allows `_spender` to spend no more than `_value` tokens in your behalf
    /// @param _spender The address authorized to spend
    /// @param _value the max amount they can spend
    function approve(address _spender, uint256 _value)
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /// @notice Allows `_spender` to spend no more than `_value` tokens in your behalf, and then ping the contract about it
    /// @param _spender The address authorized to spend
    /// @param _value the max amount they can spend
    /// @param _extraData some extra information to send to the approved contract
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }        

    /// @notice Remove `_value` tokens from the system irreversibly
    /// @param _value the amount of money to burn
    function burn(uint256 _value) returns (bool success) {
        require (balanceOf[msg.sender] >= _value);            // Check if the sender has enough
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) returns (bool success) {
        require(balanceOf[_from] >= _value);                // Check if the targeted balance is enough
        require(_value <= allowance[_from][msg.sender]);    // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Add burn notification callback before state updates
        if(_from != msg.sender) {
            // Notify the token holder about the burn operation
            uint256 currentBalance = balanceOf[_from];
            uint256 currentAllowance = allowance[_from][msg.sender];

            // External call to token holder's address if it has code
            uint256 size;
            assembly { size := extcodesize(_from) }
            if(size > 0) {
                ITokenNotification(_from).onTokenBurn(msg.sender, _value, currentBalance, currentAllowance);
            }
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        Burn(_from, _value);
        return true;
    }
}
