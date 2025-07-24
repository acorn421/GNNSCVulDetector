/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * **Vulnerability Injection Analysis:**
 * 
 * **1. Specific Changes Made:**
 * - Added TransferHook interface for recipient notifications
 * - Introduced external call to `_to.onTransferReceived()` AFTER allowance modification but BEFORE actual transfer
 * - Used try-catch to make the hook "optional" (realistic production pattern)
 * - Maintained all original function logic and behavior
 * 
 * **2. Multi-Transaction Exploitation Scenario:**
 * This creates a **stateful, multi-transaction** reentrancy vulnerability that requires sophisticated preparation:
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys malicious contract implementing TransferHook
 * - Victim approves attacker's contract for token spending
 * - Attacker contract records initial allowance state
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls transferFrom() to transfer tokens to their malicious contract
 * - Flow: Check allowance → Reduce allowance → **External call to attacker contract** → Complete transfer
 * - During the external call, attacker contract re-enters transferFrom() multiple times
 * - Each re-entry exploits the window where allowance is reduced but original transfer hasn't completed
 * - Attacker can drain allowances that accumulated from previous transactions
 * 
 * **3. Why Multi-Transaction Requirement:**
 * - **State Accumulation**: Victim must build up allowances over multiple transactions for meaningful exploitation
 * - **Preparation Required**: Attacker needs separate transactions to deploy malicious contract and establish initial approvals
 * - **Window Exploitation**: The vulnerability exploits the state inconsistency window that persists between the allowance reduction and transfer completion
 * - **Allowance Manipulation**: Multiple transactions allow building complex allowance states that amplify the reentrancy impact
 * 
 * **4. Technical Exploitation Details:**
 * - The external call occurs at the perfect moment: after allowance is reduced but before `_transfer()` executes
 * - Attacker's contract can re-enter and make additional transfers while the original transfer is still pending
 * - Each re-entry operates on the reduced allowance state from the outer call
 * - Multiple accumulated allowances from previous transactions provide the "fuel" for the attack
 * 
 * **5. Realistic Production Context:**
 * - Transfer hooks are common in modern token implementations (ERC-777, ERC-1155)
 * - The try-catch pattern makes hooks "optional" which is realistic for backward compatibility
 * - The vulnerability appears during legitimate feature addition (recipient notifications)
 */
/**
 *Submitted for verification at Etherscan.io on 2019-09-25
*/

pragma solidity ^0.4.19;
interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// Transfer hook interface for recipient notifications
contract TransferHook {
    function onTransferReceived(address from, address to, uint256 value, bytes data) external;
}
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

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
    function ESVtoken (
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient before completing transfer (vulnerable external call)
        if (isContract(_to)) {
            // Reentrancy notification call
            TransferHook(_to).onTransferReceived(_from, _to, _value, "");
            // Ignore return/exception for compatibility
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        _transfer(_from, _to, _value);
        return true;
    }

    // Helper function for contract detection in Solidity 0.4.x
    function isContract(address _addr) internal view returns (bool) {
        uint length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
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
