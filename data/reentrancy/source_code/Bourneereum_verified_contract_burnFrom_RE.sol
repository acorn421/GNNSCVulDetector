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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the token holder before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * 1. **Setup Phase (Transaction 1):** Attacker deploys a malicious contract that implements the tokenRecipient interface and gets approval from a victim to burn tokens on their behalf.
 * 
 * 2. **State Accumulation Phase (Transaction 2):** The attacker's malicious contract calls burnFrom(), which triggers the callback to the victim's contract (if it implements tokenRecipient). However, the victim's contract is legitimate and doesn't re-enter.
 * 
 * 3. **Exploitation Phase (Transaction 3+):** The attacker updates their malicious contract to act as the _from address by transferring tokens to it first, then implements receiveApproval() to re-enter burnFrom() before state updates complete. This allows burning tokens multiple times with the same allowance or manipulating the burn process.
 * 
 * **Why Multi-Transaction:**
 * - Requires initial setup of contracts and approvals across multiple transactions
 * - The external call creates a window for reentrancy only after the allowance and balance checks pass
 * - State changes from balance updates persist between transactions, allowing accumulated exploitation
 * - The vulnerability exploits the persistent allowance state that builds up over multiple transactions
 * 
 * **Exploitation Mechanism:**
 * The malicious contract can re-enter burnFrom() through the receiveApproval callback before balanceOf, allowance, and totalSupply are updated, potentially:
 * - Burning more tokens than allowed by the original allowance
 * - Manipulating the burn process to affect totalSupply calculations
 * - Creating inconsistent state between balance and allowance mappings
 * 
 * The vulnerability violates Checks-Effects-Interactions by performing external calls before completing all state updates, creating a classic reentrancy attack vector that requires multiple transactions to establish the necessary state and contracts for exploitation.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract Bourneereum {
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

// Notify the token holder about the burn operation through callback
if (_from != msg.sender && _from != address(0)) {
    uint codeLength;
    assembly { codeLength := extcodesize(_from) }
    if (codeLength > 0) {
        tokenRecipient(_from).receiveApproval(msg.sender, _value, this, "BURN_NOTIFICATION");
    }
}

// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
balanceOf[_from] -= _value;                         // Subtract from the targeted balance
allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
totalSupply -= _value;                              // Update totalSupply
emit Burn(_from, _value);
return true;
}
}