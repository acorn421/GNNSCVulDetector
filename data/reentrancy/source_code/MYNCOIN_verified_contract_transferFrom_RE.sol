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
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to recipient contract (`_to.call(...)`) before state modifications
 * 2. The call happens after all checks pass but before balances and allowances are updated
 * 3. Added helper function `isContract()` to detect contract addresses
 * 4. Maintained original function signature and core logic
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **Transaction 1**: Attacker calls `transferFrom` with malicious contract as `_to`
 * 2. **During Transaction 1**: External call to malicious contract triggers `onTokenTransfer`
 * 3. **Reentrancy**: Malicious contract calls `transferFrom` again with same parameters
 * 4. **State Persistence**: Original allowance and balance checks still pass because state wasn't updated yet
 * 5. **Accumulated Effect**: Multiple transfers occur using the same allowance, draining funds
 * 
 * **Why Multi-Transaction Nature is Required:**
 * - The vulnerability exploits the gap between authorization checks and state updates
 * - Each reentrant call sees the same pre-transaction state (allowance not yet decremented)
 * - The attack accumulates effect across multiple nested calls within the same transaction context
 * - The allowance mechanism creates persistent state that enables repeated exploitation
 * - Without the external call triggering reentrancy, the normal CEI pattern would prevent exploitation
 * 
 * **Realistic Context:**
 * This vulnerability mimics real-world patterns where tokens implement transfer hooks or notifications to recipient contracts, which is a common pattern in modern token standards like ERC-777 and some ERC-20 extensions.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract MYNCOIN {
    /* Public variables of the token */
    string public standard = 'MYN COIN ';
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
    function MYNCOIN() {
        balanceOf[msg.sender] =  40000000 * 100000000;              // Give the creator all initial tokens
        totalSupply =  40000000 * 100000000;                        // Update total supply
        name = "MYN COIN";                                   // Set the name for display purposes
        symbol = "MYN";                               // Set the symbol for display purposes
        decimals = 8;                            // Amount of decimals for display purposes
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) {
        if (_to == 0x0) throw;                               // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        emit Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* Approve and then communicate the approved contract in a single tx */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) returns (bool) {
        if (_to == 0x0) throw;                                // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract about incoming transfer (external call before state update)
        if (isContract(_to)) {
            bool callSuccess = _to.call(bytes4(keccak256("onTokenTransfer(address,address,uint256)")), _from, _to, _value);
            if (!callSuccess) throw;
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                           // Subtract from the sender
        balanceOf[_to] += _value;                             // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    
    // Helper function to check if address is a contract
    function isContract(address addr) private returns (bool) {
        uint32 size;
        assembly {
            size := extcodesize(addr)
        }
        return (size > 0);
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

    function burn(uint256 _value) returns (bool) {
        if (balanceOf[msg.sender] < _value) throw;            // Check if the sender has enough
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) returns (bool) {
        if (balanceOf[_from] < _value) throw;                // Check if the sender has enough
        if (_value > allowance[_from][msg.sender]) throw;    // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        emit Burn(_from, _value);
        return true;
    }
}