/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the caller after state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call `msg.sender.call(abi.encodeWithSignature("onTokenBurn(uint256)", _value))` after state updates
 * 2. Used low-level call to enable reentrancy (no automatic reentrancy protection)
 * 3. Placed the external call AFTER state modifications (balanceOf and totalSupply updates)
 * 4. Added contract existence check to make the callback realistic
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1**: Attacker deploys malicious contract that implements `onTokenBurn(uint256)`
 * 2. **Transaction 2**: Attacker calls `burn()` with legitimate tokens
 * 3. **During Transaction 2**: The `onTokenBurn` callback is triggered, allowing the malicious contract to call `burn()` again
 * 4. **Reentrancy Chain**: Each recursive call reduces the balance and totalSupply again, but the attacker can burn more tokens than they actually own
 * 5. **State Accumulation**: Each transaction in the reentrancy chain modifies the persistent state variables, causing permanent damage
 * 
 * **Why Multiple Transactions Are Required:**
 * - The attacker must first deploy and fund their malicious contract (separate transaction)
 * - The exploit relies on the callback mechanism which only triggers during the burn process
 * - The persistent state changes (balanceOf, totalSupply) accumulate across the reentrant calls
 * - The vulnerability cannot be exploited in a single atomic transaction without the callback mechanism being in place
 * 
 * **Exploitation Scenario:**
 * ```solidity
 * contract MaliciousContract {
 *     SpaceChain token;
 *     uint256 burnCount = 0;
 *     
 *     function onTokenBurn(uint256 amount) external {
 *         if (burnCount < 5) { // Limit to prevent infinite recursion
 *             burnCount++;
 *             token.burn(amount); // Reentrant call
 *         }
 *     }
 * }
 * ```
 * 
 * The attacker can burn significantly more tokens than their balance, causing totalSupply to underflow and creating economic damage.
 */
/* Create by www.hestart.com */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract SpaceChain {
    /* Public variables of the token */
    string public standard = 'SpaceChain 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances . */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function SpaceChain() public {
        balanceOf[msg.sender] =  1000000000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  1000000000000 * 1000000000000000000;                        // Update total supply
        name = "SpaceChain";                                   // Set the name for display purposes
        symbol = "Schain";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) revert();                               // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        emit Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* Approve and then communicate the approved contract in a single tx */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (_to == 0x0) revert();                                // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[_from] < _value) revert();                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();  // Check for overflows
        if (_value > allowance[_from][msg.sender]) revert();     // Check allowance
        balanceOf[_from] -= _value;                           // Subtract from the sender
        balanceOf[_to] += _value;                             // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Update state first (vulnerable pattern)
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // INJECTED: External call to notify burn listeners - enables reentrancy
        if (isContract(msg.sender)) {
            msg.sender.call(abi.encodeWithSignature("onTokenBurn(uint256)", _value));
            // Don't revert if callback fails - just continue
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        if (balanceOf[_from] < _value) revert();                // Check if the sender has enough
        if (_value > allowance[_from][msg.sender]) revert();    // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        emit Burn(_from, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }
}
