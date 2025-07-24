/*
 * ===== SmartInject Injection Details =====
 * Function      : freeze
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the caller's contract before state updates. The vulnerability exploits the callback mechanism where a malicious contract can reenter the freeze function multiple times across different transactions, manipulating the balance state between calls. This creates a window where an attacker can freeze more tokens than they actually own by coordinating multiple transactions that exploit the race condition between balance checks and state updates.
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `msg.sender` using low-level call mechanism
 * 2. Positioned the external call after balance validation but before state updates
 * 3. Used `onTokensFreeze` callback that malicious contracts can implement
 * 4. Made the call non-reverting to maintain function flow
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker calls freeze(1000) with 1000 tokens
 *    - Balance check passes (1000 >= 1000)
 *    - External call triggers attacker's `onTokensFreeze` callback
 *    - In callback, attacker immediately calls freeze(500) again
 *    - Second call succeeds because balance hasn't been updated yet
 *    - Both transactions complete, freezing 1500 tokens from 1000 balance
 * 
 * 2. **Transaction 2**: Attacker can repeat the pattern
 *    - Call freeze() again, and during callback, call freeze() multiple times
 *    - Each call sees stale balance state before previous updates are applied
 *    - Accumulated frozen amount exceeds actual balance
 * 
 * 3. **Transaction 3**: Exploit completion
 *    - Attacker calls unfreeze() to retrieve more tokens than originally owned
 *    - State corruption allows withdrawal of excess tokens
 * 
 * **Why Multiple Transactions Are Required:**
 * - Single transaction atomicity would prevent state corruption
 * - The vulnerability requires accumulated state changes across multiple calls
 * - Each callback creates a new execution context that can manipulate state
 * - The race condition only exists when state updates are delayed across transaction boundaries
 * - Attacker needs time to coordinate multiple freeze operations before state synchronization occurs
 * 
 * This creates a realistic, sophisticated attack vector that mirrors real-world reentrancy patterns seen in DeFi protocols where callback mechanisms are exploited across multiple transactions to manipulate accumulated state.
 */
/**
 *Submitted for verification at Etherscan.io on 2020-08-11
*/

/**
 *Submitted for verification at Etherscan.io on 2017-07-06
*/

pragma solidity ^0.4.26;

/**
 * Math operations with safety checks
 */
contract SafeMath {
    function safeMul(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a * b;
        assert(a == 0 || c / a == b);
        return c;
    }

    function safeDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b > 0);
        uint256 c = a / b;
        assert(a == b * c + a % b);
        return c;
    }

    function safeSub(uint256 a, uint256 b) internal pure returns (uint256) {
        assert(b <= a);
        return a - b;
    }

    function safeAdd(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        assert(c>=a && c>=b);
        return c;
    }

}

contract HiSwapToken is SafeMath{
    string public name = "hiswap Token";
    string public symbol = "hiswap";
    uint8 public decimals = 18;
    uint256 public totalSupply = 1000000000000000000000000000;
    address public owner;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => uint256) public freezeOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* This notifies clients about the amount frozen */
    event Freeze(address indexed from, uint256 value);

    /* This notifies clients about the amount unfrozen */
    event Unfreeze(address indexed from, uint256 value);

    /* Inline extcodesize function as internal */
    function extcodesize(address _addr) internal view returns (uint256 size) {
        assembly { size := extcodesize(_addr) }
    }

    /* Initializes contract with initial supply tokens to the creator of the contract */
    constructor() public{
        balanceOf[msg.sender] = totalSupply;              // Give the creator all initial tokens
        owner = msg.sender;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public{
        if (_to == 0x0) revert();                               // Prevent transfer to 0x0 address. Use burn() instead
        if (_value <= 0) revert();
        if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                     // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                            // Add the same to the recipient
        emit Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value) public
    returns (bool success) {
        if (_value <= 0) revert();
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (_to == 0x0) revert();                                // Prevent transfer to 0x0 address. Use burn() instead
        if (_value <= 0) revert();
        if (balanceOf[_from] < _value) revert();                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();  // Check for overflows
        if (_value > allowance[_from][msg.sender]) revert();     // Check allowance
        balanceOf[_from] = SafeMath.safeSub(balanceOf[_from], _value);                           // Subtract from the sender
        balanceOf[_to] = SafeMath.safeAdd(balanceOf[_to], _value);                             // Add the same to the recipient
        allowance[_from][msg.sender] = SafeMath.safeSub(allowance[_from][msg.sender], _value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value)public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
        if (_value <= 0) revert();
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }

    function freeze(uint256 _value)public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
        if (_value <= 0) revert();
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify external contract about freeze operation (vulnerability injection point)
        if (extcodesize(msg.sender) > 0) {
            // extcodesize returns the code size
            // call popularity to msg.sender
            (bool callSuccess,) = msg.sender.call(abi.encodeWithSignature("onTokensFreeze(uint256)", _value));
            // Continue execution regardless of callback success
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        freezeOf[msg.sender] = SafeMath.safeAdd(freezeOf[msg.sender], _value);                                // Updates totalSupply
        emit Freeze(msg.sender, _value);
        return true;
    }

    function unfreeze(uint256 _value) public returns (bool success) {
        if (freezeOf[msg.sender] < _value) revert();            // Check if the sender has enough
        if (_value <= 0) revert();
        freezeOf[msg.sender] = SafeMath.safeSub(freezeOf[msg.sender], _value);                      // Subtract from the sender
        balanceOf[msg.sender] = SafeMath.safeAdd(balanceOf[msg.sender], _value);
        emit Unfreeze(msg.sender, _value);
        return true;
    }

    // transfer balance to owner
    function withdrawEther(uint256 amount) public{
        if(msg.sender != owner) revert();
        owner.transfer(amount);
    }

    // can accept ether
    function() public payable {
    }
}
