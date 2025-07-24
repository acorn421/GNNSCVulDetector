/*
 * ===== SmartInject Injection Details =====
 * Function      : collect
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by moving the state update (tokensOwed[msg.sender] = 0) to after the external call (token.transfer). This creates a vulnerability window where:
 * 
 * **Multi-Transaction Exploitation Sequence:**
 * 1. **Transaction 1**: Attacker calls collect() with a malicious token contract
 * 2. **During Transfer**: The malicious token's transfer() function re-enters the Distribute contract
 * 3. **State Manipulation**: During reentrancy, tokensOwed[attacker] is still non-zero, allowing multiple withdrawals
 * 4. **Transaction 2**: Attacker can call collect() again or trigger additional state changes
 * 5. **Accumulated Impact**: The vulnerability exploits the persistent state across multiple transactions
 * 
 * **Why Multi-Transaction:**
 * - The vulnerability requires the attacker to set up state in earlier transactions (having tokens owed)
 * - The exploitation depends on accumulated state that persists between function calls
 * - The attacker needs to deploy a malicious token contract that can re-enter during transfer
 * - The impact compounds across multiple transactions as the attacker can drain more tokens than they're owed
 * 
 * **Realistic Nature:**
 * - This follows the classic "Checks-Effects-Interactions" pattern violation
 * - Moving state updates after external calls is a common real-world vulnerability
 * - The change appears like a simple code reordering that could happen during refactoring
 * - The vulnerability is subtle and might pass basic code review
 */
pragma solidity ^0.4.15;

contract Owned {

    /// @dev `owner` is the only address that can call a function with this
    /// modifier
    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    address public owner;

    /// @notice The Constructor assigns the message sender to be `owner`
    function Owned() {
        owner = msg.sender;
    }

    address public newOwner;

    /// @notice `owner` can step down and assign some other address to this role
    /// @param _newOwner The address of the new owner. 0x0 can be used to create
    ///  an unowned neutral vault, however that cannot be undone
    function changeOwner(address _newOwner) onlyOwner {
        newOwner = _newOwner;
    }

    function acceptOwnership() {
        if (msg.sender == newOwner) {
            owner = newOwner;
        }
    }
}

contract ERC20Basic {
    function transfer(address to, uint256 value) public returns (bool);
    function balanceOf(address who) public constant returns (uint256);
    event Transfer(address indexed from, address indexed to, uint256 value);
}

contract Distribute is Owned {

    mapping (address => uint) public tokensOwed;
    ERC20Basic token;

    event AmountSet(address contributor, uint amount);
    event AmountSent(address contributor, uint amount);

    function Distribute(address _token) public {
        token = ERC20Basic(_token);
    }

    function setAmount(address contributor, uint amount) public onlyOwner {
        tokensOwed[contributor] = amount;
    }

    function withdrawAllTokens() public onlyOwner {
        token.transfer(owner, token.balanceOf(address(this)));
    }

    function() public payable {
        collect();
    }

    function collect() public {
        uint amount = tokensOwed[msg.sender];
        require(amount > 0);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Perform external call before state update - vulnerable to reentrancy
        token.transfer(msg.sender, amount);
        
        // State update moved after external call - creates vulnerability window
        tokensOwed[msg.sender] = 0;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        AmountSent(msg.sender, amount);
    }
}