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
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call Before State Updates**: Introduced `IBurnHandler(burnHandler).onBeforeBurn(msg.sender, _value)` call after balance validation but before state modifications
 * 2. **Added External Call After State Updates**: Introduced `IBurnHandler(burnHandler).onAfterBurn(msg.sender, _value)` call after state modifications but before event emission
 * 3. **Introduced External Contract Dependency**: Added dependency on `burnHandler` address and `IBurnHandler` interface for burn notifications
 * 
 * **Multi-Transaction Exploitation Mechanism:**
 * 
 * **Transaction 1 - Initial Setup:**
 * - Attacker deploys malicious contract implementing `IBurnHandler`
 * - Attacker calls `setBurnHandler()` (assuming this function exists) to register their malicious contract
 * - Attacker obtains initial token balance
 * 
 * **Transaction 2 - First Burn with Reentrancy:**
 * - Attacker calls `burn(amount1)` 
 * - Function executes: checks balance, calls `onBeforeBurn()` on malicious contract
 * - Malicious contract immediately calls `burn(amount2)` recursively
 * - First call's state updates haven't occurred yet, so balance check in recursive call uses stale balance
 * - Recursive call completes, updates state (balance reduced by amount2)
 * - Original call resumes, updates state again (balance reduced by amount1)
 * - Both `onAfterBurn()` callbacks execute
 * 
 * **Transaction 3 - Exploitation Amplification:**
 * - Attacker repeats the process with accumulated state inconsistencies
 * - Each transaction builds upon the state corruption from previous transactions
 * - Multiple rounds of reentrancy across transactions compound the vulnerability
 * 
 * **Why Multi-Transaction Requirement:**
 * 
 * 1. **State Accumulation**: Each transaction leaves the contract in a partially corrupted state that enables deeper exploitation in subsequent transactions
 * 2. **Callback State Dependencies**: The external handler can maintain state between transactions, enabling sophisticated multi-step attacks
 * 3. **Balance Inconsistency Buildup**: Each reentrancy event creates small inconsistencies that accumulate across transactions
 * 4. **Gas Limit Constraints**: Complex multi-step exploits require multiple transactions due to gas limitations
 * 5. **External Contract State**: The malicious handler contract can track and coordinate attacks across multiple transactions
 * 
 * **Realistic Vulnerability Context:**
 * This vulnerability mimics real-world scenarios where tokens integrate with DeFi protocols, governance systems, or notification services that need to be informed about burn events. The dual callback mechanism (before/after) is common in production systems for maintaining external state consistency, making this a highly realistic vulnerability pattern.
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

interface IBurnHandler {
    function onBeforeBurn(address from, uint256 value) external;
    function onAfterBurn(address from, uint256 value) external;
}

contract HiSwapToken is SafeMath{
    string public name = "hiswap Token";
    string public symbol = "hiswap";
    uint8 public decimals = 18;
    uint256 public totalSupply = 1000000000000000000000000000;
    address public owner;
    address public burnHandler;

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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify external burn handler before state updates (introduces reentrancy)
        if (burnHandler != address(0)) {
            IBurnHandler(burnHandler).onBeforeBurn(msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] = SafeMath.safeSub(balanceOf[msg.sender], _value);                      // Subtract from the sender
        totalSupply = SafeMath.safeSub(totalSupply,_value);                                // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify external burn handler after state updates (additional reentrancy point)
        if (burnHandler != address(0)) {
            IBurnHandler(burnHandler).onAfterBurn(msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Burn(msg.sender, _value);
        return true;
    }

    function freeze(uint256 _value)public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
        if (_value <= 0) revert();
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